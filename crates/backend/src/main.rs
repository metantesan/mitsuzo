use backend::AppState;
use backend::db::DataStore;
use backend::rate_limit::RateLimiter;
use backend::routes::app_router;
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::sync::mpsc;
use std::time::Duration;
use tracing::info;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .init();

    let db = DataStore::new()?;
    let limiter = RateLimiter::new();
    let state = AppState::new(db.clone(), limiter.clone());

    let cleanup_handle = tokio::spawn(cleanup_task(db.clone()));

    let rate_limit_handle = tokio::spawn(rate_limit_cleanup_task(limiter));

    let app = app_router(state);

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "3030".to_string())
        .parse()
        .map_err(|e| eyre::eyre!("PORT must be a valid number: {}", e))?;
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .map_err(|e| eyre::eyre!("Failed to bind to port {}: {}", port, e))?;
    info!("listening on {}", listener.local_addr()?);

    let (signal_tx, signal_rx) = tokio::sync::oneshot::channel::<()>();
    let (arm_tx, arm_rx) = mpsc::channel::<()>();
    let (done_tx, done_rx) = mpsc::channel::<()>();

    // Watchdog: if a shutdown signal fired but graceful shutdown hasn't finished
    // within 8s, force-exit so Docker never has to SIGKILL us past its grace period.
    std::thread::spawn(move || {
        if arm_rx.recv().is_err() {
            return;
        }
        if done_rx.recv_timeout(Duration::from_secs(8)).is_err() {
            eprintln!("shutdown watchdog: graceful shutdown exceeded 8s, force-exiting");
            std::process::exit(0);
        }
    });

    // Catch SIGINT/SIGTERM on a dedicated thread so shutdown still triggers even if
    // the async runtime is blocked or wedged.
    std::thread::spawn(move || {
        let Ok(mut signals) = Signals::new([SIGTERM, SIGINT]) else {
            return;
        };
        for sig in signals.forever() {
            info!("received signal {sig}, shutting down");
            let _ = signal_tx.send(());
            let _ = arm_tx.send(());
            break;
        }
    });

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = signal_rx.await;
        })
        .await
        .map_err(|e| eyre::eyre!("Server error: {}", e))?;

    info!("server drained, stopping background tasks");
    cleanup_handle.abort();
    rate_limit_handle.abort();

    flush_db_bounded(db, Duration::from_secs(5));

    let _ = done_tx.send(());
    info!("shutting down");
    Ok(())
}

fn flush_db_bounded(db: DataStore, timeout: Duration) {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(db.flush());
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(())) => info!("database flushed"),
        Ok(Err(e)) => info!("failed to flush database on shutdown: {e}"),
        Err(_) => info!("database flush exceeded {timeout:?}, exiting anyway"),
    }
}

async fn cleanup_task(db: DataStore) {
    let mut interval = tokio::time::interval(Duration::from_secs(300));
    loop {
        interval.tick().await;
        let db = db.clone();
        let deleted = tokio::task::spawn_blocking(move || db.cleanup_expired())
            .await
            .unwrap_or(0);
        info!("Cleanup: removed {} expired pastes", deleted);
    }
}

async fn rate_limit_cleanup_task(limiter: RateLimiter) {
    let mut interval = tokio::time::interval(Duration::from_secs(120));
    loop {
        interval.tick().await;
        limiter.cleanup().await;
    }
}
