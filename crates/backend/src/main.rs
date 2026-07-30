use backend::AppState;
use backend::db::DataStore;
use backend::rate_limit::RateLimiter;
use backend::routes::app_router;
use std::time::Duration;
use tokio::signal;
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

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| eyre::eyre!("Server error: {}", e))?;

    cleanup_handle.abort();
    rate_limit_handle.abort();

    if let Err(e) = db.flush() {
        info!("Failed to flush database on shutdown: {}", e);
    }

    info!("shutting down");
    Ok(())
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

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler")
    };
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
