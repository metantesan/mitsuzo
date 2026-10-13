use backend::AppState;
use backend::RuntimeConfig;
use backend::db::DataStore;
use backend::rate_limit::RateLimiter;
use backend::routes::app_router;
use std::time::Duration;
use tracing::info;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .init();

    let db = DataStore::new().await?;
    let limiter = RateLimiter::new();
    let config = RuntimeConfig::from_env();
    if config.demo_mode {
        info!(
            "running in demo mode: max ttl {}s, max file size {} bytes",
            config.max_ttl_seconds, config.max_file_size
        );
    }
    let state = AppState::new(db.clone(), limiter.clone(), config);

    let cleanup_handle = tokio::spawn(cleanup_task(db.clone()));
    let rate_limit_handle = tokio::spawn(rate_limit_cleanup_task(limiter));
    let challenge_handle = tokio::spawn(challenge_cleanup_task(state.challenges.clone()));

    let app = app_router(state);

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "3030".to_string())
        .parse()
        .map_err(|e| eyre::eyre!("PORT must be a valid number: {}", e))?;
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .map_err(|e| eyre::eyre!("Failed to bind to port {}: {}", port, e))?;
    info!("listening on {}", listener.local_addr()?);

    // Graceful shutdown lets in-flight requests finish and the shutdown code
    // below flush the database before the process exits on SIGINT/SIGTERM.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .map_err(|e| eyre::eyre!("Server error: {}", e))?;

    info!("server stopped, flushing database");
    cleanup_handle.abort();
    rate_limit_handle.abort();
    challenge_handle.abort();
    let _ = db.flush();
    info!("shutting down");
    Ok(())
}

/// Resolve when the process receives Ctrl-C or SIGTERM, then arm a bounded
/// force-exit so a stuck keep-alive or streaming connection can never prevent
/// the process from stopping.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("shutdown signal received");

    // Give in-flight requests a short grace window, then exit unconditionally
    // so the process always stops (even if a connection never drains).
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(8)).await;
        tracing::warn!("graceful shutdown timed out; forcing exit");
        std::process::exit(0);
    });
}

async fn cleanup_task(db: DataStore) {
    let mut interval = tokio::time::interval(Duration::from_secs(300));
    loop {
        interval.tick().await;
        let deleted = db.cleanup_expired().await;
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

async fn challenge_cleanup_task(challenges: backend::challenge::ChallengeStore) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        challenges.cleanup().await;
    }
}
