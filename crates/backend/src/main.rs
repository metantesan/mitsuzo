use backend::rate_limit::RateLimiter;
use backend::routes::app_router;
use backend::AppState;
use backend::db::DataStore;
use std::time::Duration;
use tokio::signal;
use tracing::info;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .init();

    let db = DataStore::new();
    let limiter = RateLimiter::new();
    let state = AppState::new(db.clone(), limiter.clone());

    let cleanup_handle = tokio::spawn(cleanup_task(db.clone()));

    let rate_limit_handle = tokio::spawn(rate_limit_cleanup_task(limiter));

    let app = app_router(state);

    let listener = tokio::net::TcpListener::bind((
        "0.0.0.0",
        std::env::var("PORT")
            .unwrap_or_else(|_| "3030".to_string())
            .parse()
            .expect("PORT must be a valid number"),
    ))
    .await
    .unwrap();
    info!("listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();

    cleanup_handle.abort();
    rate_limit_handle.abort();
    info!("shutting down");
}

async fn cleanup_task(db: DataStore) {
    let mut interval = tokio::time::interval(Duration::from_secs(300));
    loop {
        interval.tick().await;
        let db = db.clone();
        let deleted = tokio::task::spawn_blocking(move || db.cleanup_expired())
            .await
            .unwrap();
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
    signal::ctrl_c().await.unwrap();
}
