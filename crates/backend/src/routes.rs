use crate::AppState;
use crate::handlers;
use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::{HeaderName, Method},
    routing::{get, post, put},
};
use mitsuzo_types::UPLOAD_CHUNK_SIZE;
use std::path::PathBuf;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    services::ServeDir,
};

pub fn api_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::mirror_request())
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::OPTIONS])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ORIGIN,
            axum::http::header::ACCEPT,
            HeaderName::from_static("x-password-hash"),
        ])
        .allow_credentials(true);

    Router::new()
        .route("/paste", post(handlers::init_paste))
        .route("/paste/{id}", get(handlers::get_paste))
        .route(
            "/paste/{id}/chunk/{chunk_index}",
            put(handlers::upload_chunk),
        )
        .route("/paste/{id}/chunks", get(handlers::get_chunk_info))
        .route("/paste/{id}/complete", post(handlers::complete_paste))
        .route("/paste/{id}/salt", get(handlers::get_salt))
        .route("/paste/{id}/data", get(handlers::get_paste_data))
        .route("/paste/{id}/burn", post(handlers::burn_paste))
        .route("/paste/stats", get(handlers::get_stats))
        .with_state(state)
        .layer(cors)
        .layer(DefaultBodyLimit::max(UPLOAD_CHUNK_SIZE))
}

pub fn app_router(state: AppState) -> Router {
    let assets_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.join("public/assets")))
        .unwrap_or_else(|| PathBuf::from("public/assets"));

    Router::new()
        .route("/", get(handlers::serve_index))
        .route("/robots.txt", get(handlers::robots_txt))
        .nest("/api", api_router(state))
        .nest_service("/assets", ServeDir::new(assets_path))
        .fallback(get(handlers::fallback_to_index))
}
