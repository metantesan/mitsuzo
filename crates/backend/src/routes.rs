use crate::db::DataStore;
use crate::handlers;
use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::Method,
    routing::{get, post},
};
use mitsuzo_types::MAX_PASTE_SIZE;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    services::ServeDir,
};

pub fn api_router(db: DataStore) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::mirror_request())
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ORIGIN,
            axum::http::header::ACCEPT,
            "X-Password-Hash".parse().unwrap(),
        ])
        .allow_credentials(true);

    Router::new()
        .route("/paste", post(handlers::create_paste))
        .route("/paste/{id}", get(handlers::get_paste))
        .route("/paste/{id}/salt", get(handlers::get_salt))
        .route("/paste/stats", get(handlers::get_stats))
        .with_state(db)
        .layer(cors)
        .layer(DefaultBodyLimit::max(MAX_PASTE_SIZE))
}

pub fn app_router(db: DataStore) -> Router {
    let assets_path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join("public/assets");

    Router::new()
        .route("/", get(handlers::serve_index))
        .nest("/api", api_router(db))
        .nest_service("/assets", ServeDir::new(assets_path))
        .fallback(get(handlers::fallback_to_index))
}
