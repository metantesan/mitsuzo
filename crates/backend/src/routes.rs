use crate::db::DataStore;
use crate::handlers;
use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::Method,
    routing::{get, post, put},
};
use mitsuzo_types::UPLOAD_CHUNK_SIZE;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    services::ServeDir,
};

pub fn api_router(db: DataStore) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::mirror_request())
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::OPTIONS])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ORIGIN,
            axum::http::header::ACCEPT,
            "X-Password-Hash".parse().unwrap(),
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
        .route("/paste/stats", get(handlers::get_stats))
        .with_state(db)
        .layer(cors)
        .layer(DefaultBodyLimit::max(UPLOAD_CHUNK_SIZE))
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
