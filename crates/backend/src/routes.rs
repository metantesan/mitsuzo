use crate::AppState;
use crate::handlers;
use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::{HeaderName, HeaderValue, Method},
    routing::{get, post, put},
};
use mitsuzo_types::UPLOAD_CHUNK_SIZE;
use std::path::PathBuf;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    services::ServeDir,
};

/// Headers the API accepts from cross-origin clients.
fn allowed_headers() -> Vec<HeaderName> {
    vec![
        axum::http::header::CONTENT_TYPE,
        axum::http::header::ORIGIN,
        axum::http::header::ACCEPT,
        HeaderName::from_static("x-password-hash"),
        HeaderName::from_static("x-account-proof"),
        HeaderName::from_static("x-upload-token"),
    ]
}

/// Build a CORS policy from an explicit origin allowlist. An empty allowlist
/// means same-origin only and adds no CORS layer, so the API never reflects
/// arbitrary origins by default.
fn cors_layer(allowed_origins: &[String]) -> Option<CorsLayer> {
    let origins: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter_map(|origin| origin.parse::<HeaderValue>().ok())
        .collect();
    if origins.is_empty() {
        return None;
    }
    Some(
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::OPTIONS])
            .allow_headers(allowed_headers())
            .allow_credentials(true),
    )
}

pub fn api_router(state: AppState) -> Router {
    let allowed_origins = state.config.allowed_origins.clone();

    let router = Router::new()
        .route("/paste", post(handlers::init_paste))
        .route("/paste/xchacha", post(handlers::init_paste))
        .route("/paste/{id}", get(handlers::get_paste))
        .route(
            "/paste/{id}/chunk/{chunk_index}",
            put(handlers::upload_chunk),
        )
        .route("/paste/{id}/chunks", get(handlers::get_chunk_info))
        .route("/paste/{id}/complete", post(handlers::complete_paste))
        .route("/paste/{id}/salt", get(handlers::get_salt))
        .route("/paste/{id}/data", get(handlers::get_paste_data))
        .route("/paste/{id}/challenge", get(handlers::get_paste_challenge))
        .route("/paste/{id}/password", post(handlers::change_password))
        .route("/paste/{id}/burn", post(handlers::burn_paste))
        .route("/paste/stats", get(handlers::get_stats))
        .route("/account", post(handlers::register_account))
        .route("/account/{kid}", get(handlers::get_account))
        .route(
            "/account/{kid}/xwing",
            get(handlers::get_account_xwing_key).post(handlers::set_account_xwing_key),
        )
        .route(
            "/account/{kid}/challenge",
            get(handlers::get_account_challenge),
        )
        .route("/account/{kid}/name", post(handlers::change_account_name))
        .route("/account/{kid}/inbox", get(handlers::get_account_inbox))
        .with_state(state)
        .layer(DefaultBodyLimit::max(UPLOAD_CHUNK_SIZE));

    match cors_layer(&allowed_origins) {
        Some(cors) => router.layer(cors),
        None => router,
    }
}

pub fn app_router(state: AppState) -> Router {
    let assets_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.join("public/assets")))
        .unwrap_or_else(|| PathBuf::from("public/assets"));

    // The API subrouter carries its own state, so nest it after the outer
    // router resolves its state (the stateful `/readyz` route needs `AppState`).
    let api = api_router(state.clone());

    Router::new()
        .route("/", get(handlers::serve_index))
        .route("/robots.txt", get(handlers::robots_txt))
        .route("/install.sh", get(handlers::install_script))
        .route("/healthz", get(handlers::healthz))
        .route("/readyz", get(handlers::readyz))
        .nest_service("/assets", ServeDir::new(assets_path))
        .fallback(get(handlers::fallback_to_index))
        .with_state(state)
        .nest("/api", api)
}
