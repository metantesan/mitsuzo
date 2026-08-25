pub mod db;
pub mod handlers;
pub mod rate_limit;
pub mod routes;

use crate::db::DataStore;
use crate::rate_limit::RateLimiter;
use mitsuzo_types::MAX_PASTE_SIZE;

/// Runtime limits / environment configuration.
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub demo_mode: bool,
    pub max_ttl_seconds: u32,
    pub max_file_size: u64,
}

impl RuntimeConfig {
    /// Build from environment variables. Demo mode (MITSUZO_DEMO_MODE=1/true/yes/on)
    /// changes the defaults to a 60-second TTL and a 5 MiB upload limit.
    pub fn from_env() -> Self {
        let demo_mode = std::env::var("MITSUZO_DEMO_MODE")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);

        let max_ttl_seconds = std::env::var("MITSUZO_MAX_TTL_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(if demo_mode { 60 } else { 43200 });

        let max_file_size = std::env::var("MITSUZO_MAX_FILE_SIZE_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(if demo_mode {
                5 * 1024 * 1024
            } else {
                MAX_PASTE_SIZE as u64
            });

        Self {
            demo_mode,
            max_ttl_seconds,
            max_file_size,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub db: DataStore,
    pub limiter: RateLimiter,
    pub config: RuntimeConfig,
}

impl AppState {
    pub fn new(db: DataStore, limiter: RateLimiter, config: RuntimeConfig) -> Self {
        Self {
            db,
            limiter,
            config,
        }
    }
}
