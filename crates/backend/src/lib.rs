pub mod db;
pub mod handlers;
pub mod rate_limit;
pub mod routes;

use crate::db::DataStore;
use crate::rate_limit::RateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub db: DataStore,
    pub limiter: RateLimiter,
}

impl AppState {
    pub fn new(db: DataStore, limiter: RateLimiter) -> Self {
        Self { db, limiter }
    }
}
