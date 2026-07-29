use std::{
    collections::HashMap,
    sync::Arc,
    time::Instant,
};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn check(&self, key: &str, max_requests: usize, window_secs: u64) -> bool {
        let mut map = self.inner.lock().await;
        let now = Instant::now();
        let window = std::time::Duration::from_secs(window_secs);

        let entries = map.entry(key.to_string()).or_default();
        entries.retain(|t| now.duration_since(*t) < window);
        if entries.len() >= max_requests {
            return false;
        }
        entries.push(now);
        true
    }

    pub async fn cleanup(&self) {
        let mut map = self.inner.lock().await;
        let now = Instant::now();
        map.retain(|_, entries| {
            entries.retain(|t| now.duration_since(*t) < std::time::Duration::from_secs(300));
            !entries.is_empty()
        });
    }
}
