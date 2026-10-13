use std::{collections::HashMap, sync::Arc, time::Instant};
use tokio::sync::Mutex;

/// Default ceiling on distinct rate-limit keys held in memory. Keys are client
/// identities; without a bound, a client that can influence its identity (for
/// example via a spoofable forwarded header) could grow the map without limit.
const DEFAULT_MAX_KEYS: usize = 100_000;

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    max_keys: usize,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::with_max_keys(DEFAULT_MAX_KEYS)
    }

    pub fn with_max_keys(max_keys: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max_keys: max_keys.max(1),
        }
    }

    pub async fn check(&self, key: &str, max_requests: usize, window_secs: u64) -> bool {
        let mut map = self.inner.lock().await;
        let now = Instant::now();
        let window = std::time::Duration::from_secs(window_secs);

        if !map.contains_key(key) && map.len() >= self.max_keys {
            self.evict_one(&mut map, now, window);
        }

        let entries = map.entry(key.to_string()).or_default();
        entries.retain(|t| now.duration_since(*t) < window);
        if entries.len() >= max_requests {
            return false;
        }
        entries.push(now);
        true
    }

    /// Make room for one new key: drop entries whose timestamps have all aged
    /// out of `window`, and if the map is still full, evict the key that was
    /// seen least recently. This caps memory at the cost of resetting one
    /// identity's window under sustained key pressure.
    fn evict_one(
        &self,
        map: &mut HashMap<String, Vec<Instant>>,
        now: Instant,
        window: std::time::Duration,
    ) {
        map.retain(|_, entries| {
            entries.retain(|t| now.duration_since(*t) < window);
            !entries.is_empty()
        });
        if map.len() < self.max_keys {
            return;
        }
        if let Some(oldest) = map
            .iter()
            .min_by_key(|(_, entries)| entries.last().copied())
            .map(|(key, _)| key.clone())
        {
            map.remove(&oldest);
        }
    }

    pub async fn cleanup(&self) {
        let mut map = self.inner.lock().await;
        let now = Instant::now();
        map.retain(|_, entries| {
            entries.retain(|t| now.duration_since(*t) < std::time::Duration::from_secs(300));
            !entries.is_empty()
        });
    }

    #[cfg(test)]
    pub async fn key_count(&self) -> usize {
        self.inner.lock().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allows_up_to_limit_then_blocks() {
        let limiter = RateLimiter::new();
        for _ in 0..3 {
            assert!(limiter.check("k", 3, 60).await);
        }
        assert!(!limiter.check("k", 3, 60).await);
    }

    #[tokio::test]
    async fn distinct_keys_are_independent() {
        let limiter = RateLimiter::new();
        assert!(limiter.check("a", 1, 60).await);
        assert!(!limiter.check("a", 1, 60).await);
        // A different key still has its own budget.
        assert!(limiter.check("b", 1, 60).await);
    }

    #[tokio::test]
    async fn key_count_is_bounded() {
        let limiter = RateLimiter::with_max_keys(8);
        for i in 0..1_000 {
            limiter.check(&format!("key-{i}"), 10, 60).await;
        }
        // The map never grows past the configured ceiling.
        assert!(limiter.key_count().await <= 8);
    }
}
