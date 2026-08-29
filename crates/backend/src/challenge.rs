//! Transient single-use login challenges. Challenges live in memory only —
//! they are never persisted and expire after a short TTL.
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct PendingChallenge {
    /// Server-held ephemeral X25519 private key used to seal the challenge.
    pub ephemeral_priv: [u8; 32],
    /// The 32-byte response nonce the client must recover.
    pub expected_response: [u8; 32],
    pub created: Instant,
}

pub const CHALLENGE_TTL: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct ChallengeStore {
    inner: Arc<Mutex<HashMap<String, PendingChallenge>>>,
}

impl Default for ChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn insert(&self, key: String, ephemeral_priv: [u8; 32], expected_response: [u8; 32]) {
        self.inner.lock().await.insert(
            key,
            PendingChallenge {
                ephemeral_priv,
                expected_response,
                created: Instant::now(),
            },
        );
    }

    /// Constant-time verification of the response and single-use consumption.
    /// A stale challenge is expired (removed) and treated as a miss.
    pub async fn verify_and_consume(&self, key: &str, response: &[u8]) -> bool {
        let mut map = self.inner.lock().await;
        let Some(pending) = map.get(key) else {
            return false;
        };
        if pending.created.elapsed() > CHALLENGE_TTL {
            map.remove(key);
            return false;
        }
        if !constant_time_eq(&pending.expected_response, response) {
            return false;
        }
        map.remove(key);
        true
    }

    pub async fn cleanup(&self) {
        let mut map = self.inner.lock().await;
        map.retain(|_, pending| pending.created.elapsed() <= CHALLENGE_TTL);
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}
