use std::sync::Arc;
use std::time::{Duration, Instant};

/// A cached, already-authenticated RRset with its expiry.
#[derive(Debug, Clone)]
pub struct CacheEntry<T> {
    items: Arc<[T]>,
    expires_at: Instant,
}

impl<T> CacheEntry<T> {
    pub fn new(items: Vec<T>, ttl_secs: u32) -> Self {
        Self {
            items: Arc::from(items),
            expires_at: Instant::now() + Duration::from_secs(u64::from(ttl_secs)),
        }
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    pub fn items(&self) -> &Arc<[T]> {
        &self.items
    }
}
