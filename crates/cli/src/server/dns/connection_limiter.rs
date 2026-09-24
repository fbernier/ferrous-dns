use dashmap::DashMap;
use rustc_hash::FxBuildHasher;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

type Counts = DashMap<IpAddr, AtomicU32, FxBuildHasher>;

/// Limits concurrent TCP/DoT/DoQ connections per IP address.
///
/// Uses an RAII guard: when a connection is accepted, `try_acquire()` returns
/// a `ConnectionGuard` that decrements the count on drop.
#[derive(Clone)]
pub struct ConnectionLimiter {
    counts: Arc<Counts>,
    max_per_ip: u32,
}

/// RAII guard that releases the connection's slot when it closes; holds
/// nothing (and releases nothing) in unlimited mode.
pub struct ConnectionGuard(Option<(Arc<Counts>, IpAddr)>);

impl ConnectionLimiter {
    /// Creates a new limiter. `max_per_ip = 0` means unlimited.
    pub fn new(max_per_ip: u32) -> Self {
        Self {
            counts: Arc::new(DashMap::with_hasher(FxBuildHasher)),
            max_per_ip,
        }
    }

    /// Tries to acquire a connection slot for `ip`.
    /// Returns `Some(guard)` if within limit, `None` if the limit is exceeded.
    pub fn try_acquire(&self, ip: IpAddr) -> Option<ConnectionGuard> {
        if self.max_per_ip == 0 {
            return Some(ConnectionGuard(None));
        }

        // The entry's shard lock is held until `entry` drops, which is what
        // lets `ConnectionGuard::drop` remove only a genuinely idle entry.
        let entry = self.counts.entry(ip).or_insert_with(|| AtomicU32::new(0));
        let prev = entry.value().fetch_add(1, Ordering::Relaxed);

        if prev >= self.max_per_ip {
            entry.value().fetch_sub(1, Ordering::Relaxed);
            return None;
        }

        Some(ConnectionGuard(Some((Arc::clone(&self.counts), ip))))
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let Some((counts, ip)) = &self.0 else {
            return;
        };
        let Some(entry) = counts.get(ip) else {
            return;
        };
        let prev = entry.value().fetch_sub(1, Ordering::Relaxed);
        // Release the shard read-lock before the map-level remove.
        drop(entry);
        if prev <= 1 {
            // Re-checked under the shard write lock: a connection acquired
            // since the decrement keeps the entry, and with it its count.
            counts.remove_if(ip, |_, count| count.load(Ordering::Relaxed) == 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_within_limit() {
        let limiter = ConnectionLimiter::new(2);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let g1 = limiter.try_acquire(ip);
        let g2 = limiter.try_acquire(ip);
        assert!(g1.is_some());
        assert!(g2.is_some());
    }

    #[test]
    fn rejects_over_limit() {
        let limiter = ConnectionLimiter::new(2);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let _g1 = limiter.try_acquire(ip).unwrap();
        let _g2 = limiter.try_acquire(ip).unwrap();
        assert!(limiter.try_acquire(ip).is_none());
    }

    #[test]
    fn guard_drop_frees_slot() {
        let limiter = ConnectionLimiter::new(1);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        {
            let _g = limiter.try_acquire(ip).unwrap();
            assert!(limiter.try_acquire(ip).is_none());
        }
        assert!(limiter.try_acquire(ip).is_some());
    }

    #[test]
    fn unlimited_when_zero() {
        let limiter = ConnectionLimiter::new(0);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let guards: Vec<_> = (0..100).map(|_| limiter.try_acquire(ip).unwrap()).collect();
        assert_eq!(guards.len(), 100);
    }

    #[test]
    fn concurrent_release_never_admits_past_the_limit() {
        let limiter = ConnectionLimiter::new(1);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let holders = AtomicU32::new(0);
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    for _ in 0..50_000 {
                        if let Some(guard) = limiter.try_acquire(ip) {
                            let others = holders.fetch_add(1, Ordering::SeqCst);
                            assert_eq!(others, 0, "two connections held the only slot");
                            holders.fetch_sub(1, Ordering::SeqCst);
                            drop(guard);
                        }
                    }
                });
            }
        });
    }
}
