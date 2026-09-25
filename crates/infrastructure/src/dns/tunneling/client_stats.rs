use dashmap::DashMap;
use rustc_hash::FxBuildHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Compact tracking key: client subnet hash + apex domain hash.
///
/// Register-sized (16 bytes) for efficient DashMap lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrackingKey {
    pub subnet: u64,
    pub apex_hash: u64,
}

/// Per-client per-apex-domain statistics for tunneling analysis.
///
/// All fields are atomic for lock-free concurrent updates.
pub struct ClientApexStats {
    pub query_count: AtomicU32,
    pub unique_subdomain_count: AtomicU32,
    pub txt_query_count: AtomicU32,
    pub nxdomain_count: AtomicU32,
    pub last_seen_ns: AtomicU64,
    pub window_start_ns: AtomicU64,
    /// 256-bit mini bloom filter for approximate unique subdomain counting.
    pub mini_bloom: [AtomicU64; 4],
}

impl ClientApexStats {
    pub fn new(now_ns: u64) -> Self {
        Self {
            query_count: AtomicU32::new(0),
            unique_subdomain_count: AtomicU32::new(0),
            txt_query_count: AtomicU32::new(0),
            nxdomain_count: AtomicU32::new(0),
            last_seen_ns: AtomicU64::new(now_ns),
            window_start_ns: AtomicU64::new(now_ns),
            mini_bloom: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
        }
    }

    /// Resets counters for a new time window.
    pub fn reset_window(&self, now_ns: u64) {
        self.query_count.store(0, Ordering::Relaxed);
        self.unique_subdomain_count.store(0, Ordering::Relaxed);
        self.txt_query_count.store(0, Ordering::Relaxed);
        self.nxdomain_count.store(0, Ordering::Relaxed);
        self.window_start_ns.store(now_ns, Ordering::Relaxed);
        for slot in &self.mini_bloom {
            slot.store(0, Ordering::Relaxed);
        }
    }

    /// Adds a subdomain hash to the mini bloom filter using two independent bit positions.
    /// Returns `true` if the subdomain was probably new (not seen before).
    pub fn bloom_add(&self, subdomain_hash: u64) -> bool {
        let idx1 = (subdomain_hash & 0xFF) as usize;
        let idx2 = ((subdomain_hash >> 8) & 0xFF) as usize;

        let slot1 = idx1 / 64;
        let bit1 = 1u64 << (idx1 % 64);
        let old1 = self.mini_bloom[slot1].fetch_or(bit1, Ordering::Relaxed);

        let slot2 = idx2 / 64;
        let bit2 = 1u64 << (idx2 % 64);
        let old2 = self.mini_bloom[slot2].fetch_or(bit2, Ordering::Relaxed);

        (old1 & bit1) == 0 || (old2 & bit2) == 0
    }
}

/// Sharded concurrent map for per-client per-apex statistics.
pub type StatsMap = DashMap<TrackingKey, ClientApexStats, FxBuildHasher>;

/// Groups clients by /24 (IPv4) or /48 (IPv6) so one host rotating addresses
/// inside its allocation is still counted as one client.
pub fn subnet_key_from_ip(ip: IpAddr) -> u64 {
    // IPv4-mapped IPv6 (dual-stack sockets) would otherwise collapse every
    // IPv4 client into the single ::/48 key.
    match ip.to_canonical() {
        IpAddr::V4(v4) => u64::from(u32::from(v4) & (u32::MAX << 8)),
        IpAddr::V6(v6) => ((u128::from(v6) & (u128::MAX << 80)) >> 64) as u64,
    }
}

/// Computes a fast hash for a domain string using FxHash.
pub fn fx_hash_str(s: &str) -> u64 {
    let mut hasher = rustc_hash::FxHasher::default();
    s.hash(&mut hasher);
    hasher.finish()
}
