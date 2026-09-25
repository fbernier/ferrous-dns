use super::super::types::{DnskeyRecord, DsRecord};
use super::entries::CacheEntry;
use super::stats::{CacheStats, CacheStatsSnapshot};
use crate::counted_map::CountedDashMap;
use std::sync::Arc;
use tracing::{debug, trace};

/// Per-map ceiling on cached zones. Without it, a stream of queries naming
/// distinct (attacker-chosen) signer zones would grow these maps without bound
/// — a memory-exhaustion vector, since every cold chain walk inserts a DS and a
/// DNSKEY entry. The real namespace a recursor touches is far smaller than this.
const MAX_ENTRIES: usize = 50_000;

/// Maximum entries inspected for expiration per full-cache insert before
/// falling back to evicting an arbitrary entry.
const EVICTION_BATCH_SIZE: usize = 32;

pub struct DnssecCache {
    dnskeys: CountedDashMap<Arc<str>, CacheEntry<DnskeyRecord>>,

    ds_records: CountedDashMap<Arc<str>, CacheEntry<DsRecord>>,

    stats: CacheStats,
}

impl DnssecCache {
    pub fn new() -> Self {
        Self {
            dnskeys: CountedDashMap::new(),
            ds_records: CountedDashMap::new(),
            stats: CacheStats::default(),
        }
    }

    pub fn cache_dnskey(&self, domain: &str, keys: Vec<DnskeyRecord>, ttl_seconds: u32) {
        insert(&self.dnskeys, domain, keys, ttl_seconds);
        trace!(domain = %domain, ttl = ttl_seconds, "Cached DNSKEY records");
    }

    pub fn get_dnskey(&self, domain: &str) -> Option<Arc<[DnskeyRecord]>> {
        let hit = lookup(&self.dnskeys, domain);
        if hit.is_some() {
            self.stats.record_dnskey_hit();
        } else {
            self.stats.record_dnskey_miss();
        }
        hit
    }

    pub fn cache_ds(&self, domain: &str, records: Vec<DsRecord>, ttl_seconds: u32) {
        insert(&self.ds_records, domain, records, ttl_seconds);
        trace!(domain = %domain, ttl = ttl_seconds, "Cached DS records");
    }

    pub fn get_ds(&self, domain: &str) -> Option<Arc<[DsRecord]>> {
        let hit = lookup(&self.ds_records, domain);
        if hit.is_some() {
            self.stats.record_ds_hit();
        } else {
            self.stats.record_ds_miss();
        }
        hit
    }

    pub fn stats(&self) -> CacheStatsSnapshot {
        CacheStatsSnapshot {
            dnskey_entries: self.dnskeys.len(),
            ds_entries: self.ds_records.len(),
            total_dnskey_hits: self.stats.total_dnskey_hits(),
            total_dnskey_misses: self.stats.total_dnskey_misses(),
            total_ds_hits: self.stats.total_ds_hits(),
            total_ds_misses: self.stats.total_ds_misses(),
            total_ds_denial_fail_opens: self.stats.total_ds_denial_fail_opens(),
        }
    }

    /// See [`CacheStats::record_ds_denial_fail_open`].
    pub fn record_ds_denial_fail_open(&self) {
        self.stats.record_ds_denial_fail_open();
    }
}

fn insert<T>(
    map: &CountedDashMap<Arc<str>, CacheEntry<T>>,
    domain: &str,
    items: Vec<T>,
    ttl_seconds: u32,
) {
    map.evict_if_full::<EVICTION_BATCH_SIZE>(MAX_ENTRIES, CacheEntry::is_expired);
    map.insert(Arc::from(domain), CacheEntry::new(items, ttl_seconds));
}

fn lookup<T>(map: &CountedDashMap<Arc<str>, CacheEntry<T>>, domain: &str) -> Option<Arc<[T]>> {
    let entry = map.get(domain)?;
    if !entry.is_expired() {
        return Some(Arc::clone(entry.items()));
    }
    drop(entry);
    // Conditional: a concurrent validator may have re-cached a fresh set since the read.
    map.remove_if(domain, |_, entry| entry.is_expired());
    debug!(domain = %domain, "DNSSEC cache entry expired");
    None
}

impl Default for DnssecCache {
    fn default() -> Self {
        Self::new()
    }
}
