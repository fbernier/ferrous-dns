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
    evict_if_full(map, CacheEntry::is_expired);
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

/// Makes room in a full `map` before an insert. Inspects at most
/// [`EVICTION_BATCH_SIZE`] entries for expiration first;
/// if the map is still full it drops one arbitrary entry so the
/// insert cannot grow the map past the ceiling. Hot zones (root, common TLDs)
/// re-populate on the next miss, so worst case is extra churn, never unbounded
/// growth.
fn evict_if_full<V, F>(map: &CountedDashMap<Arc<str>, V>, is_expired: F)
where
    F: Fn(&V) -> bool,
{
    if map.len() < MAX_ENTRIES {
        return;
    }

    let expired: Vec<Arc<str>> = map
        .iter()
        .take(EVICTION_BATCH_SIZE)
        .filter(|e| is_expired(e.value()))
        .map(|e| e.key().clone())
        .collect();
    for k in &expired {
        map.remove(k);
    }

    if map.len() >= MAX_ENTRIES {
        let fallback = map.iter().next().map(|e| e.key().clone());
        if let Some(k) = fallback {
            map.remove(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn eviction_bounds_inspections_and_makes_room() {
        for expired in [false, true] {
            let map: CountedDashMap<Arc<str>, bool> = (0..MAX_ENTRIES)
                .map(|i| (Arc::from(format!("zone{i}.example")), expired))
                .collect();
            let inspected = Cell::new(0);

            evict_if_full(&map, |expired| {
                inspected.set(inspected.get() + 1);
                *expired
            });

            assert_eq!(inspected.get(), EVICTION_BATCH_SIZE);
            let removed = if expired { EVICTION_BATCH_SIZE } else { 1 };
            assert_eq!(map.len(), MAX_ENTRIES - removed);
        }
    }
}
