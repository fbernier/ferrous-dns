use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::dns::{
    cache::{DnsCache, DnsCacheConfig, EvictionStrategy},
    CachedAddresses, CachedData,
};
use std::sync::Arc;
use tracing::{info, warn};

/// The configured eviction strategy; an unknown name falls back to the
/// hit-rate default with a warning rather than failing startup.
fn eviction_strategy(name: &str) -> EvictionStrategy {
    name.parse().unwrap_or_else(|e| {
        warn!(error = %e, "Unknown cache_eviction_strategy, using hit_rate");
        EvictionStrategy::HitRate
    })
}

pub(super) fn build_cache(config: &Config) -> Arc<DnsCache> {
    if config.dns.cache_enabled {
        let eviction_strategy = eviction_strategy(&config.dns.cache_eviction_strategy);
        info!(
            strategy = eviction_strategy.as_str(),
            max_entries = config.dns.cache_max_entries,
            "Cache enabled"
        );
        Arc::new(DnsCache::new(DnsCacheConfig {
            max_entries: config.dns.cache_max_entries,
            eviction_strategy,
            // Seeded neutral, not from `cache_min_hit_rate`: this feeds the
            // adaptive EWMA, which blends it with an eviction score bounded by
            // 1.0, while `cache_min_hit_rate` is a hits-per-minute figure. The
            // EWMA converges on the observed worst score on its own.
            min_threshold: 0.0,
            refresh_threshold: config.dns.cache_refresh_threshold,
            batch_eviction_percentage: config.dns.cache_batch_eviction_percentage,
            adaptive_thresholds: config.dns.cache_adaptive_thresholds,
            min_frequency: config.dns.cache_min_frequency,
            min_lfuk_score: config.dns.cache_min_lfuk_score,
            shard_amount: config.dns.cache_shard_amount,
            access_window_secs: config.dns.cache_access_window_secs,
            eviction_sample_size: config.dns.cache_eviction_sample_size,
            lfuk_k_value: 0.5,
            refresh_sample_rate: 1.0,
            min_ttl: config.dns.cache_min_ttl,
            max_ttl: config.dns.cache_max_ttl,
        }))
    } else {
        Arc::new(DnsCache::new(DnsCacheConfig {
            max_entries: 0,
            eviction_strategy: EvictionStrategy::HitRate,
            min_threshold: 0.0,
            refresh_threshold: 0.0,
            batch_eviction_percentage: 0.0,
            adaptive_thresholds: false,
            min_frequency: 0,
            min_lfuk_score: 0.0,
            shard_amount: 4,
            access_window_secs: 0,
            eviction_sample_size: 8,
            lfuk_k_value: 0.5,
            refresh_sample_rate: 1.0,
            min_ttl: config.dns.cache_min_ttl,
            max_ttl: config.dns.cache_max_ttl,
        }))
    }
}

pub(super) fn preload_local_records_into_cache(
    cache: &Arc<DnsCache>,
    records: &[ferrous_dns_domain::LocalDnsRecord],
    default_domain: Option<&str>,
) {
    // Wildcards are served by `LocalWildcardResolver` above the cache: a cache
    // key is matched exactly, so `*.home.lan` here would be an entry no query
    // could ever reach.
    let mut count = 0usize;
    for record in records.iter().filter(|r| !r.is_wildcard()) {
        let fqdn = record.fqdn(default_domain);
        let data = CachedData::IpAddresses(CachedAddresses {
            addresses: Arc::new(vec![record.ip]),
        });
        let ttl = record.ttl_or_default();

        cache.insert_permanent(&fqdn, record.record_type.into(), data, ttl, None);

        info!(
            fqdn = %fqdn,
            ip = %record.ip,
            record_type = %record.record_type,
            ttl = %ttl,
            "Preloaded local DNS record into permanent cache"
        );
        count += 1;
    }

    if count > 0 {
        info!(
            count,
            wildcards = records.len() - count,
            "✓ Preloaded {} local DNS record(s) into permanent cache",
            count
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_documented_eviction_strategy_is_honoured() {
        assert_eq!(eviction_strategy("lru"), EvictionStrategy::LRU);
        assert_eq!(eviction_strategy("lfu"), EvictionStrategy::LFU);
        assert_eq!(eviction_strategy("lfu-k"), EvictionStrategy::LFUK);
        assert_eq!(eviction_strategy("hit_rate"), EvictionStrategy::HitRate);
    }

    #[test]
    fn unknown_eviction_strategy_falls_back_to_hit_rate() {
        assert_eq!(eviction_strategy("fifo"), EvictionStrategy::HitRate);
    }
}
