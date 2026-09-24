mod cache;
mod pool;
mod resolver;

use crate::server::dns::connection_limiter::ConnectionLimiter;
use ferrous_dns_application::ports::{
    CacheMaintenancePort, DgaEvictionTarget, DgaFlagStore, DnssecStatsPort, NxdomainHijackIpStore,
    NxdomainHijackProbeTarget, PtrRecordRegistry, ResponseIpFilterEvictionTarget,
    ResponseIpFilterStore, TunnelingEvictionTarget, TunnelingFlagStore, WildcardRecordRegistry,
};
use ferrous_dns_application::use_cases::dns::rate_limiter::DnsRateLimiter;
use ferrous_dns_application::use_cases::dns::tsc_timer;
use ferrous_dns_application::use_cases::dns::DnsCookieGuard;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::dns::{
    cache::DnsCache,
    cache_maintenance::DnsCacheMaintenance,
    dnssec::DnssecStatsAdapter,
    resolver::{LocalPtrResolver, LocalWildcardResolver, WildcardRegistry},
    DgaDetector, HealthChecker, HickoryDnsResolver, NxdomainHijackDetector, PoolManager,
    RefreshScanOptions, RefreshSenders, ResponseIpFilterDetector, TunnelingDetector,
};
use ferrous_dns_jobs::{
    DgaEvictionJob, NxdomainHijackEvictionJob, ResponseIpFilterEvictionJob, TunnelingEvictionJob,
    DEFAULT_REFRESH_INTERVAL_SECS,
};
use std::sync::Arc;
use tracing::{info, warn};

use super::Repositories;

pub struct DnsServices {
    pub cache: Arc<DnsCache>,
    pub handler_use_case: Arc<HandleDnsQueryUseCase>,
    pub pool_manager: Arc<PoolManager>,
    /// Pool manager the DNSSEC validator walks the chain of trust on; absent
    /// when validation is off.
    pub dnssec_pool_manager: Option<Arc<PoolManager>>,
    /// Live counters from the DNSSEC validator cache. Reports zeros when DNSSEC
    /// validation is disabled.
    pub dnssec_stats: Arc<dyn DnssecStatsPort>,
    /// Pool manager backing the cache optimistic-refresh resolver, when that
    /// path is enabled. Kept so hot upstream reloads also reach it.
    pub maintenance_pool_manager: Option<Arc<PoolManager>>,
    pub health_checker: Arc<HealthChecker>,
    pub cache_maintenance: Option<Arc<dyn CacheMaintenancePort>>,
    pub ptr_registry: Option<Arc<dyn PtrRecordRegistry>>,
    /// Live wildcard index. Always present, even with no wildcard configured,
    /// so the first one added from the admin UI answers without a restart.
    pub wildcard_registry: Arc<dyn WildcardRecordRegistry>,
    pub tcp_conn_limiter: ConnectionLimiter,
    pub dot_conn_limiter: ConnectionLimiter,
    pub doq_conn_limiter: ConnectionLimiter,
}

impl DnsServices {
    pub async fn new(config: &Config, repos: &Repositories) -> anyhow::Result<Self> {
        info!("Initializing DNS services with load balancing");
        tsc_timer::init();

        let health_checker = pool::setup_health_checker(config);
        let pool_manager = pool::setup_pool_manager(config, &health_checker).await?;
        pool::start_health_checker_task(Arc::clone(&health_checker), &pool_manager, config);

        let timeout_ms = config.dns.query_timeout * 1000;

        // The DNSSEC validator walks the chain of trust on its own pool manager.
        // It needs its own health checker + probe task, otherwise its upstreams
        // are never marked healthy and every chain lookup fails "unreachable" —
        // which would make Strict mode SERVFAIL even correctly-signed domains.
        let dnssec_pool_manager = if config.dns.effective_dnssec_mode().validates() {
            let dnssec_health_checker = pool::setup_health_checker(config);
            let manager = pool::setup_pool_manager(config, &dnssec_health_checker).await?;
            pool::start_health_checker_task(dnssec_health_checker, &manager, config);
            Some(manager)
        } else {
            None
        };

        let (mut dns_resolver, dnssec_cache) = resolver::build_resolver(
            Arc::clone(&pool_manager),
            dnssec_pool_manager.clone(),
            config,
            repos,
            timeout_ms,
        )?;
        let dnssec_stats: Arc<dyn DnssecStatsPort> = Arc::new(match dnssec_cache {
            Some(cache) => DnssecStatsAdapter::new(cache),
            None => DnssecStatsAdapter::disabled(),
        });
        let dns_cache = cache::build_cache(config);

        if config.dns.cache_enabled {
            dns_resolver = dns_resolver
                .with_inflight_shards(config.dns.cache_inflight_shards)
                .with_cache(dns_cache.clone(), config.dns.cache_ttl);
        }

        let (cache_maintenance, maintenance_pool_manager) =
            Self::setup_cache_maintenance(config, &dns_cache, &health_checker, timeout_ms, repos)
                .await?;

        let ptr_registry: Option<Arc<dyn PtrRecordRegistry>> =
            if !config.dns.local_records.is_empty() {
                info!(
                    count = config.dns.local_records.len(),
                    "Preloading local DNS records into permanent cache..."
                );
                cache::preload_local_records_into_cache(
                    &dns_cache,
                    &config.dns.local_records,
                    &config.dns.local_domain,
                );
                info!("✓ Local DNS records preloaded (cached permanently, <0.1ms resolution)");

                let dummy_inner: Arc<dyn ferrous_dns_application::ports::DnsResolver> =
                    Arc::new(HickoryDnsResolver::new_with_pools(
                        Arc::clone(&pool_manager),
                        timeout_ms,
                        false,
                        None,
                    )?);
                let local_ptr = Arc::new(LocalPtrResolver::from_local_records(
                    &config.dns.local_records,
                    &config.dns.local_domain,
                    dummy_inner,
                ));
                dns_resolver = dns_resolver.with_local_ptr_map(Arc::clone(&local_ptr.map));
                Some(local_ptr as Arc<dyn PtrRecordRegistry>)
            } else {
                None
            };

        // Unconditional, unlike the PTR map above: an empty index costs one
        // `is_empty()` check per query, and it is what lets a wildcard created
        // from the admin UI take effect on the next query.
        let wildcard_map = LocalWildcardResolver::map_from_local_records(
            &config.dns.local_records,
            &config.dns.local_domain,
        );
        dns_resolver = dns_resolver.with_local_wildcards(Arc::clone(&wildcard_map));
        let wildcard_registry: Arc<dyn WildcardRecordRegistry> =
            Arc::new(WildcardRegistry::new(wildcard_map));

        let resolver = Arc::new(dns_resolver);

        let rate_limiter = Arc::new(DnsRateLimiter::new(&config.dns.rate_limit));
        if config.dns.rate_limit.enabled {
            rate_limiter.start_eviction_task();
            info!(
                "DNS rate limiter enabled ({}qps, burst {})",
                config.dns.rate_limit.queries_per_second, config.dns.rate_limit.burst_size
            );
        }

        let tunneling_detector = if config.dns.tunneling_detection.enabled {
            let (detector, tx, rx) = TunnelingDetector::new(&config.dns.tunneling_detection);
            let detector = Arc::new(detector);
            let detector_clone = Arc::clone(&detector);
            tokio::spawn(async move { detector_clone.run_analysis_loop(rx).await });
            TunnelingEvictionJob::new(
                Arc::clone(&detector) as Arc<dyn TunnelingEvictionTarget>,
                detector.stale_entry_ttl_secs(),
            )
            .spawn();
            info!(
                action = ?config.dns.tunneling_detection.action,
                "DNS tunneling detection enabled"
            );
            if config.dns.tunneling_detection.action
                == ferrous_dns_domain::TunnelingAction::Throttle
            {
                warn!("Tunneling action 'throttle' is not yet implemented — treating as 'alert'");
            }
            Some((detector, tx))
        } else {
            None
        };

        let nxdomain_hijack_detector = if config.dns.nxdomain_hijack.enabled {
            let detector = Arc::new(NxdomainHijackDetector::new(&config.dns.nxdomain_hijack));
            let protocols = pool_manager.get_all_arc_protocols();
            let detector_clone = Arc::clone(&detector);
            tokio::spawn(async move {
                detector_clone.run_probe_loop(protocols).await;
            });
            // Evict at twice the probe frequency so stale IPs are cleaned
            // before the TTL fully expires.
            NxdomainHijackEvictionJob::new(
                Arc::clone(&detector) as Arc<dyn NxdomainHijackProbeTarget>,
                config.dns.nxdomain_hijack.hijack_ip_ttl_secs / 2,
            )
            .spawn();
            info!(
                action = ?config.dns.nxdomain_hijack.action,
                "NXDomain hijack detection enabled"
            );
            Some(detector)
        } else {
            None
        };

        let mut handler = HandleDnsQueryUseCase::new(
            resolver.clone(),
            repos.block_filter_engine.clone(),
            repos.query_log.clone(),
        )
        .with_safe_search(repos.safe_search_engine.clone())
        .with_client_tracking(
            repos.client.clone(),
            config.database.client_tracking_interval,
        )
        .with_rebinding_protection(
            config.dns.rebinding_protection_enabled,
            config.dns.local_domain.as_deref(),
            &config.dns.rebinding_allowlist,
        )
        .with_rate_limiter(rate_limiter)
        .with_dnssec_enforcement(config.dns.effective_dnssec_mode().enforces())
        .with_query_logging(config.database.log_queries);

        if config.dns64.enabled {
            if let Some(prefix) = config.dns64.parsed_prefix() {
                handler = handler.with_dns64(prefix);
            }
        }

        if let Some((detector, tx)) = &tunneling_detector {
            handler = handler
                .with_tunneling_detection(&config.dns.tunneling_detection)
                .with_tunneling_event_sender(tx.clone())
                .with_tunneling_flag_store(Arc::clone(detector) as Arc<dyn TunnelingFlagStore>);
        }

        if let Some(detector) = &nxdomain_hijack_detector {
            handler = handler.with_nxdomain_hijack_detection(
                &config.dns.nxdomain_hijack,
                Arc::clone(detector) as Arc<dyn NxdomainHijackIpStore>,
            );
        }

        let response_ip_filter_detector = if config.dns.response_ip_filter.enabled
            && !config.dns.response_ip_filter.ip_list_urls.is_empty()
        {
            let detector = Arc::new(ResponseIpFilterDetector::new(
                &config.dns.response_ip_filter,
            ));
            let http_client = reqwest::Client::builder()
                .user_agent(format!(
                    "ferrous-dns/{} (response-ip-filter)",
                    env!("CARGO_PKG_VERSION")
                ))
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|e| anyhow::anyhow!("Failed to build HTTP client: {e}"))?;
            let detector_clone = Arc::clone(&detector);
            tokio::spawn(async move {
                detector_clone.run_fetch_loop(http_client).await;
            });
            ResponseIpFilterEvictionJob::new(
                Arc::clone(&detector) as Arc<dyn ResponseIpFilterEvictionTarget>,
                config.dns.response_ip_filter.ip_ttl_secs / 2,
            )
            .spawn();
            if config.dns.response_ip_filter.ip_ttl_secs
                < config.dns.response_ip_filter.refresh_interval_secs
            {
                warn!(
                    ip_ttl_secs = config.dns.response_ip_filter.ip_ttl_secs,
                    refresh_interval_secs = config.dns.response_ip_filter.refresh_interval_secs,
                    "ip_ttl_secs < refresh_interval_secs — IPs will be evicted before the next feed refresh"
                );
            }
            info!(
                action = ?config.dns.response_ip_filter.action,
                "Response IP filtering enabled"
            );
            Some(detector)
        } else {
            None
        };

        if let Some(detector) = &response_ip_filter_detector {
            handler = handler.with_response_ip_filter(
                &config.dns.response_ip_filter,
                Arc::clone(detector) as Arc<dyn ResponseIpFilterStore>,
            );
        }

        let dga_detector = if config.dns.dga_detection.enabled {
            let (detector, tx, rx) = DgaDetector::new(&config.dns.dga_detection);
            let detector = Arc::new(detector);
            let detector_clone = Arc::clone(&detector);
            tokio::spawn(async move { detector_clone.run_analysis_loop(rx).await });
            DgaEvictionJob::new(
                Arc::clone(&detector) as Arc<dyn DgaEvictionTarget>,
                detector.stale_entry_ttl_secs(),
            )
            .spawn();
            info!(
                action = ?config.dns.dga_detection.action,
                "DGA detection enabled"
            );
            Some((detector, tx))
        } else {
            None
        };

        if let Some((detector, tx)) = &dga_detector {
            handler = handler
                .with_dga_detection(&config.dns.dga_detection)
                .with_dga_event_sender(tx.clone())
                .with_dga_flag_store(Arc::clone(detector) as Arc<dyn DgaFlagStore>);
        }

        if config.dns.dns_cookies.enabled {
            let secret = resolve_cookie_secret(&config.dns.dns_cookies)?;
            let cookie_guard = DnsCookieGuard::from_config(&config.dns.dns_cookies, secret);
            handler = handler.with_dns_cookies(cookie_guard);
            info!(
                require_valid = config.dns.dns_cookies.require_valid_cookie,
                "DNS Cookies (RFC 7873) enabled"
            );
        }

        let handler_use_case = Arc::new(handler);

        let tcp_conn_limiter =
            ConnectionLimiter::new(config.dns.rate_limit.tcp_max_connections_per_ip);
        let dot_conn_limiter =
            ConnectionLimiter::new(config.dns.rate_limit.dot_max_connections_per_ip);
        let doq_conn_limiter =
            ConnectionLimiter::new(config.dns.rate_limit.doq_max_connections_per_ip);

        info!("DNS services initialized successfully with load balancing");

        Ok(Self {
            cache: dns_cache,
            handler_use_case,
            pool_manager,
            dnssec_pool_manager,
            dnssec_stats,
            maintenance_pool_manager,
            health_checker,
            cache_maintenance,
            ptr_registry,
            wildcard_registry,
            tcp_conn_limiter,
            dot_conn_limiter,
            doq_conn_limiter,
        })
    }

    async fn setup_cache_maintenance(
        config: &Config,
        cache: &Arc<DnsCache>,
        health_checker: &Arc<HealthChecker>,
        timeout_ms: u64,
        repos: &Repositories,
    ) -> anyhow::Result<(
        Option<Arc<dyn CacheMaintenancePort>>,
        Option<Arc<PoolManager>>,
    )> {
        if !config.dns.cache_enabled || !config.dns.cache_optimistic_refresh {
            return Ok((None, None));
        }

        // The optimistic queue holds one cycle's backlog. A cycle produces
        // roughly `entries * interval / ttl` candidates, so it is sized off the
        // cache rather than fixed: a constant that fits a small deployment
        // silently caps how much of a large one can stay warm. The clamp keeps
        // both ends sane — the upper bound is ~0.8 MB of queued keys.
        let optimistic_capacity = (config.dns.cache_max_entries / 4).clamp(1024, 32_768);
        // The stale queue is shallower on purpose: those items are
        // latency-sensitive and drained unpaced, so it only has to absorb a
        // burst, not a backlog — the client interaction is over long before a
        // deep one would drain.
        let (stale_tx, stale_rx) = tokio::sync::mpsc::channel(128);
        let (optimistic_tx, optimistic_rx) = tokio::sync::mpsc::channel(optimistic_capacity);
        let (pace_tx, pace_rx) = tokio::sync::watch::channel(None);
        cache.set_refresh_senders(RefreshSenders {
            stale: stale_tx,
            optimistic: optimistic_tx,
        });

        // A candidate waits up to one cycle to be scanned and up to one more to
        // be drained, so anything with less life than that left would expire
        // before its turn. Taking it early is what makes "renewed before the
        // TTL lapses" hold rather than merely tend to hold.
        let scan_opts = RefreshScanOptions {
            min_lead_secs: DEFAULT_REFRESH_INTERVAL_SECS * 2,
            min_hit_rate: config.dns.cache_min_hit_rate,
            min_frequency: config.dns.cache_min_frequency,
        };

        // Returned too, so hot upstream reloads also reach this resolver.
        let maintenance_pool_manager = pool::setup_pool_manager(config, health_checker).await?;
        let resolver_for_maintenance: Arc<dyn ferrous_dns_application::ports::DnsResolver> =
            Arc::new(HickoryDnsResolver::new_with_pools(
                Arc::clone(&maintenance_pool_manager),
                timeout_ms,
                false,
                None,
            )?);

        DnsCacheMaintenance::start_refresh_worker(
            cache.clone(),
            resolver_for_maintenance,
            Some(repos.query_log.clone()),
            stale_rx,
            optimistic_rx,
            pace_rx,
            scan_opts.min_lead_secs,
        );

        Ok((
            Some(Arc::new(DnsCacheMaintenance::new(
                cache.clone(),
                DEFAULT_REFRESH_INTERVAL_SECS,
                scan_opts,
                pace_tx,
            )) as Arc<dyn CacheMaintenancePort>),
            Some(maintenance_pool_manager),
        ))
    }
}

/// The DNS Cookie server secret: the configured 64-hex-digit value, or a fresh
/// random one when none is set.
fn resolve_cookie_secret(
    config: &ferrous_dns_domain::DnsCookiesConfig,
) -> anyhow::Result<[u8; 32]> {
    let mut secret = [0u8; 32];
    if config.server_secret.is_empty() {
        use ring::rand::SecureRandom;
        ring::rand::SystemRandom::new()
            .fill(&mut secret)
            .map_err(|_| anyhow::anyhow!("system RNG failed to generate the DNS cookie secret"))?;
        warn!(
            "dns_cookies.server_secret is not set — using ephemeral secret \
             (will not survive restart; set a 64-hex-char value in config)"
        );
        return Ok(secret);
    }

    let hex = config.server_secret.trim().as_bytes();
    anyhow::ensure!(
        hex.len() == 64,
        "dns_cookies.server_secret must be exactly 64 hex characters (32 bytes), got {}",
        hex.len()
    );
    let digit = |b: u8| char::from(b).to_digit(16);
    for (byte, pair) in secret.iter_mut().zip(hex.chunks_exact(2)) {
        let (Some(high), Some(low)) = (digit(pair[0]), digit(pair[1])) else {
            anyhow::bail!("dns_cookies.server_secret contains invalid hex characters");
        };
        *byte = (high << 4 | low) as u8;
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrous_dns_domain::DnsCookiesConfig;

    fn with_secret(secret: &str) -> DnsCookiesConfig {
        DnsCookiesConfig {
            server_secret: secret.to_string(),
            ..DnsCookiesConfig::default()
        }
    }

    #[test]
    fn configured_cookie_secret_is_decoded() {
        let hex = format!("  {}  ", "0fA1".repeat(16));
        let secret = resolve_cookie_secret(&with_secret(&hex)).unwrap();
        assert_eq!(secret[..2], [0x0f, 0xa1]);
        assert_eq!(secret[30..], [0x0f, 0xa1]);
    }

    #[test]
    fn malformed_cookie_secrets_are_errors_not_panics() {
        for bad in [
            "abc".to_string(),
            "zz".repeat(32),
            "+f".repeat(32),
            format!("{}é", "a".repeat(62)),
        ] {
            assert!(
                resolve_cookie_secret(&with_secret(&bad)).is_err(),
                "{bad:?} was accepted"
            );
        }
    }
}
