use serde::{Deserialize, Serialize};

use super::dga_detection::DgaDetectionConfig;
use super::dns_cookies::DnsCookiesConfig;
use super::dnssec::DnssecMode;
use super::health::HealthCheckConfig;
use super::local_records::LocalDnsRecord;
use super::nxdomain_hijack::NxdomainHijackConfig;
use super::rate_limit::RateLimitConfig;
use super::response_ip_filter::ResponseIpFilterConfig;
use super::tunneling::TunnelingDetectionConfig;
use super::upstream::UpstreamPool;
use super::upstream::UpstreamStrategy;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DnsConfig {
    /// Empty when omitted, unlike `Default`, which seeds public resolvers.
    #[serde(default)]
    pub upstream_servers: Vec<String>,

    pub query_timeout: u64,

    pub cache_enabled: bool,

    pub cache_ttl: u32,

    /// DNSSEC validation enforcement mode (RFC 4035 / 6840). Single source of
    /// truth. When absent, falls back to the deprecated `dnssec_enabled` flag
    /// (see `effective_dnssec_mode`).
    pub dnssec_mode: Option<DnssecMode>,

    /// Deprecated: use `dnssec_mode`. Kept only for backward-compatibility with
    /// older config files; `true` maps to `Permissive`, `false` to `Off`.
    pub dnssec_enabled: Option<bool>,

    /// Path to a DNSSEC trust anchor file in DNS presentation format (DS and/or
    /// DNSKEY records), replacing the IANA root anchors embedded in the binary.
    /// Read once at startup — deliberately not exposed through the API, since it
    /// names a host path and only takes effect on restart.
    pub dnssec_trust_anchor_file: Option<String>,

    pub default_strategy: UpstreamStrategy,

    pub pools: Vec<UpstreamPool>,

    pub health_check: HealthCheckConfig,

    pub cache_max_entries: usize,
    pub cache_eviction_strategy: String,
    pub cache_optimistic_refresh: bool,
    pub cache_min_hit_rate: f64,
    pub cache_min_frequency: u64,
    pub cache_min_lfuk_score: f64,
    pub cache_refresh_threshold: f64,

    pub cache_lfuk_history_size: usize,
    pub cache_batch_eviction_percentage: f64,
    pub cache_compaction_interval: u64,
    pub cache_adaptive_thresholds: bool,

    pub cache_shard_amount: usize,

    pub cache_inflight_shards: usize,

    pub cache_access_window_secs: u64,

    pub cache_eviction_sample_size: usize,

    pub cache_min_ttl: u32,

    pub cache_max_ttl: u32,

    pub block_private_ptr: bool,

    pub block_non_fqdn: bool,

    pub mdns_enabled: bool,

    pub local_domain: Option<String>,

    pub local_dns_server: Option<String>,

    pub local_records: Vec<LocalDnsRecord>,

    /// Whether DNS rebinding protection is enabled. When `true`, responses that
    /// resolve a public domain to a private/RFC1918 IP are blocked.
    /// Defaults to `true` — opt-out rather than opt-in for security-sensitive features.
    pub rebinding_protection_enabled: bool,

    /// Domains that are always exempt from rebinding protection, regardless of the
    /// resolved IP address. Useful for split-horizon DNS scenarios where an external
    /// name intentionally resolves to a private address (e.g. VPN or router admin panels).
    pub rebinding_allowlist: Vec<String>,

    /// DNS query rate limiting and DoS protection configuration.
    pub rate_limit: RateLimitConfig,

    /// DNS tunneling detection configuration.
    pub tunneling_detection: TunnelingDetectionConfig,

    /// NXDomain hijack detection configuration.
    pub nxdomain_hijack: NxdomainHijackConfig,

    /// Response IP filtering (block known C2 IPs in DNS responses).
    pub response_ip_filter: ResponseIpFilterConfig,

    /// DGA (Domain Generation Algorithm) detection configuration.
    pub dga_detection: DgaDetectionConfig,

    /// DNS Cookies anti-spoofing configuration (RFC 7873).
    pub dns_cookies: DnsCookiesConfig,

    /// Randomize the case of QNAME letters on A/AAAA upstream queries
    /// (draft-vixie-dns-0x20) for extra anti-spoofing entropy, validating the
    /// echoed case on the response. Off by default: some upstreams/forwarders do
    /// not preserve QNAME case and would fail validation. DNS Cookies on A/AAAA
    /// upstream queries are always on and graceful, independent of this flag.
    pub qname_case_randomization: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            upstream_servers: vec!["8.8.8.8:53".to_string(), "1.1.1.1:53".to_string()],
            query_timeout: 3,
            cache_enabled: true,
            cache_ttl: 3600,
            dnssec_mode: None,
            dnssec_enabled: None,
            dnssec_trust_anchor_file: None,
            default_strategy: UpstreamStrategy::Parallel,
            pools: vec![],
            health_check: HealthCheckConfig::default(),
            cache_max_entries: 200_000,
            cache_eviction_strategy: "hit_rate".to_string(),
            cache_optimistic_refresh: true,
            cache_min_hit_rate: 2.0,
            cache_min_frequency: 10,
            cache_min_lfuk_score: 1.5,
            cache_refresh_threshold: 0.75,
            cache_lfuk_history_size: 10,
            cache_batch_eviction_percentage: 0.1,
            cache_compaction_interval: 300,
            cache_adaptive_thresholds: false,
            cache_shard_amount: default_cache_shard_amount(),
            cache_inflight_shards: default_cache_inflight_shards(),
            cache_access_window_secs: 7200,
            cache_eviction_sample_size: 8,
            cache_min_ttl: 0,
            cache_max_ttl: 86_400,
            block_private_ptr: true,
            block_non_fqdn: false,
            mdns_enabled: false,
            local_domain: None,
            local_dns_server: None,
            local_records: vec![],
            rebinding_protection_enabled: true,
            rebinding_allowlist: vec![],
            rate_limit: RateLimitConfig::default(),
            tunneling_detection: TunnelingDetectionConfig::default(),
            nxdomain_hijack: NxdomainHijackConfig::default(),
            response_ip_filter: ResponseIpFilterConfig::default(),
            dga_detection: DgaDetectionConfig::default(),
            dns_cookies: DnsCookiesConfig::default(),
            qname_case_randomization: false,
        }
    }
}

impl DnsConfig {
    /// Resolves the effective DNSSEC mode, applying backward-compatibility
    /// precedence: an explicit `dnssec_mode` wins; otherwise the deprecated
    /// `dnssec_enabled` flag is mapped (`true` → Permissive, `false` → Off);
    /// when neither is set, the default (`Permissive`) applies.
    pub fn effective_dnssec_mode(&self) -> DnssecMode {
        if let Some(mode) = self.dnssec_mode {
            return mode;
        }
        match self.dnssec_enabled {
            Some(true) => DnssecMode::Permissive,
            Some(false) => DnssecMode::Off,
            None => DnssecMode::default(),
        }
    }
}

fn default_cache_shard_amount() -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    (cpus * 4).next_power_of_two().clamp(8, 256)
}

fn default_cache_inflight_shards() -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    // In-flight entries are transient: half the cache shard count.
    (cpus * 2).next_power_of_two().clamp(8, 128)
}
