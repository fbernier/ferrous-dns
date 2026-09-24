use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use super::auth::AuthConfig;
use super::blocking::BlockingConfig;
use super::database::DatabaseConfig;
use super::dns::DnsConfig;
use super::dns64::Dns64Config;
use super::logging::LoggingConfig;
use super::server::ServerConfig;
use super::upstream::UpstreamPool;
use crate::errors::domain_error::DomainError;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Config {
    pub server: ServerConfig,

    pub dns: DnsConfig,

    pub blocking: BlockingConfig,

    #[serde(default)]
    pub dns64: Dns64Config,

    pub logging: LoggingConfig,

    pub database: DatabaseConfig,

    #[serde(default)]
    pub auth: AuthConfig,
}

impl Config {
    /// Parses a `ferrous-dns.toml` document. Call [`Config::validate`] once
    /// every override is applied.
    pub fn from_toml_str(contents: &str) -> Result<Self, DomainError> {
        let mut config: Self = toml::from_str(contents)
            .map_err(|e| DomainError::ConfigError(format!("Failed to parse config: {e}")))?;
        config.normalize_pools();
        Ok(config)
    }

    /// The configuration used when no config file exists.
    pub fn builtin() -> Self {
        let mut config = Self::default();
        config.normalize_pools();
        config
    }

    fn normalize_pools(&mut self) {
        if self.dns.pools.is_empty() && !self.dns.upstream_servers.is_empty() {
            self.dns.pools.push(UpstreamPool {
                name: "default".to_string(),
                strategy: self.dns.default_strategy,
                priority: 1,
                servers: self.dns.upstream_servers.clone(),
                weight: None,
            });
        }
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.server.dns_port == 0 {
            return Err(DomainError::ConfigError("DNS port cannot be 0".to_string()));
        }

        self.validate_non_zero()?;

        if let Some(server) = &self.dns.local_dns_server {
            if server.parse::<SocketAddr>().is_err() {
                return Err(DomainError::ConfigError(format!(
                    "dns.local_dns_server '{server}' must be an IP:port literal such as 192.168.1.1:53"
                )));
            }
        }

        if self.dns.pools.is_empty() && self.dns.upstream_servers.is_empty() {
            return Err(DomainError::ConfigError(
                "No upstream servers configured".to_string(),
            ));
        }

        for pool in &self.dns.pools {
            if pool.servers.is_empty() {
                return Err(DomainError::ConfigError(format!(
                    "Pool '{}' has no servers",
                    pool.name
                )));
            }
        }

        Ok(())
    }

    /// Rejects values the runtime cannot honour: a zero interval, timeout,
    /// TTL or capacity panics (zero-period timer, zero-capacity channel or
    /// pool), spins, or silently disables the component it sizes.
    fn validate_non_zero(&self) -> Result<(), DomainError> {
        let dns = &self.dns;
        let database = &self.database;
        let auth = &self.auth;
        let zero_checks = [
            ("dns.query_timeout", dns.query_timeout == 0),
            ("dns.cache_max_entries", dns.cache_max_entries == 0),
            (
                "dns.cache_compaction_interval",
                dns.cache_compaction_interval == 0,
            ),
            (
                "dns.cache_eviction_sample_size",
                dns.cache_eviction_sample_size == 0,
            ),
            ("dns.health_check.interval", dns.health_check.interval == 0),
            ("dns.health_check.timeout", dns.health_check.timeout == 0),
            (
                "dns.rate_limit.queries_per_second",
                dns.rate_limit.queries_per_second == 0,
            ),
            ("dns.rate_limit.burst_size", dns.rate_limit.burst_size == 0),
            (
                "dns.rate_limit.stale_entry_ttl_secs",
                dns.rate_limit.stale_entry_ttl_secs == 0,
            ),
            (
                "dns.tunneling_detection.stale_entry_ttl_secs",
                dns.tunneling_detection.stale_entry_ttl_secs == 0,
            ),
            (
                "dns.nxdomain_hijack.probe_interval_secs",
                dns.nxdomain_hijack.probe_interval_secs == 0,
            ),
            (
                "dns.nxdomain_hijack.probe_timeout_ms",
                dns.nxdomain_hijack.probe_timeout_ms == 0,
            ),
            (
                "dns.nxdomain_hijack.hijack_ip_ttl_secs",
                dns.nxdomain_hijack.hijack_ip_ttl_secs == 0,
            ),
            (
                "dns.response_ip_filter.refresh_interval_secs",
                dns.response_ip_filter.refresh_interval_secs == 0,
            ),
            (
                "dns.response_ip_filter.ip_ttl_secs",
                dns.response_ip_filter.ip_ttl_secs == 0,
            ),
            (
                "dns.dga_detection.stale_entry_ttl_secs",
                dns.dga_detection.stale_entry_ttl_secs == 0,
            ),
            (
                "database.queries_log_stored",
                database.queries_log_stored == 0,
            ),
            (
                "database.query_log_channel_capacity",
                database.query_log_channel_capacity == 0,
            ),
            (
                "database.query_log_max_batch_size",
                database.query_log_max_batch_size == 0,
            ),
            (
                "database.query_log_flush_interval_ms",
                database.query_log_flush_interval_ms == 0,
            ),
            (
                "database.client_channel_capacity",
                database.client_channel_capacity == 0,
            ),
            (
                "database.write_pool_max_connections",
                database.write_pool_max_connections == 0,
            ),
            (
                "database.query_log_pool_max_connections",
                database.query_log_pool_max_connections == 0,
            ),
            (
                "database.read_pool_max_connections",
                database.read_pool_max_connections == 0,
            ),
            (
                "database.write_busy_timeout_secs",
                database.write_busy_timeout_secs == 0,
            ),
            (
                "database.read_acquire_timeout_secs",
                database.read_acquire_timeout_secs == 0,
            ),
            (
                "database.wal_checkpoint_interval_secs",
                database.wal_checkpoint_interval_secs == 0,
            ),
            ("auth.session_ttl_hours", auth.session_ttl_hours == 0),
            ("auth.remember_me_days", auth.remember_me_days == 0),
            (
                "auth.login_rate_limit_window_secs",
                auth.login_rate_limit_window_secs == 0,
            ),
            (
                "auth.mfa_challenge_ttl_secs",
                auth.mfa_challenge_ttl_secs <= 0,
            ),
        ];
        if let Some((field, _)) = zero_checks.into_iter().find(|&(_, is_zero)| is_zero) {
            return Err(DomainError::ConfigError(format!(
                "{field} must be greater than 0"
            )));
        }

        // DashMap asserts a power-of-two shard count above 1.
        for (field, shards) in [
            ("dns.cache_shard_amount", dns.cache_shard_amount),
            ("dns.cache_inflight_shards", dns.cache_inflight_shards),
        ] {
            if shards < 2 || !shards.is_power_of_two() {
                return Err(DomainError::ConfigError(format!(
                    "{field} must be a power of two of at least 2, got {shards}"
                )));
            }
        }

        // Every cached TTL is clamped to this range, which must not be inverted.
        if dns.cache_min_ttl > dns.cache_max_ttl {
            return Err(DomainError::ConfigError(format!(
                "dns.cache_min_ttl ({}) must not exceed dns.cache_max_ttl ({})",
                dns.cache_min_ttl, dns.cache_max_ttl
            )));
        }

        Ok(())
    }
}
