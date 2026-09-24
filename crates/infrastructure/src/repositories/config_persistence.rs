use ferrous_dns_application::ports::ConfigFilePersistence;
use ferrous_dns_domain::{config::errors::ConfigError, Config};

pub struct TomlConfigFilePersistence;

impl ConfigFilePersistence for TomlConfigFilePersistence {
    fn save_config_to_file(&self, config: &Config, path: &str) -> Result<(), String> {
        save_config_to_file(config, path).map_err(|e| e.to_string())
    }
}

/// Updates an existing value preserving its inline comment (suffix decoration),
/// or inserts a new key if absent.
fn set_val(table: &mut toml_edit::Table, key: &str, new_val: impl Into<toml_edit::Value>) {
    let new_val = new_val.into();
    match table.get_mut(key) {
        Some(item @ toml_edit::Item::Value(_)) => {
            let suffix = item.as_value().and_then(|v| v.decor().suffix()).cloned();
            *item = toml_edit::Item::Value(new_val);
            if let (Some(s), Some(v)) = (suffix, item.as_value_mut()) {
                v.decor_mut().set_suffix(s);
            }
        }
        Some(item) => *item = toml_edit::Item::Value(new_val),
        None => {
            table.insert(key, toml_edit::Item::Value(new_val));
        }
    }
}

fn str_array(values: &[String]) -> toml_edit::Value {
    let mut arr = toml_edit::Array::new();
    for v in values {
        arr.push(v.as_str());
    }
    toml_edit::Value::Array(arr)
}

/// Gets a mutable reference to a top-level table, creating it if absent
/// (handles commented-out sections that `toml_edit` doesn't see).
fn ensure_table<'a>(
    doc: &'a mut toml_edit::DocumentMut,
    key: &str,
) -> Result<&'a mut toml_edit::Table, ConfigError> {
    if doc.get(key).is_none() {
        doc.insert(key, toml_edit::Item::Table(toml_edit::Table::new()));
    }
    doc.get_mut(key)
        .and_then(|item| item.as_table_mut())
        .ok_or_else(|| ConfigError::Parse(format!("Failed to ensure table '{key}'")))
}

/// Gets a mutable reference to a sub-table inside a parent table,
/// creating it if absent.
fn ensure_subtable<'a>(
    parent: &'a mut toml_edit::Table,
    key: &str,
) -> Result<&'a mut toml_edit::Table, ConfigError> {
    if parent.get(key).is_none() {
        parent.insert(key, toml_edit::Item::Table(toml_edit::Table::new()));
    }
    parent
        .get_mut(key)
        .and_then(|item| item.as_table_mut())
        .ok_or_else(|| ConfigError::Parse(format!("Failed to ensure subtable '{key}'")))
}

/// Reads and parses the file at `path`, applies `edit`, and writes the document back,
/// so every key and comment the edit doesn't touch survives the save.
fn edit_config_file(
    path: &str,
    edit: impl FnOnce(&mut toml_edit::DocumentMut) -> Result<(), ConfigError>,
) -> Result<(), ConfigError> {
    let existing = std::fs::read_to_string(path)
        .map_err(|e| ConfigError::FileRead(path.to_string(), e.to_string()))?;

    let mut doc = existing
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| ConfigError::Parse(format!("Failed to parse config file: {}", e)))?;

    edit(&mut doc)?;

    std::fs::write(path, doc.to_string())
        .map_err(|e| ConfigError::FileWrite(path.to_string(), e.to_string()))
}

pub fn save_config_to_file(config: &Config, path: &str) -> Result<(), ConfigError> {
    edit_config_file(path, |doc| write_config(doc, config))
}

fn write_config(doc: &mut toml_edit::DocumentMut, config: &Config) -> Result<(), ConfigError> {
    {
        let t = ensure_table(doc, "server")?;
        set_val(t, "dns_port", config.server.dns_port as i64);
        set_val(t, "web_port", config.server.web_port as i64);
        set_val(t, "bind_address", config.server.bind_address.as_str());
        t.remove("api_key");
        set_val(t, "pihole_compat", config.server.pihole_compat);
    }

    {
        let server = ensure_table(doc, "server")?;
        let wt = ensure_subtable(server, "web_tls")?;
        set_val(wt, "enabled", config.server.web_tls.enabled);
        set_val(
            wt,
            "tls_cert_path",
            config.server.web_tls.tls_cert_path.as_str(),
        );
        set_val(
            wt,
            "tls_key_path",
            config.server.web_tls.tls_key_path.as_str(),
        );
    }

    {
        let t = ensure_table(doc, "dns")?;
        set_val(
            t,
            "upstream_servers",
            str_array(&config.dns.upstream_servers),
        );
        set_val(t, "query_timeout", config.dns.query_timeout as i64);
        set_val(t, "cache_enabled", config.dns.cache_enabled);
        set_val(t, "cache_ttl", config.dns.cache_ttl as i64);
        set_val(t, "cache_min_ttl", config.dns.cache_min_ttl as i64);
        set_val(t, "cache_max_ttl", config.dns.cache_max_ttl as i64);
        set_val(
            t,
            "dnssec_mode",
            config.dns.effective_dnssec_mode().to_string(),
        );
        set_val(
            t,
            "default_strategy",
            config.dns.default_strategy.to_string(),
        );
        set_val(t, "cache_max_entries", config.dns.cache_max_entries as i64);
        set_val(
            t,
            "cache_eviction_strategy",
            config.dns.cache_eviction_strategy.as_str(),
        );
        set_val(
            t,
            "cache_optimistic_refresh",
            config.dns.cache_optimistic_refresh,
        );
        set_val(t, "cache_min_hit_rate", config.dns.cache_min_hit_rate);
        set_val(
            t,
            "cache_min_frequency",
            config.dns.cache_min_frequency as i64,
        );
        set_val(t, "cache_min_lfuk_score", config.dns.cache_min_lfuk_score);
        set_val(
            t,
            "cache_refresh_threshold",
            config.dns.cache_refresh_threshold,
        );
        // Retired key: drop it so files written by older versions stop carrying it.
        t.remove("cache_max_refresh_per_sec");
        set_val(
            t,
            "cache_lfuk_history_size",
            config.dns.cache_lfuk_history_size as i64,
        );
        set_val(
            t,
            "cache_batch_eviction_percentage",
            config.dns.cache_batch_eviction_percentage,
        );
        set_val(
            t,
            "cache_compaction_interval",
            config.dns.cache_compaction_interval as i64,
        );
        set_val(
            t,
            "cache_adaptive_thresholds",
            config.dns.cache_adaptive_thresholds,
        );
        set_val(
            t,
            "cache_access_window_secs",
            config.dns.cache_access_window_secs as i64,
        );
        set_val(t, "block_private_ptr", config.dns.block_private_ptr);
        set_val(t, "block_non_fqdn", config.dns.block_non_fqdn);
        set_val(t, "mdns_enabled", config.dns.mdns_enabled);
        match &config.dns.local_domain {
            Some(domain) => set_val(t, "local_domain", domain.as_str()),
            None => {
                t.remove("local_domain");
            }
        }
        match &config.dns.local_dns_server {
            Some(server) => set_val(t, "local_dns_server", server.as_str()),
            None => {
                t.remove("local_dns_server");
            }
        }
    }

    {
        let dns = ensure_table(doc, "dns")?;
        dns.remove("pools");
        if !config.dns.pools.is_empty() {
            let mut aot = toml_edit::ArrayOfTables::new();
            for pool in &config.dns.pools {
                let mut table = toml_edit::Table::new();
                table.insert("name", toml_edit::value(pool.name.as_str()));
                table.insert("strategy", toml_edit::value(pool.strategy.to_string()));
                table.insert("priority", toml_edit::value(pool.priority as i64));
                table.insert("servers", toml_edit::Item::Value(str_array(&pool.servers)));
                if let Some(weight) = pool.weight {
                    table.insert("weight", toml_edit::value(weight as i64));
                }
                aot.push(table);
            }
            dns.insert("pools", toml_edit::Item::ArrayOfTables(aot));
        }
    }

    {
        let dns = ensure_table(doc, "dns")?;
        let hc = ensure_subtable(dns, "health_check")?;
        set_val(hc, "interval", config.dns.health_check.interval as i64);
        set_val(hc, "timeout", config.dns.health_check.timeout as i64);
        set_val(
            hc,
            "failure_threshold",
            config.dns.health_check.failure_threshold as i64,
        );
        set_val(
            hc,
            "success_threshold",
            config.dns.health_check.success_threshold as i64,
        );
    }

    {
        let dns = ensure_table(doc, "dns")?;
        let rl = ensure_subtable(dns, "rate_limit")?;
        set_val(rl, "enabled", config.dns.rate_limit.enabled);
        set_val(
            rl,
            "queries_per_second",
            config.dns.rate_limit.queries_per_second as i64,
        );
        set_val(rl, "burst_size", config.dns.rate_limit.burst_size as i64);
        set_val(
            rl,
            "ipv4_prefix_len",
            config.dns.rate_limit.ipv4_prefix_len as i64,
        );
        set_val(
            rl,
            "ipv6_prefix_len",
            config.dns.rate_limit.ipv6_prefix_len as i64,
        );
        set_val(
            rl,
            "nxdomain_per_second",
            config.dns.rate_limit.nxdomain_per_second as i64,
        );
        set_val(rl, "slip_ratio", config.dns.rate_limit.slip_ratio as i64);
        set_val(rl, "dry_run", config.dns.rate_limit.dry_run);
        set_val(
            rl,
            "stale_entry_ttl_secs",
            config.dns.rate_limit.stale_entry_ttl_secs as i64,
        );
        set_val(
            rl,
            "tcp_max_connections_per_ip",
            config.dns.rate_limit.tcp_max_connections_per_ip as i64,
        );
        set_val(
            rl,
            "dot_max_connections_per_ip",
            config.dns.rate_limit.dot_max_connections_per_ip as i64,
        );
        set_val(
            rl,
            "doq_max_connections_per_ip",
            config.dns.rate_limit.doq_max_connections_per_ip as i64,
        );
        set_val(rl, "whitelist", str_array(&config.dns.rate_limit.whitelist));
    }

    {
        let t = ensure_table(doc, "blocking")?;
        set_val(t, "enabled", config.blocking.enabled);
        set_val(
            t,
            "custom_blocked",
            str_array(&config.blocking.custom_blocked),
        );
        set_val(t, "whitelist", str_array(&config.blocking.whitelist));
        set_val(t, "block_mode", config.blocking.block_mode.as_str());
        set_val(t, "block_ttl", config.blocking.block_ttl as i64);
        // Optional custom sinkhole targets: write when set, drop the key when
        // cleared so the file reflects "no custom target" (falls back to null).
        match config.blocking.sinkhole_ipv4 {
            Some(addr) => set_val(t, "sinkhole_ipv4", addr.to_string()),
            None => {
                t.remove("sinkhole_ipv4");
            }
        }
        match config.blocking.sinkhole_ipv6 {
            Some(addr) => set_val(t, "sinkhole_ipv6", addr.to_string()),
            None => {
                t.remove("sinkhole_ipv6");
            }
        }
    }

    {
        let t = ensure_table(doc, "dns64")?;
        set_val(t, "enabled", config.dns64.enabled);
        set_val(t, "prefix", config.dns64.prefix.as_str());
    }

    {
        let t = ensure_table(doc, "logging")?;
        set_val(t, "level", config.logging.level.as_str());
    }

    {
        let t = ensure_table(doc, "database")?;
        set_val(t, "path", config.database.path.as_str());
        set_val(t, "log_queries", config.database.log_queries);
        set_val(
            t,
            "queries_log_stored",
            config.database.queries_log_stored as i64,
        );
        set_val(
            t,
            "client_tracking_interval",
            config.database.client_tracking_interval as i64,
        );
        set_val(
            t,
            "query_log_channel_capacity",
            config.database.query_log_channel_capacity as i64,
        );
        set_val(
            t,
            "query_log_max_batch_size",
            config.database.query_log_max_batch_size as i64,
        );
        set_val(
            t,
            "query_log_flush_interval_ms",
            config.database.query_log_flush_interval_ms as i64,
        );
        set_val(
            t,
            "query_log_sample_rate",
            config.database.query_log_sample_rate as i64,
        );
        set_val(
            t,
            "client_channel_capacity",
            config.database.client_channel_capacity as i64,
        );
        set_val(
            t,
            "write_pool_max_connections",
            config.database.write_pool_max_connections as i64,
        );
        set_val(
            t,
            "read_pool_max_connections",
            config.database.read_pool_max_connections as i64,
        );
        set_val(
            t,
            "write_busy_timeout_secs",
            config.database.write_busy_timeout_secs as i64,
        );
        set_val(
            t,
            "read_busy_timeout_secs",
            config.database.read_busy_timeout_secs as i64,
        );
        set_val(
            t,
            "read_acquire_timeout_secs",
            config.database.read_acquire_timeout_secs as i64,
        );
        set_val(
            t,
            "wal_autocheckpoint",
            config.database.wal_autocheckpoint as i64,
        );
    }

    {
        let t = ensure_table(doc, "auth")?;
        set_val(t, "enabled", config.auth.enabled);
        set_val(t, "session_ttl_hours", config.auth.session_ttl_hours as i64);
        set_val(t, "remember_me_days", config.auth.remember_me_days as i64);
        set_val(
            t,
            "login_rate_limit_attempts",
            config.auth.login_rate_limit_attempts as i64,
        );
        set_val(
            t,
            "login_rate_limit_window_secs",
            config.auth.login_rate_limit_window_secs as i64,
        );
        set_val(t, "totp_issuer", config.auth.totp_issuer.as_str());
        set_val(
            t,
            "mfa_challenge_ttl_secs",
            config.auth.mfa_challenge_ttl_secs,
        );
    }

    {
        let auth = ensure_table(doc, "auth")?;
        let admin = ensure_subtable(auth, "admin")?;
        set_val(admin, "username", config.auth.admin.username.as_str());
        match &config.auth.admin.password_hash {
            Some(hash) => set_val(admin, "password_hash", hash.as_str()),
            None => {
                admin.remove("password_hash");
            }
        }
    }

    {
        let auth = ensure_table(doc, "auth")?;
        let webauthn = ensure_subtable(auth, "webauthn")?;
        set_val(webauthn, "rp_id", config.auth.webauthn.rp_id.as_str());
        set_val(
            webauthn,
            "rp_origin",
            config.auth.webauthn.rp_origin.as_str(),
        );
    }

    Ok(())
}

pub fn save_local_records_to_file(config: &Config, path: &str) -> Result<(), ConfigError> {
    edit_config_file(path, |doc| write_local_records(doc, config))
}

fn write_local_records(
    doc: &mut toml_edit::DocumentMut,
    config: &Config,
) -> Result<(), ConfigError> {
    let dns = ensure_table(doc, "dns")?;
    if config.dns.local_records.is_empty() {
        dns.remove("local_records");
    } else {
        let mut aot = toml_edit::ArrayOfTables::new();
        for record in &config.dns.local_records {
            let mut table = toml_edit::Table::new();
            table.insert("hostname", toml_edit::value(record.hostname.as_str()));
            if let Some(ref domain) = record.domain {
                table.insert("domain", toml_edit::value(domain.as_str()));
            }
            table.insert("ip", toml_edit::value(record.ip.to_string()));
            table.insert("record_type", toml_edit::value(record.record_type.as_str()));
            if let Some(ttl) = record.ttl {
                table.insert("ttl", toml_edit::value(ttl as i64));
            }
            aot.push(table);
        }
        dns.insert("local_records", toml_edit::Item::ArrayOfTables(aot));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_val_preserves_inline_comment() {
        let input = r#"
[server]
dns_port = 53  # UDP port
"#;
        let mut doc = input.parse::<toml_edit::DocumentMut>().unwrap();
        let server = doc.get_mut("server").unwrap().as_table_mut().unwrap();

        set_val(server, "dns_port", 5353i64);

        let output = doc.to_string();
        assert!(output.contains("5353"));
        assert!(output.contains("# UDP port"));
    }

    #[test]
    fn test_set_val_inserts_missing_key() {
        let input = r#"
[server]
dns_port = 53
"#;
        let mut doc = input.parse::<toml_edit::DocumentMut>().unwrap();
        let server = doc.get_mut("server").unwrap().as_table_mut().unwrap();

        set_val(server, "new_key", "new_value");

        let output = doc.to_string();
        assert!(output.contains("new_key = \"new_value\""));
    }

    #[test]
    fn test_ensure_table_creates_missing_section() {
        let input = "# empty config\n";
        let mut doc = input.parse::<toml_edit::DocumentMut>().unwrap();

        let table = ensure_table(&mut doc, "new_section").unwrap();
        table.insert("key", toml_edit::value("val"));

        let output = doc.to_string();
        assert!(output.contains("[new_section]"));
        assert!(output.contains("key = \"val\""));
    }

    #[test]
    fn test_ensure_subtable_creates_nested_section() {
        let input = r#"
[dns]
cache_enabled = true
"#;
        let mut doc = input.parse::<toml_edit::DocumentMut>().unwrap();
        let dns = ensure_table(&mut doc, "dns").unwrap();
        let sub = ensure_subtable(dns, "nested").unwrap();
        sub.insert("value", toml_edit::value(42i64));

        let output = doc.to_string();
        assert!(output.contains("[dns.nested]") && output.contains("value = 42"));
    }
}
