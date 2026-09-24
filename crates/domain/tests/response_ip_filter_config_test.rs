use ferrous_dns_domain::{ResponseIpFilterAction, ResponseIpFilterConfig};

#[test]
fn deserializes_empty_toml_with_defaults() {
    let config: ResponseIpFilterConfig = toml::from_str("").unwrap();
    assert!(!config.enabled);
    assert_eq!(config.refresh_interval_secs, 86400);
    assert_eq!(config.ip_ttl_secs, 604800);
}

#[test]
fn deserializes_partial_toml_preserves_defaults() {
    let toml = r#"
        enabled = true
        action = "alert"
    "#;
    let config: ResponseIpFilterConfig = toml::from_str(toml).unwrap();
    assert!(config.enabled);
    assert_eq!(config.action, ResponseIpFilterAction::Alert);
    assert_eq!(config.refresh_interval_secs, 86400);
    assert_eq!(config.ip_ttl_secs, 604800);
}

#[test]
fn deserializes_full_config() {
    let toml = r#"
        enabled = true
        action = "alert"
        ip_list_urls = ["https://example.com/ips.txt", "https://other.com/feed.txt"]
        refresh_interval_secs = 3600
        ip_ttl_secs = 86400
    "#;
    let config: ResponseIpFilterConfig = toml::from_str(toml).unwrap();
    assert!(config.enabled);
    assert_eq!(config.action, ResponseIpFilterAction::Alert);
    assert_eq!(config.ip_list_urls.len(), 2);
    assert_eq!(config.refresh_interval_secs, 3600);
    assert_eq!(config.ip_ttl_secs, 86400);
}

#[test]
fn rejects_invalid_action() {
    let toml = r#"action = "drop""#;
    assert!(toml::from_str::<ResponseIpFilterConfig>(toml).is_err());
}
