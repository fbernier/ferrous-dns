use ferrous_dns_domain::{Config, LocalDnsRecord, LocalRecordType};

fn record(hostname: &str, domain: Option<&str>) -> LocalDnsRecord {
    LocalDnsRecord {
        hostname: hostname.to_string(),
        domain: domain.map(str::to_string),
        ip: "192.168.1.10".parse().unwrap(),
        record_type: LocalRecordType::A,
        ttl: None,
    }
}

const MINIMAL_TOML: &str = "[server]\ndns_port = 53\nweb_port = 8080\nbind_address = \"0.0.0.0\"\n\
     [dns]\nupstream_servers = [\"1.1.1.1:53\"]\n[blocking]\nenabled = true\n\
     [logging]\nlevel = \"info\"\n[database]\n";

fn load_records(entries: &str) -> Vec<LocalDnsRecord> {
    Config::from_toml_str(&format!("{MINIMAL_TOML}{entries}"))
        .expect("the config must load")
        .dns
        .local_records
}

#[test]
fn test_record_type_parses_case_insensitively_and_writes_canonically() {
    let records = load_records(
        "[[dns.local_records]]\nhostname = \"nas\"\nip = \"fd00::1\"\nrecord_type = \"aaaa\"\n",
    );

    assert_eq!(records[0].record_type, LocalRecordType::AAAA);
    let written = toml::to_string(&records[0]).unwrap();
    assert!(written.contains("record_type = \"AAAA\""), "{written}");
}

/// Older builds saved these unchecked; one of them must not stop the server from starting.
#[test]
fn test_a_record_that_cannot_be_served_is_dropped_and_the_rest_load() {
    for invalid in [
        "ip = \"fd00::1\"\nrecord_type = \"A\"",
        "ip = \"10.0.0.1\"\nrecord_type = \"AAAA\"",
        "ip = \"nas.lan\"\nrecord_type = \"A\"",
        "ip = \"10.0.0.1\"\nrecord_type = \"CNAME\"",
    ] {
        let records = load_records(&format!(
            "[[dns.local_records]]\nhostname = \"bad\"\n{invalid}\n\
             [[dns.local_records]]\nhostname = \"nas\"\nip = \"192.168.1.10\"\nrecord_type = \"A\"\n"
        ));

        assert_eq!(records, [record("nas", None)], "{invalid}");
    }
}

#[test]
fn test_has_fqdn_matches_the_composed_name_case_insensitively() {
    let nas = record("nas", Some("home.lan"));

    assert!(nas.has_fqdn("NAS.Home.lan", None));
    assert!(record("nas.home", Some("lan")).has_fqdn("nas.home.lan", None));
    assert!(record("nas", None).has_fqdn("nas.lan", Some("lan")));
    assert!(!nas.has_fqdn("nas.home.la", None));
    assert!(!nas.has_fqdn("nas", None));
    assert!(!nas.has_fqdn("nasxhome.lan", None));
}

#[test]
fn test_validate_hostname_accepts_plain_names() {
    assert!(LocalDnsRecord::validate_hostname("nas").is_ok());
    assert!(LocalDnsRecord::validate_hostname("www-1").is_ok());
    assert!(LocalDnsRecord::validate_hostname("my_host").is_ok());
    assert!(LocalDnsRecord::validate_hostname("app.internal").is_ok());
}

#[test]
fn test_validate_hostname_accepts_leftmost_wildcard() {
    assert!(LocalDnsRecord::validate_hostname("*").is_ok());
    assert!(LocalDnsRecord::validate_hostname("*.dev").is_ok());
}

#[test]
fn test_validate_hostname_rejects_misplaced_wildcard() {
    assert!(LocalDnsRecord::validate_hostname("a.*.b").is_err());
    assert!(LocalDnsRecord::validate_hostname("*x").is_err());
    assert!(LocalDnsRecord::validate_hostname("dev.*").is_err());
}

#[test]
fn test_validate_hostname_rejects_empty() {
    assert!(LocalDnsRecord::validate_hostname("").is_err());
}

#[test]
fn test_validate_hostname_rejects_empty_label() {
    assert!(LocalDnsRecord::validate_hostname("foo..bar").is_err());
    assert!(LocalDnsRecord::validate_hostname(".foo").is_err());
    assert!(LocalDnsRecord::validate_hostname("foo.").is_err());
}

#[test]
fn test_validate_hostname_rejects_oversized_label() {
    let label = "a".repeat(64);
    assert!(LocalDnsRecord::validate_hostname(&label).is_err());
}

#[test]
fn test_validate_hostname_rejects_invalid_characters() {
    assert!(LocalDnsRecord::validate_hostname("my host").is_err());
    assert!(LocalDnsRecord::validate_hostname("host!").is_err());
    assert!(LocalDnsRecord::validate_hostname("héllo").is_err());
}

#[test]
fn test_validate_domain_rejects_wildcard() {
    assert!(LocalDnsRecord::validate_domain("example.com").is_ok());
    assert!(LocalDnsRecord::validate_domain("*.example.com").is_err());
    assert!(LocalDnsRecord::validate_domain("").is_err());
}

#[test]
fn test_is_wildcard_follows_hostname() {
    assert!(record("*", Some("home.lan")).is_wildcard());
    assert!(record("*.dev", Some("home.lan")).is_wildcard());
    assert!(!record("nas", Some("home.lan")).is_wildcard());
}

#[test]
fn test_wildcard_suffix_strips_the_star_label() {
    assert_eq!(
        record("*", Some("home.lan")).wildcard_suffix(None),
        Some("home.lan".to_string())
    );
    assert_eq!(
        record("*.dev", Some("home.lan")).wildcard_suffix(None),
        Some("dev.home.lan".to_string())
    );
}

#[test]
fn test_wildcard_suffix_uses_the_default_domain() {
    assert_eq!(
        record("*", None).wildcard_suffix(Some("lan")),
        Some("lan".to_string())
    );
}

#[test]
fn test_wildcard_suffix_is_lowercased() {
    assert_eq!(
        record("*", Some("HOME.LAN")).wildcard_suffix(None),
        Some("home.lan".to_string())
    );
}

#[test]
fn test_wildcard_suffix_none_without_a_domain_to_anchor_it() {
    assert_eq!(record("*", None).wildcard_suffix(None), None);
}

#[test]
fn test_wildcard_suffix_none_for_an_exact_record() {
    assert_eq!(record("nas", Some("home.lan")).wildcard_suffix(None), None);
}
