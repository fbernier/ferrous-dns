use ferrous_dns_domain::value_objects::validators::{
    validate_comment, validate_source_name, validate_url,
};
use ferrous_dns_domain::{BlocklistSource, Group, ManagedDomain, RegexFilter, ScheduleProfile};

#[test]
fn test_validate_url_accepts_http_and_https() {
    assert!(validate_url(Some("https://example.com/blocklist.txt")).is_ok());
    assert!(validate_url(Some("http://example.com/blocklist.txt")).is_ok());
    assert!(validate_url(None).is_ok());
}

#[test]
fn test_validate_url_rejects_other_schemes() {
    assert!(validate_url(Some("ftp://example.com/list.txt")).is_err());
    assert!(validate_url(Some("example.com/list.txt")).is_err());
}

#[test]
fn test_validate_url_length_boundary() {
    let prefix = "https://x.com/";
    let at_limit = format!("{prefix}{}", "a".repeat(2048 - prefix.len()));
    assert!(validate_url(Some(&at_limit)).is_ok());
    let over = format!("{at_limit}a");
    assert!(validate_url(Some(&over)).is_err());
}

#[test]
fn test_validate_comment_length_boundary() {
    assert!(validate_comment(None).is_ok());
    assert!(validate_comment(Some(&"a".repeat(500))).is_ok());
    assert!(validate_comment(Some(&"a".repeat(501))).is_err());
}

#[test]
fn test_length_limits_count_characters_not_bytes() {
    // 'é' is two bytes and '日' three: at-limit input must pass although its
    // byte length exceeds the limit.
    assert!(validate_comment(Some(&"é".repeat(500))).is_ok());
    assert!(validate_comment(Some(&"é".repeat(501))).is_err());
    assert!(validate_source_name(&"日".repeat(200), "Blocklist source").is_ok());
    assert!(validate_source_name(&"日".repeat(201), "Blocklist source").is_err());
    assert!(BlocklistSource::validate_name(&"é".repeat(200)).is_ok());
    assert!(Group::validate_name(&"é".repeat(100)).is_ok());
    assert!(Group::validate_name(&"é".repeat(101)).is_err());
    assert!(ManagedDomain::validate_name(&"日".repeat(200)).is_ok());
    assert!(RegexFilter::validate_name(&"日".repeat(200)).is_ok());
    assert!(RegexFilter::validate_pattern(&"é".repeat(1000)).is_ok());
    assert!(RegexFilter::validate_pattern(&"é".repeat(1001)).is_err());
    assert!(ScheduleProfile::validate_name(&"é".repeat(100)).is_ok());
    assert!(ScheduleProfile::validate_name(&"é".repeat(101)).is_err());

    let url = format!(
        "https://x.com/{}",
        "é".repeat(2048 - "https://x.com/".len())
    );
    assert!(validate_url(Some(&url)).is_ok());
}
