use ferrous_dns_domain::BlocklistSource;
use std::sync::Arc;

#[test]
fn test_validate_name_valid() {
    assert!(BlocklistSource::validate_name("Valid Name").is_ok());
    assert!(BlocklistSource::validate_name("A").is_ok());
    assert!(BlocklistSource::validate_name("AdGuard DNS Blocklist").is_ok());
    assert!(BlocklistSource::validate_name("list-1_v2.txt").is_ok());
}

#[test]
fn test_validate_name_empty() {
    let result = BlocklistSource::validate_name("");
    assert!(result.is_err());
}

#[test]
fn test_validate_name_too_long() {
    let long_name = "a".repeat(201);
    let result = BlocklistSource::validate_name(&long_name);
    assert!(result.is_err());
}

#[test]
fn test_validate_name_exactly_200_chars() {
    let name = "a".repeat(200);
    assert!(BlocklistSource::validate_name(&name).is_ok());
}

#[test]
fn test_validate_url_valid_https() {
    let url = Some(Arc::from("https://example.com/blocklist.txt"));
    assert!(BlocklistSource::validate_url(&url).is_ok());
}

#[test]
fn test_validate_url_valid_http() {
    let url = Some(Arc::from("http://example.com/blocklist.txt"));
    assert!(BlocklistSource::validate_url(&url).is_ok());
}

#[test]
fn test_validate_url_invalid_scheme_ftp() {
    let url = Some(Arc::from("ftp://example.com/list.txt"));
    let result = BlocklistSource::validate_url(&url);
    assert!(result.is_err());
}

#[test]
fn test_validate_url_no_scheme() {
    let url = Some(Arc::from("example.com/list.txt"));
    let result = BlocklistSource::validate_url(&url);
    assert!(result.is_err());
}

#[test]
fn test_validate_url_none() {
    assert!(BlocklistSource::validate_url(&None).is_ok());
}

#[test]
fn test_validate_url_too_long() {
    let long_url = format!("https://example.com/{}", "a".repeat(2048));
    let url = Some(Arc::from(long_url.as_str()));
    let result = BlocklistSource::validate_url(&url);
    assert!(result.is_err());
}

#[test]
fn test_validate_url_exactly_2048_chars() {
    let prefix = "https://x.com/";
    let path = "a".repeat(2048 - prefix.len());
    let url_str = format!("{}{}", prefix, path);
    assert_eq!(url_str.len(), 2048);
    let url = Some(Arc::from(url_str.as_str()));
    assert!(BlocklistSource::validate_url(&url).is_ok());
}

#[test]
fn test_validate_comment_valid() {
    let comment = Some(Arc::from("A valid comment"));
    assert!(BlocklistSource::validate_comment(&comment).is_ok());
}

#[test]
fn test_validate_comment_none() {
    assert!(BlocklistSource::validate_comment(&None).is_ok());
}

#[test]
fn test_validate_comment_too_long() {
    let long_comment = Some(Arc::from("a".repeat(501).as_str()));
    let result = BlocklistSource::validate_comment(&long_comment);
    assert!(result.is_err());
}

#[test]
fn test_validate_comment_exactly_500_chars() {
    let comment = Some(Arc::from("a".repeat(500).as_str()));
    assert!(BlocklistSource::validate_comment(&comment).is_ok());
}
