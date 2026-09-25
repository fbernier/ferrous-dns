use ferrous_dns_domain::BlocklistSource;

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
