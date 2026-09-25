use ferrous_dns_domain::Group;

#[test]
fn test_validate_name_valid() {
    assert!(Group::validate_name("Valid Name").is_ok());
    assert!(Group::validate_name("Test-Group_123").is_ok());
    assert!(Group::validate_name("A").is_ok());
}

#[test]
fn test_validate_name_empty() {
    assert!(Group::validate_name("").is_err());
}

#[test]
fn test_validate_name_too_long() {
    let long_name = "a".repeat(101);
    assert!(Group::validate_name(&long_name).is_err());
}

#[test]
fn test_validate_name_invalid_characters() {
    assert!(Group::validate_name("Invalid@Name").is_err());
    assert!(Group::validate_name("Name!With#Special$").is_err());
}
