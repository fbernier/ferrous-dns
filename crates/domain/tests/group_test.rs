use ferrous_dns_domain::Group;
use std::sync::Arc;

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

#[test]
fn test_validate_comment_valid() {
    let valid_comment = Some(Arc::from("Valid comment"));
    assert!(Group::validate_comment(&valid_comment).is_ok());
}

#[test]
fn test_validate_comment_none() {
    assert!(Group::validate_comment(&None).is_ok());
}

#[test]
fn test_validate_comment_too_long() {
    let long_comment = Some(Arc::from("a".repeat(501).as_str()));
    assert!(Group::validate_comment(&long_comment).is_err());
}
