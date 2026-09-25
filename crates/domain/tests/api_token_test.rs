use ferrous_dns_domain::ApiToken;

#[test]
fn validate_name_accepts_alphanumeric() {
    assert!(ApiToken::validate_name("my-token").is_ok());
    assert!(ApiToken::validate_name("Token 123").is_ok());
    assert!(ApiToken::validate_name("under_score").is_ok());
    assert!(ApiToken::validate_name("A").is_ok());
}

#[test]
fn validate_name_rejects_empty() {
    assert!(ApiToken::validate_name("").is_err());
}

#[test]
fn validate_name_rejects_too_long() {
    let long = "a".repeat(101);
    assert!(ApiToken::validate_name(&long).is_err());
}

#[test]
fn validate_name_accepts_exactly_100_chars() {
    let name = "a".repeat(100);
    assert!(ApiToken::validate_name(&name).is_ok());
}

#[test]
fn validate_name_rejects_special_characters() {
    assert!(ApiToken::validate_name("token!").is_err());
    assert!(ApiToken::validate_name("token@home").is_err());
    assert!(ApiToken::validate_name("token#1").is_err());
    assert!(ApiToken::validate_name("to/ken").is_err());
    assert!(ApiToken::validate_name("tok.en").is_err());
}

#[test]
fn validate_name_returns_domain_error() {
    let err = ApiToken::validate_name("").unwrap_err();
    assert!(
        matches!(err, ferrous_dns_domain::DomainError::InvalidInput(_)),
        "expected InvalidInput, got: {err:?}"
    );
}
