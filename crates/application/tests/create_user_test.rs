use async_trait::async_trait;
use ferrous_dns_application::ports::{
    CreateUserInput, PasswordHasher, UserProvider, UserRepository,
};
use ferrous_dns_application::use_cases::CreateUserUseCase;
use ferrous_dns_domain::{DomainError, User};
use std::sync::Arc;

/// Every call is unreachable: input validation must reject before any port is used.
struct Unreachable;

#[async_trait]
impl UserRepository for Unreachable {
    async fn create(
        &self,
        _: &str,
        _: Option<&str>,
        _: &str,
        _: &str,
    ) -> Result<User, DomainError> {
        unreachable!()
    }
    async fn get_by_username(&self, _: &str) -> Result<Option<User>, DomainError> {
        unreachable!()
    }
    async fn get_by_id(&self, _: i64) -> Result<Option<User>, DomainError> {
        unreachable!()
    }
    async fn get_all(&self) -> Result<Vec<User>, DomainError> {
        unreachable!()
    }
    async fn update_password(&self, _: i64, _: &str) -> Result<(), DomainError> {
        unreachable!()
    }
    async fn delete(&self, _: i64) -> Result<(), DomainError> {
        unreachable!()
    }
}

#[async_trait]
impl UserProvider for Unreachable {
    async fn get_by_username(&self, _: &str) -> Result<Option<User>, DomainError> {
        unreachable!()
    }
    async fn get_all(&self) -> Result<Vec<User>, DomainError> {
        unreachable!()
    }
    async fn update_password(&self, _: &str, _: &str) -> Result<(), DomainError> {
        unreachable!()
    }
}

#[async_trait]
impl PasswordHasher for Unreachable {
    async fn hash(&self, _: &str) -> Result<String, DomainError> {
        unreachable!()
    }
    async fn verify(&self, _: &str, _: &str) -> Result<bool, DomainError> {
        unreachable!()
    }
    async fn hash_many(&self, _: &[String]) -> Result<Vec<String>, DomainError> {
        unreachable!()
    }
    async fn verify_any(&self, _: &str, _: Vec<Arc<str>>) -> Result<Option<usize>, DomainError> {
        unreachable!()
    }
}

fn input(display_name: Option<&str>, role: &str) -> CreateUserInput {
    CreateUserInput {
        username: Arc::from("alice"),
        display_name: display_name.map(Arc::from),
        password: "correct-horse-battery".to_string(),
        role: role.to_string(),
    }
}

fn use_case() -> CreateUserUseCase {
    CreateUserUseCase::new(
        Arc::new(Unreachable),
        Arc::new(Unreachable),
        Arc::new(Unreachable),
    )
}

#[tokio::test]
async fn overlong_display_name_is_invalid_input() {
    let result = use_case()
        .execute(input(Some(&"x".repeat(101)), "viewer"))
        .await;
    assert!(matches!(result, Err(DomainError::InvalidInput(_))));
}

#[tokio::test]
async fn unknown_role_is_rejected_before_persisting() {
    let result = use_case().execute(input(None, "superuser")).await;
    assert!(matches!(result, Err(DomainError::InvalidInput(_))));
}
