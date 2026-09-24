use async_trait::async_trait;
use ferrous_dns_domain::{DomainError, User, UserRole};

/// Port for managing database-stored user accounts.
///
/// The TOML admin is NOT managed through this port — it comes from
/// `Config.auth.admin` and is combined via the `UserProvider` port.
#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create(
        &self,
        username: &str,
        display_name: Option<&str>,
        password_hash: &str,
        role: UserRole,
    ) -> Result<User, DomainError>;

    async fn get_by_username(&self, username: &str) -> Result<Option<User>, DomainError>;

    async fn get_by_id(&self, id: i64) -> Result<Option<User>, DomainError>;

    async fn get_all(&self) -> Result<Vec<User>, DomainError>;

    async fn update_password(&self, id: i64, password_hash: &str) -> Result<(), DomainError>;

    async fn delete(&self, id: i64) -> Result<(), DomainError>;
}
