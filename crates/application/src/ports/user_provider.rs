use async_trait::async_trait;
use ferrous_dns_domain::{DomainError, User};

/// Composite port that combines TOML admin + database users.
///
/// Follows the same Composite pattern as `CompositeServiceCatalog`:
/// a static source (TOML config) merged with a dynamic source (SQLite).
/// TOML admin always takes priority when usernames collide.
#[async_trait]
pub trait UserProvider: Send + Sync {
    /// Find a user by username across all sources (TOML first, then DB).
    async fn get_by_username(&self, username: &str) -> Result<Option<User>, DomainError>;

    /// List all users from all sources.
    async fn get_all(&self) -> Result<Vec<User>, DomainError>;

    /// Update password for any user source.
    /// For TOML admin: persists hash to config file.
    /// For DB users: updates the `users` table.
    async fn update_password(&self, username: &str, password_hash: &str)
        -> Result<(), DomainError>;
}
