use std::sync::Arc;

use ferrous_dns_domain::{AdminConfig, User, UserRole, UserSource};

/// `[auth.admin]` user: the escape hatch that regains access by editing TOML when the DB is lost.
pub struct TomlAdminProvider {
    admin_config: AdminConfig,
}

impl TomlAdminProvider {
    pub fn new(admin_config: AdminConfig) -> Self {
        Self { admin_config }
    }

    /// Returns the TOML admin as a `User` entity, or `None` if no password is set.
    pub fn get_admin(&self) -> Option<User> {
        let hash = self.admin_config.password_hash.as_deref()?;
        if hash.is_empty() {
            return None;
        }

        Some(User {
            id: None,
            username: Arc::from(self.admin_config.username.as_str()),
            display_name: None,
            password_hash: Arc::from(hash),
            role: UserRole::Admin,
            source: UserSource::Toml,
            enabled: true,
            created_at: None,
            updated_at: None,
        })
    }

    /// Unlike `get_admin`, returned even when no password is set, so the name stays reserved.
    pub fn admin_username(&self) -> &str {
        &self.admin_config.username
    }
}
