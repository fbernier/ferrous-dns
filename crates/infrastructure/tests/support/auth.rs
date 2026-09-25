//! The TOML admin over SQLite users, and the challenge a correct password
//! leaves behind, for driving the second-factor use cases end to end.

use std::sync::Arc;

use ferrous_dns_application::ports::{MfaRepository, UserProvider};
use ferrous_dns_domain::{Config, MfaChallenge, MfaMethod};
use ferrous_dns_infrastructure::auth::{CompositeUserProvider, TomlAdminProvider};
use ferrous_dns_infrastructure::repositories::{SqliteUserRepository, TomlConfigFilePersistence};
use sqlx::SqlitePool;
use tokio::sync::RwLock;

pub const ADMIN: &str = "admin";

/// `ADMIN` with a password set, so the provider returns it.
pub fn admin_user_provider(pool: SqlitePool) -> Arc<dyn UserProvider> {
    let mut config = Config::default();
    config.auth.admin.username = ADMIN.into();
    config.auth.admin.password_hash = Some("unused".into());
    Arc::new(CompositeUserProvider::new(
        TomlAdminProvider::new(config.auth.admin.clone()),
        Arc::new(SqliteUserRepository::new(pool)),
        Arc::new(RwLock::new(config)),
        None,
        Arc::new(TomlConfigFilePersistence),
    ))
}

/// The pending challenge `LoginUseCase` issues for `ADMIN` after a correct password.
pub async fn password_accepted(mfa: &dyn MfaRepository, token: &str) {
    let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(5))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    mfa.create_challenge(&MfaChallenge {
        token: Arc::from(token),
        username: Arc::from(ADMIN),
        remember_me: false,
        kind: MfaMethod::Totp,
        state: None,
        expires_at,
    })
    .await
    .unwrap();
}
