use std::sync::Arc;

use ferrous_dns_application::ports::{ConfigFilePersistence, UserProvider};
use ferrous_dns_domain::{Config, DomainError};
use ferrous_dns_infrastructure::auth::{CompositeUserProvider, TomlAdminProvider};
use ferrous_dns_infrastructure::repositories::SqliteUserRepository;
use tokio::sync::RwLock;

#[path = "support/db.rs"]
mod db;

struct FailingPersistence;

impl ConfigFilePersistence for FailingPersistence {
    fn load_config_from_file(&self, _path: &str) -> Result<Config, DomainError> {
        Err(DomainError::ConfigError("disk full".into()))
    }

    fn save_config_to_file(&self, _config: &Config, _path: &str) -> Result<(), DomainError> {
        Err(DomainError::ConfigError("disk full".into()))
    }
}

#[tokio::test]
async fn failed_admin_password_save_leaves_config_and_login_hash_unchanged() {
    let mut config = Config::default();
    config.auth.admin.username = "admin".into();
    config.auth.admin.password_hash = Some("old-hash".into());
    let admin = TomlAdminProvider::new(config.auth.admin.clone());
    let config = Arc::new(RwLock::new(config));
    let provider = CompositeUserProvider::new(
        admin,
        Arc::new(SqliteUserRepository::new(db::migrated_pool().await)),
        config.clone(),
        Some("/nonexistent/config.toml".into()),
        Arc::new(FailingPersistence),
    );

    assert!(matches!(
        provider.update_password("admin", "new-hash").await,
        Err(DomainError::ConfigError(_))
    ));

    assert_eq!(
        config.read().await.auth.admin.password_hash.as_deref(),
        Some("old-hash")
    );
    let admin = provider.get_by_username("admin").await.unwrap().unwrap();
    assert_eq!(admin.password_hash.as_ref(), "old-hash");
}
