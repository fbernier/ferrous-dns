use super::db_err;
use async_trait::async_trait;
use ferrous_dns_application::ports::WhitelistRepository;
use ferrous_dns_domain::{whitelist::WhitelistedDomain, DomainError};
use sqlx::SqlitePool;
use tracing::debug;

pub struct SqliteWhitelistRepository {
    pool: SqlitePool,
}

impl SqliteWhitelistRepository {
    pub async fn load(pool: SqlitePool) -> Result<Self, DomainError> {
        Ok(Self::new(pool))
    }

    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl WhitelistRepository for SqliteWhitelistRepository {
    async fn get_all(&self) -> Result<Vec<WhitelistedDomain>, DomainError> {
        let rows = sqlx::query_as::<_, (i64, String, Option<String>)>(
            "SELECT id, domain, datetime(added_at) AS added_at FROM whitelist ORDER BY added_at DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err("Failed to fetch whitelist"))?;
        Ok(rows
            .into_iter()
            .map(|(id, domain, added_at)| WhitelistedDomain {
                id: Some(id),
                domain,
                added_at,
            })
            .collect())
    }

    async fn add_domain(&self, domain: &WhitelistedDomain) -> Result<(), DomainError> {
        sqlx::query("INSERT INTO whitelist (domain) VALUES (?)")
            .bind(&domain.domain)
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to add whitelist domain"))?;
        debug!(domain = %domain.domain, "Domain added to whitelist");
        Ok(())
    }

    async fn remove_domain(&self, domain: &str) -> Result<(), DomainError> {
        sqlx::query("DELETE FROM whitelist WHERE domain = ?")
            .bind(domain)
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to remove whitelist domain"))?;
        debug!(domain = %domain, "Domain removed from whitelist");
        Ok(())
    }

    async fn is_whitelisted(&self, domain: &str) -> Result<bool, DomainError> {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM whitelist WHERE domain = ?)")
            .bind(domain)
            .fetch_one(&self.pool)
            .await
            .map_err(db_err("Failed to query whitelist domain"))
    }
}
