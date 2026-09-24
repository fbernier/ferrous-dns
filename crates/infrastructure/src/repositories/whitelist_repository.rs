use super::db_err;
use async_trait::async_trait;
use ferrous_dns_application::ports::WhitelistRepository;
use ferrous_dns_domain::{DomainError, WhitelistedDomain};
use sqlx::SqlitePool;

pub struct SqliteWhitelistRepository {
    pool: SqlitePool,
}

impl SqliteWhitelistRepository {
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
}
