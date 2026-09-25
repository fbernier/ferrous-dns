use super::db_err;
use async_trait::async_trait;
use ferrous_dns_application::ports::BlocklistRepository;
use ferrous_dns_domain::{BlockedDomain, DomainError};
use sqlx::SqlitePool;

type DomainRow = (i64, String, Option<String>);

fn to_domain((id, domain, added_at): DomainRow) -> BlockedDomain {
    BlockedDomain {
        id: Some(id),
        domain,
        added_at,
    }
}

pub struct SqliteBlocklistRepository {
    pool: SqlitePool,
}

impl SqliteBlocklistRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl BlocklistRepository for SqliteBlocklistRepository {
    async fn get_all_paged(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<BlockedDomain>, u64), DomainError> {
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blocklist")
            .fetch_one(&self.pool)
            .await
            .map_err(db_err("Failed to count blocklist"))?;

        let rows = sqlx::query_as::<_, DomainRow>(
            "SELECT id, domain, datetime(added_at) AS added_at FROM blocklist
             ORDER BY added_at DESC LIMIT ? OFFSET ?",
        )
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(db_err("Failed to fetch blocklist page"))?;

        Ok((rows.into_iter().map(to_domain).collect(), total as u64))
    }
}
