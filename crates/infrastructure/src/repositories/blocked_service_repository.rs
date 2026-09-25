use crate::repositories::{db_err, is_fk_violation, is_unique_violation, sql_now};
use async_trait::async_trait;
use ferrous_dns_application::ports::BlockedServiceRepository;
use ferrous_dns_domain::{BlockedService, DomainError};
use sqlx::SqlitePool;
use std::sync::Arc;
use tracing::instrument;

type BlockedServiceRow = (i64, String, i64, String);

pub struct SqliteBlockedServiceRepository {
    pool: SqlitePool,
}

impl SqliteBlockedServiceRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_entity(row: BlockedServiceRow) -> BlockedService {
        let (id, service_id, group_id, created_at) = row;
        BlockedService {
            id: Some(id),
            service_id: Arc::from(service_id.as_str()),
            group_id,
            created_at: Some(created_at),
        }
    }
}

#[async_trait]
impl BlockedServiceRepository for SqliteBlockedServiceRepository {
    #[instrument(skip(self))]
    async fn block_service(
        &self,
        service_id: &str,
        group_id: i64,
    ) -> Result<BlockedService, DomainError> {
        let now = sql_now();

        let result = sqlx::query(
            "INSERT INTO blocked_services (service_id, group_id, created_at) VALUES (?, ?, ?)",
        )
        .bind(service_id)
        .bind(group_id)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                DomainError::BlockedServiceAlreadyExists(format!(
                    "{service_id} for group {group_id}"
                ))
            } else if is_fk_violation(&e) {
                DomainError::GroupNotFound(group_id)
            } else {
                db_err("Failed to block service")(e)
            }
        })?;

        let id = result.last_insert_rowid();

        Ok(BlockedService {
            id: Some(id),
            service_id: Arc::from(service_id),
            group_id,
            created_at: Some(now),
        })
    }

    #[instrument(skip(self))]
    async fn unblock_service(&self, service_id: &str, group_id: i64) -> Result<(), DomainError> {
        let result =
            sqlx::query("DELETE FROM blocked_services WHERE service_id = ? AND group_id = ?")
                .bind(service_id)
                .bind(group_id)
                .execute(&self.pool)
                .await
                .map_err(db_err("Failed to unblock service"))?;

        if result.rows_affected() == 0 {
            return Err(DomainError::NotFound(format!(
                "Blocked service {service_id} for group {group_id}"
            )));
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_blocked_for_group(
        &self,
        group_id: i64,
    ) -> Result<Vec<BlockedService>, DomainError> {
        let rows = sqlx::query_as::<_, BlockedServiceRow>(
            "SELECT id, service_id, group_id, created_at
             FROM blocked_services WHERE group_id = ? ORDER BY service_id ASC",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err("Failed to get blocked services for group"))?;

        Ok(rows.into_iter().map(Self::row_to_entity).collect())
    }

    #[instrument(skip(self))]
    async fn get_all_blocked(&self) -> Result<Vec<BlockedService>, DomainError> {
        let rows = sqlx::query_as::<_, BlockedServiceRow>(
            "SELECT id, service_id, group_id, created_at
             FROM blocked_services ORDER BY service_id ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err("Failed to get all blocked services"))?;

        Ok(rows.into_iter().map(Self::row_to_entity).collect())
    }

    #[instrument(skip(self))]
    async fn delete_all_for_service(&self, service_id: &str) -> Result<u64, DomainError> {
        let result = sqlx::query("DELETE FROM blocked_services WHERE service_id = ?")
            .bind(service_id)
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to delete all blocked services for service"))?;

        Ok(result.rows_affected())
    }
}
