use crate::repositories::{db_err, is_fk_violation, is_unique_violation, sql_now};
use async_trait::async_trait;
use ferrous_dns_application::ports::ClientSubnetRepository;
use ferrous_dns_domain::{ClientSubnet, DomainError};
use sqlx::SqlitePool;
use std::sync::Arc;
use tracing::instrument;

type SubnetRow = (i64, String, i64, Option<String>, String, String);

pub struct SqliteClientSubnetRepository {
    pool: SqlitePool,
}

impl SqliteClientSubnetRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_subnet(row: SubnetRow) -> ClientSubnet {
        let (id, subnet_cidr, group_id, comment, created_at, updated_at) = row;

        ClientSubnet {
            id: Some(id),
            subnet_cidr: Arc::from(subnet_cidr.as_str()),
            group_id,
            comment: comment.map(|s| Arc::from(s.as_str())),
            created_at: Some(created_at),
            updated_at: Some(updated_at),
        }
    }
}

#[async_trait]
impl ClientSubnetRepository for SqliteClientSubnetRepository {
    #[instrument(skip(self))]
    async fn create(
        &self,
        subnet_cidr: String,
        group_id: i64,
        comment: Option<String>,
    ) -> Result<ClientSubnet, DomainError> {
        let now = sql_now();

        let row = sqlx::query_as::<_, SubnetRow>(
            "INSERT INTO client_subnets (subnet_cidr, group_id, comment, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?)
             RETURNING id, subnet_cidr, group_id, comment, created_at, updated_at",
        )
        .bind(&subnet_cidr)
        .bind(group_id)
        .bind(&comment)
        .bind(&now)
        .bind(&now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                DomainError::SubnetConflict(format!("Subnet '{subnet_cidr}' already exists"))
            } else if is_fk_violation(&e) {
                DomainError::GroupNotFound(group_id)
            } else {
                db_err("Failed to create client subnet")(e)
            }
        })?;

        Ok(Self::row_to_subnet(row))
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, id: i64) -> Result<Option<ClientSubnet>, DomainError> {
        let row = sqlx::query_as::<_, SubnetRow>(
            "SELECT id, subnet_cidr, group_id, comment, created_at, updated_at
             FROM client_subnets WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err("Failed to query subnet by id"))?;

        Ok(row.map(Self::row_to_subnet))
    }

    #[instrument(skip(self))]
    async fn get_all(&self) -> Result<Vec<ClientSubnet>, DomainError> {
        let rows = sqlx::query_as::<_, SubnetRow>(
            "SELECT id, subnet_cidr, group_id, comment, created_at, updated_at
             FROM client_subnets
             ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err("Failed to query all subnets"))?;

        Ok(rows.into_iter().map(Self::row_to_subnet).collect())
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM client_subnets WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to delete subnet"))?;

        if result.rows_affected() == 0 {
            return Err(DomainError::SubnetNotFound(format!(
                "Subnet {id} not found"
            )));
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn exists(&self, subnet_cidr: &str) -> Result<bool, DomainError> {
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM client_subnets WHERE subnet_cidr = ?")
                .bind(subnet_cidr)
                .fetch_one(&self.pool)
                .await
                .map_err(db_err("Failed to check subnet existence"))?;

        Ok(count.0 > 0)
    }
}
