use crate::repositories::{db_err, is_unique_violation, sql_now};
use async_trait::async_trait;
use ferrous_dns_application::ports::CustomServiceRepository;
use ferrous_dns_domain::{CustomService, DomainError};
use sqlx::SqlitePool;
use std::sync::Arc;
use tracing::{instrument, warn};

type CustomServiceRow = (i64, String, String, String, String, String, String);

pub struct SqliteCustomServiceRepository {
    pool: SqlitePool,
}

impl SqliteCustomServiceRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_entity(row: CustomServiceRow) -> CustomService {
        let (id, service_id, name, category_name, domains_json, created_at, updated_at) = row;
        let domains = match serde_json::from_str::<Vec<String>>(&domains_json) {
            Ok(raw) => raw.into_iter().map(|d| Arc::from(d.as_str())).collect(),
            Err(e) => {
                warn!(error = %e, service_id, "Corrupt custom service domains JSON in DB, reading as empty");
                Vec::new()
            }
        };

        CustomService {
            id: Some(id),
            service_id: Arc::from(service_id.as_str()),
            name: Arc::from(name.as_str()),
            category_name: Arc::from(category_name.as_str()),
            domains,
            created_at: Some(created_at),
            updated_at: Some(updated_at),
        }
    }
}

fn domains_to_json(domains: &[String]) -> Result<String, DomainError> {
    serde_json::to_string(domains).map_err(|e| DomainError::DatabaseError(e.to_string()))
}

#[async_trait]
impl CustomServiceRepository for SqliteCustomServiceRepository {
    #[instrument(skip(self, domains))]
    async fn create(
        &self,
        service_id: &str,
        name: &str,
        category_name: &str,
        domains: &[String],
    ) -> Result<CustomService, DomainError> {
        let now = sql_now();

        let row = sqlx::query_as::<_, CustomServiceRow>(
            "INSERT INTO custom_services (service_id, name, category_name, domains, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)
             RETURNING id, service_id, name, category_name, domains, created_at, updated_at",
        )
        .bind(service_id)
        .bind(name)
        .bind(category_name)
        .bind(domains_to_json(domains)?)
        .bind(&now)
        .bind(&now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                DomainError::CustomServiceAlreadyExists(service_id.to_string())
            } else {
                db_err("Failed to create custom service")(e)
            }
        })?;

        Ok(Self::row_to_entity(row))
    }

    #[instrument(skip(self))]
    async fn get_by_service_id(
        &self,
        service_id: &str,
    ) -> Result<Option<CustomService>, DomainError> {
        let row = sqlx::query_as::<_, CustomServiceRow>(
            "SELECT id, service_id, name, category_name, domains, created_at, updated_at
             FROM custom_services WHERE service_id = ?",
        )
        .bind(service_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err("Failed to query custom service by service_id"))?;

        Ok(row.map(Self::row_to_entity))
    }

    #[instrument(skip(self))]
    async fn get_all(&self) -> Result<Vec<CustomService>, DomainError> {
        let rows = sqlx::query_as::<_, CustomServiceRow>(
            "SELECT id, service_id, name, category_name, domains, created_at, updated_at
             FROM custom_services ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err("Failed to query all custom services"))?;

        Ok(rows.into_iter().map(Self::row_to_entity).collect())
    }

    #[instrument(skip(self))]
    async fn update(
        &self,
        service_id: &str,
        name: Option<String>,
        category_name: Option<String>,
        domains: Option<Vec<String>>,
    ) -> Result<CustomService, DomainError> {
        let domains_json = domains.as_deref().map(domains_to_json).transpose()?;

        let row = sqlx::query_as::<_, CustomServiceRow>(
            "UPDATE custom_services
             SET name = COALESCE(?, name),
                 category_name = COALESCE(?, category_name),
                 domains = COALESCE(?, domains),
                 updated_at = ?
             WHERE service_id = ?
             RETURNING id, service_id, name, category_name, domains, created_at, updated_at",
        )
        .bind(&name)
        .bind(&category_name)
        .bind(&domains_json)
        .bind(sql_now())
        .bind(service_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err("Failed to update custom service"))?;

        row.map(Self::row_to_entity)
            .ok_or_else(|| DomainError::CustomServiceNotFound(service_id.to_string()))
    }

    #[instrument(skip(self))]
    async fn delete(&self, service_id: &str) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM custom_services WHERE service_id = ?")
            .bind(service_id)
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to delete custom service"))?;

        if result.rows_affected() == 0 {
            return Err(DomainError::CustomServiceNotFound(service_id.to_string()));
        }

        Ok(())
    }
}
