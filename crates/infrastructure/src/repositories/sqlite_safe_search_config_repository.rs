use crate::repositories::{db_err, is_fk_violation};
use async_trait::async_trait;
use ferrous_dns_application::ports::SafeSearchConfigRepository;
use ferrous_dns_domain::{DomainError, SafeSearchConfig, SafeSearchEngine, YouTubeMode};
use sqlx::SqlitePool;
use tracing::warn;

type ConfigRow = (i64, i64, String, bool, String, String, String);

pub struct SqliteSafeSearchConfigRepository {
    pool: SqlitePool,
}

impl SqliteSafeSearchConfigRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_config(row: ConfigRow) -> Option<SafeSearchConfig> {
        let (id, group_id, engine_str, enabled, youtube_mode_str, created_at, updated_at) = row;
        let engine = engine_str
            .parse::<SafeSearchEngine>()
            .map_err(|_| {
                warn!(engine = %engine_str, "Unrecognised Safe Search engine in database, skipping row");
            })
            .ok()?;
        let youtube_mode = youtube_mode_str.parse::<YouTubeMode>().unwrap_or_else(|_| {
            warn!(
                youtube_mode = %youtube_mode_str,
                "Unrecognised youtube_mode in database, defaulting to strict"
            );
            YouTubeMode::default()
        });
        Some(SafeSearchConfig {
            id: Some(id),
            group_id,
            engine,
            enabled,
            youtube_mode,
            created_at: Some(created_at),
            updated_at: Some(updated_at),
        })
    }
}

#[async_trait]
impl SafeSearchConfigRepository for SqliteSafeSearchConfigRepository {
    async fn get_all(&self) -> Result<Vec<SafeSearchConfig>, DomainError> {
        let rows = sqlx::query_as::<_, ConfigRow>(
            "SELECT id, group_id, engine, enabled, youtube_mode, created_at, updated_at
             FROM safe_search_configs
             ORDER BY group_id, engine",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err("Failed to query all safe search configs"))?;

        Ok(rows.into_iter().filter_map(Self::row_to_config).collect())
    }

    async fn get_by_group(&self, group_id: i64) -> Result<Vec<SafeSearchConfig>, DomainError> {
        let rows = sqlx::query_as::<_, ConfigRow>(
            "SELECT id, group_id, engine, enabled, youtube_mode, created_at, updated_at
             FROM safe_search_configs
             WHERE group_id = ?
             ORDER BY engine",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err("Failed to query safe search configs by group"))?;

        Ok(rows.into_iter().filter_map(Self::row_to_config).collect())
    }

    async fn upsert(
        &self,
        group_id: i64,
        engine: SafeSearchEngine,
        enabled: bool,
        youtube_mode: YouTubeMode,
    ) -> Result<SafeSearchConfig, DomainError> {
        let now = chrono::Utc::now().to_rfc3339();

        let row = sqlx::query_as::<_, ConfigRow>(
            "INSERT INTO safe_search_configs (group_id, engine, enabled, youtube_mode, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(group_id, engine) DO UPDATE SET
               enabled      = excluded.enabled,
               youtube_mode = excluded.youtube_mode,
               updated_at   = excluded.updated_at
             RETURNING id, group_id, engine, enabled, youtube_mode, created_at, updated_at",
        )
        .bind(group_id)
        .bind(engine.to_str())
        .bind(enabled)
        .bind(youtube_mode.to_str())
        .bind(&now)
        .bind(&now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if is_fk_violation(&e) {
                DomainError::GroupNotFound(group_id)
            } else {
                db_err("Failed to upsert safe search config")(e)
            }
        })?;

        Self::row_to_config(row)
            .ok_or_else(|| DomainError::DatabaseError("Invalid safe search config row".into()))
    }

    async fn delete_by_group(&self, group_id: i64) -> Result<(), DomainError> {
        sqlx::query("DELETE FROM safe_search_configs WHERE group_id = ?")
            .bind(group_id)
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to delete safe search configs by group"))?;
        Ok(())
    }
}
