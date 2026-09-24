use crate::repositories::{db_err, is_fk_violation, is_unique_violation, parse_db_action, sql_now};
use async_trait::async_trait;
use fancy_regex::Regex;
use ferrous_dns_application::ports::{RegexFilterRepository, RegexFilterUpdate};
use ferrous_dns_domain::{DomainAction, DomainError, RegexFilter};
use sqlx::SqlitePool;
use std::sync::Arc;
use tracing::instrument;

type RegexFilterRow = (
    i64,
    String,
    String,
    String,
    i64,
    Option<String>,
    bool,
    String,
    String,
);

pub struct SqliteRegexFilterRepository {
    pool: SqlitePool,
}

impl SqliteRegexFilterRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_filter(row: RegexFilterRow) -> RegexFilter {
        let (id, name, pattern, action, group_id, comment, enabled, created_at, updated_at) = row;
        RegexFilter {
            id: Some(id),
            name: Arc::from(name.as_str()),
            pattern: Arc::from(pattern.as_str()),
            action: parse_db_action(&action),
            group_id,
            comment: comment.map(|s| Arc::from(s.as_str())),
            enabled,
            created_at: Some(created_at),
            updated_at: Some(updated_at),
        }
    }

    fn validate_regex_syntax(pattern: &str) -> Result<(), DomainError> {
        Regex::new(pattern).map(|_| ()).map_err(|e| {
            DomainError::InvalidRegexFilter(format!("Invalid regex pattern '{pattern}': {e}"))
        })
    }
}

#[async_trait]
impl RegexFilterRepository for SqliteRegexFilterRepository {
    #[instrument(skip(self))]
    async fn create(
        &self,
        name: String,
        pattern: String,
        action: DomainAction,
        group_id: i64,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<RegexFilter, DomainError> {
        Self::validate_regex_syntax(&pattern)?;

        let now = sql_now();

        let row = sqlx::query_as::<_, RegexFilterRow>(
            "INSERT INTO regex_filters (name, pattern, action, group_id, comment, enabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             RETURNING id, name, pattern, action, group_id, comment, enabled, created_at, updated_at",
        )
        .bind(&name)
        .bind(&pattern)
        .bind(action.to_str())
        .bind(group_id)
        .bind(&comment)
        .bind(enabled)
        .bind(&now)
        .bind(&now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                DomainError::AlreadyExists(format!("Regex filter '{name}' already exists"))
            } else if is_fk_violation(&e) {
                DomainError::GroupNotFound(group_id)
            } else {
                db_err("Failed to create regex filter")(e)
            }
        })?;

        Ok(Self::row_to_filter(row))
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, id: i64) -> Result<Option<RegexFilter>, DomainError> {
        let row = sqlx::query_as::<_, RegexFilterRow>(
            "SELECT id, name, pattern, action, group_id, comment, enabled, created_at, updated_at
             FROM regex_filters WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err("Failed to query regex filter by id"))?;

        Ok(row.map(Self::row_to_filter))
    }

    #[instrument(skip(self))]
    async fn get_all(&self) -> Result<Vec<RegexFilter>, DomainError> {
        let rows = sqlx::query_as::<_, RegexFilterRow>(
            "SELECT id, name, pattern, action, group_id, comment, enabled, created_at, updated_at
             FROM regex_filters ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err("Failed to query all regex filters"))?;

        Ok(rows.into_iter().map(Self::row_to_filter).collect())
    }

    #[instrument(skip(self))]
    async fn update(&self, id: i64, update: RegexFilterUpdate) -> Result<RegexFilter, DomainError> {
        let RegexFilterUpdate {
            name,
            pattern,
            action,
            group_id,
            comment,
            enabled,
        } = update;
        let replace_comment = comment.is_some();
        let comment = comment.flatten();
        if let Some(p) = &pattern {
            Self::validate_regex_syntax(p)?;
        }

        let row = sqlx::query_as::<_, RegexFilterRow>(
            "UPDATE regex_filters
             SET name = COALESCE(?, name),
                 pattern = COALESCE(?, pattern),
                 action = COALESCE(?, action),
                 group_id = COALESCE(?, group_id),
                 comment = CASE WHEN ? THEN ? ELSE comment END,
                 enabled = COALESCE(?, enabled),
                 updated_at = ?
             WHERE id = ?
             RETURNING id, name, pattern, action, group_id, comment, enabled, created_at, updated_at",
        )
        .bind(&name)
        .bind(&pattern)
        .bind(action.map(|a| a.to_str()))
        .bind(group_id)
        .bind(replace_comment)
        .bind(&comment)
        .bind(enabled)
        .bind(sql_now())
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                DomainError::AlreadyExists(format!(
                    "Regex filter '{}' already exists",
                    name.as_deref().unwrap_or_default()
                ))
            } else if let Some(gid) = group_id.filter(|_| is_fk_violation(&e)) {
                DomainError::GroupNotFound(gid)
            } else {
                db_err("Failed to update regex filter")(e)
            }
        })?;

        row.map(Self::row_to_filter)
            .ok_or(DomainError::RegexFilterNotFound(id))
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM regex_filters WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to delete regex filter"))?;

        if result.rows_affected() == 0 {
            return Err(DomainError::RegexFilterNotFound(id));
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_enabled(&self) -> Result<Vec<RegexFilter>, DomainError> {
        let rows = sqlx::query_as::<_, RegexFilterRow>(
            "SELECT id, name, pattern, action, group_id, comment, enabled, created_at, updated_at
             FROM regex_filters WHERE enabled = 1 ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err("Failed to query enabled regex filters"))?;

        Ok(rows.into_iter().map(Self::row_to_filter).collect())
    }
}
