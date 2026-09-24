use std::sync::Arc;

use async_trait::async_trait;
use sqlx::SqlitePool;
use tracing::{error, info, instrument};

use ferrous_dns_application::ports::UserRepository;
use ferrous_dns_domain::{DomainError, User, UserRole, UserSource};

use crate::repositories::{db_err, is_unique_violation, sql_now};

pub struct SqliteUserRepository {
    pool: Arc<SqlitePool>,
}

impl SqliteUserRepository {
    pub fn new(pool: Arc<SqlitePool>) -> Self {
        Self { pool }
    }
}

type UserRow = (
    i64,
    String,
    Option<String>,
    String,
    String,
    bool,
    String,
    String,
);

#[async_trait]
impl UserRepository for SqliteUserRepository {
    #[instrument(skip(self, password_hash))]
    async fn create(
        &self,
        username: &str,
        display_name: Option<&str>,
        password_hash: &str,
        role: &str,
    ) -> Result<User, DomainError> {
        let now = sql_now();

        let row: UserRow = sqlx::query_as(
            "INSERT INTO users (username, display_name, password_hash, role, enabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, 1, ?, ?)
             RETURNING id, username, display_name, password_hash, role, enabled, created_at, updated_at",
        )
        .bind(username)
        .bind(display_name)
        .bind(password_hash)
        .bind(role)
        .bind(&now)
        .bind(&now)
        .fetch_one(self.pool.as_ref())
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                DomainError::DuplicateUsername(username.to_string())
            } else {
                db_err("Failed to create user")(e)
            }
        })?;

        info!(username = username, "User created in database");
        Ok(row_to_user(row))
    }

    #[instrument(skip(self))]
    async fn get_by_username(&self, username: &str) -> Result<Option<User>, DomainError> {
        let row: Option<UserRow> = sqlx::query_as(
            "SELECT id, username, display_name, password_hash, role, enabled, created_at, updated_at
             FROM users WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(self.pool.as_ref())
        .await
        .map_err(db_err("Failed to get user by username"))?;

        Ok(row.map(row_to_user))
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, id: i64) -> Result<Option<User>, DomainError> {
        let row: Option<UserRow> = sqlx::query_as(
            "SELECT id, username, display_name, password_hash, role, enabled, created_at, updated_at
             FROM users WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.pool.as_ref())
        .await
        .map_err(db_err("Failed to get user by id"))?;

        Ok(row.map(row_to_user))
    }

    #[instrument(skip(self))]
    async fn get_all(&self) -> Result<Vec<User>, DomainError> {
        let rows: Vec<UserRow> = sqlx::query_as(
            "SELECT id, username, display_name, password_hash, role, enabled, created_at, updated_at
             FROM users ORDER BY id",
        )
        .fetch_all(self.pool.as_ref())
        .await
        .map_err(db_err("Failed to get all users"))?;

        Ok(rows.into_iter().map(row_to_user).collect())
    }

    #[instrument(skip(self, password_hash))]
    async fn update_password(&self, id: i64, password_hash: &str) -> Result<(), DomainError> {
        let result = sqlx::query("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?")
            .bind(password_hash)
            .bind(sql_now())
            .bind(id)
            .execute(self.pool.as_ref())
            .await
            .map_err(db_err("Failed to update user password"))?;

        if result.rows_affected() == 0 {
            return Err(DomainError::UserNotFound(id.to_string()));
        }

        Ok(())
    }

    /// Username-keyed auth state has no FK: purge it so sessions die and a reused name inherits no factors.
    #[instrument(skip(self))]
    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(db_err("Failed to begin user delete"))?;

        let deleted: Option<(String,)> =
            sqlx::query_as("DELETE FROM users WHERE id = ? RETURNING username")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err("Failed to delete user"))?;

        let Some((username,)) = deleted else {
            return Err(DomainError::UserNotFound(id.to_string()));
        };

        for stmt in [
            "DELETE FROM auth_sessions WHERE username = ?",
            "DELETE FROM user_mfa WHERE username = ?",
            "DELETE FROM mfa_recovery_codes WHERE username = ?",
            "DELETE FROM webauthn_credentials WHERE username = ?",
            "DELETE FROM mfa_challenges WHERE username = ?",
        ] {
            sqlx::query(stmt)
                .bind(&username)
                .execute(&mut *tx)
                .await
                .map_err(db_err("Failed to delete user auth state"))?;
        }

        tx.commit()
            .await
            .map_err(db_err("Failed to commit user delete"))?;

        Ok(())
    }
}

fn row_to_user(
    (id, username, display_name, password_hash, role, enabled, created_at, updated_at): UserRow,
) -> User {
    let role = UserRole::parse(&role).unwrap_or_else(|_| {
        error!(role, "Invalid user role in database, defaulting to Viewer");
        UserRole::Viewer
    });
    User {
        id: Some(id),
        username: Arc::from(username.as_str()),
        display_name: display_name.map(|s| Arc::from(s.as_str())),
        password_hash: Arc::from(password_hash.as_str()),
        role,
        source: UserSource::Database,
        enabled,
        created_at: Some(created_at),
        updated_at: Some(updated_at),
    }
}
