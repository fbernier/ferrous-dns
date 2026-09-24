//! In-memory SQLite pool carrying the production schema, so repository tests
//! exercise the real constraints and cascades instead of hand-written DDL.

use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;

/// Fresh in-memory database with every migration applied. The migrations seed
/// the default group (`id = 1, is_default = 1`).
pub async fn migrated_pool() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("connect in-memory sqlite");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("run migrations");
    pool
}
