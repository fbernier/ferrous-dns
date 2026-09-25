//! Exercises 20260924000400 (safe_search_configs.group_id ON DELETE CASCADE) on a
//! database migrated to the previous schema and seeded, and on a fresh one.

use ferrous_dns_application::ports::GroupRepository;
use ferrous_dns_infrastructure::repositories::SqliteGroupRepository;
use sqlx::migrate::Migrator;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use std::borrow::Cow;

#[path = "support/db.rs"]
mod db;

const CASCADE_VERSION: i64 = 20260924000400;

type ConfigRow = (i64, i64, String, bool, String, String, String);

async fn pool() -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap()
}

async fn migrate_up_to(pool: &SqlitePool, below: i64) {
    let mut old: Migrator = sqlx::migrate!("../../migrations");
    old.migrations = Cow::Owned(
        old.migrations
            .iter()
            .filter(|m| m.version < below)
            .cloned()
            .collect(),
    );
    old.run(pool).await.unwrap();
}

async fn migrate_all(pool: &SqlitePool) {
    sqlx::migrate!("../../migrations").run(pool).await.unwrap();
}

async fn configs(pool: &SqlitePool) -> Vec<ConfigRow> {
    sqlx::query_as(
        "SELECT id, group_id, engine, enabled, youtube_mode, created_at, updated_at
         FROM safe_search_configs ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// Every index and trigger on `safe_search_configs`, with its SQL.
async fn schema_objects(pool: &SqlitePool) -> Vec<(String, String, Option<String>)> {
    sqlx::query_as(
        "SELECT type, name, sql FROM sqlite_master
         WHERE tbl_name = 'safe_search_configs' AND type IN ('index', 'trigger')
         ORDER BY type, name",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn group_fk_on_delete(pool: &SqlitePool) -> String {
    sqlx::query_scalar(
        "SELECT on_delete FROM pragma_foreign_key_list('safe_search_configs') WHERE \"from\" = 'group_id'",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn delete_group(pool: &SqlitePool, id: i64) {
    SqliteGroupRepository::new(pool.clone())
        .delete(id)
        .await
        .expect("safe-search configs must not pin their group");
}

async fn config_groups(pool: &SqlitePool) -> Vec<i64> {
    sqlx::query_scalar("SELECT group_id FROM safe_search_configs ORDER BY id")
        .fetch_all(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn upgrade_keeps_configs_indexes_and_ids_and_cascades_group_deletes() {
    let pool = pool().await;
    migrate_up_to(&pool, CASCADE_VERSION).await;
    sqlx::raw_sql(
        "INSERT INTO groups (id, name) VALUES (2, 'Kids'), (3, 'Office');
         INSERT INTO safe_search_configs
             (id, group_id, engine, enabled, youtube_mode, created_at, updated_at)
         VALUES (1, 2, 'google', 1, 'strict', 't1', 'u1'),
                (2, 2, 'youtube', 1, 'moderate', 't2', 'u2'),
                (3, 3, 'bing', 0, 'strict', 't3', 'u3'),
                (4, 3, 'brave', 1, 'strict', 't4', 'u4');
         DELETE FROM safe_search_configs WHERE id = 4;",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(group_fk_on_delete(&pool).await, "NO ACTION");
    let configs_before = configs(&pool).await;
    let objects_before = schema_objects(&pool).await;

    migrate_all(&pool).await;

    assert_eq!(configs(&pool).await, configs_before);
    assert_eq!(schema_objects(&pool).await, objects_before);
    assert_eq!(group_fk_on_delete(&pool).await, "CASCADE");
    let violations: Vec<(String,)> = sqlx::query_as("PRAGMA foreign_key_check")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(violations.is_empty(), "{violations:?}");

    // Row 4 was deleted before the upgrade; its id must not be handed out again.
    let next_id: i64 = sqlx::query_scalar(
        "INSERT INTO safe_search_configs (group_id, engine, created_at, updated_at)
         VALUES (3, 'ecosia', 't', 't') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(next_id, 5);

    delete_group(&pool, 2).await;
    assert_eq!(config_groups(&pool).await, vec![3, 3]);
}

#[tokio::test]
async fn on_a_fresh_database_deleting_a_group_deletes_its_safe_search_configs() {
    let pool = db::migrated_pool().await;
    assert_eq!(group_fk_on_delete(&pool).await, "CASCADE");
    sqlx::raw_sql(
        "INSERT INTO groups (id, name) VALUES (2, 'Kids'), (3, 'Office');
         INSERT INTO safe_search_configs (group_id, engine, enabled, created_at, updated_at)
         VALUES (2, 'google', 1, 't', 't'),
                (3, 'bing', 1, 't', 't');",
    )
    .execute(&pool)
    .await
    .unwrap();

    delete_group(&pool, 2).await;

    assert_eq!(config_groups(&pool).await, vec![3]);
}

#[tokio::test]
async fn upgrade_drops_configs_of_a_deleted_group_instead_of_failing() {
    let pool = pool().await;
    migrate_up_to(&pool, CASCADE_VERSION).await;
    // Foreign keys off so the seed can name a missing group.
    sqlx::raw_sql(
        "PRAGMA foreign_keys = OFF;
         INSERT INTO groups (id, name) VALUES (2, 'Kids');
         INSERT INTO safe_search_configs (id, group_id, engine, created_at, updated_at)
         VALUES (1, 2, 'google', 't', 't'),
                (2, 99, 'google', 't', 't');
         PRAGMA foreign_keys = ON;",
    )
    .execute(&pool)
    .await
    .unwrap();

    migrate_all(&pool).await;

    assert_eq!(config_groups(&pool).await, vec![2]);
}
