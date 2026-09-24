//! Exercises 20260924000500 (regex_filters.group_id ON DELETE CASCADE) on a
//! database migrated to the previous schema and seeded, and on a fresh one.

use ferrous_dns_application::ports::GroupRepository;
use ferrous_dns_infrastructure::repositories::SqliteGroupRepository;
use sqlx::migrate::Migrator;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use std::borrow::Cow;

#[path = "support/db.rs"]
mod db;

const CASCADE_VERSION: i64 = 20260924000500;

type FilterRow = (
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

async fn filters(pool: &SqlitePool) -> Vec<FilterRow> {
    sqlx::query_as(
        "SELECT id, name, pattern, action, group_id, comment, enabled, created_at, updated_at
         FROM regex_filters ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// Every index and trigger on `regex_filters`, with its SQL.
async fn schema_objects(pool: &SqlitePool) -> Vec<(String, String, Option<String>)> {
    sqlx::query_as(
        "SELECT type, name, sql FROM sqlite_master
         WHERE tbl_name = 'regex_filters' AND type IN ('index', 'trigger')
         ORDER BY type, name",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn group_fk_on_delete(pool: &SqlitePool) -> String {
    sqlx::query_scalar(
        "SELECT on_delete FROM pragma_foreign_key_list('regex_filters') WHERE \"from\" = 'group_id'",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn delete_group(pool: &SqlitePool, id: i64) {
    SqliteGroupRepository::new(pool.clone())
        .delete(id)
        .await
        .expect("regex filters must not pin their group");
}

async fn group_exists(pool: &SqlitePool, id: i64) -> bool {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM groups WHERE id = ?)")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn filter_groups(pool: &SqlitePool) -> Vec<i64> {
    sqlx::query_scalar("SELECT group_id FROM regex_filters ORDER BY id")
        .fetch_all(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn upgrade_keeps_filters_indexes_and_ids_and_cascades_group_deletes() {
    let pool = pool().await;
    migrate_up_to(&pool, CASCADE_VERSION).await;
    sqlx::raw_sql(
        "INSERT INTO groups (id, name) VALUES (2, 'Kids'), (3, 'Office');
         INSERT INTO regex_filters
             (id, name, pattern, action, group_id, comment, enabled, created_at, updated_at)
         VALUES (1, 'ads', '^ads\\.', 'deny', 2, 'no ads', 1, 't1', 'u1'),
                (2, 'cdn', 'cdn\\.example$', 'allow', 2, NULL, 0, 't2', 'u2'),
                (3, 'track', 'track', 'deny', 3, NULL, 1, 't3', 'u3'),
                (4, 'gone', 'gone', 'deny', 3, NULL, 1, 't4', 'u4');
         DELETE FROM regex_filters WHERE id = 4;",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(group_fk_on_delete(&pool).await, "RESTRICT");
    let filters_before = filters(&pool).await;
    let objects_before = schema_objects(&pool).await;

    migrate_all(&pool).await;

    assert_eq!(filters(&pool).await, filters_before);
    assert_eq!(schema_objects(&pool).await, objects_before);
    assert_eq!(group_fk_on_delete(&pool).await, "CASCADE");
    let violations: Vec<(String,)> = sqlx::query_as("PRAGMA foreign_key_check")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(violations.is_empty(), "{violations:?}");

    // Row 4 was deleted before the upgrade; its id must not be handed out again.
    let next_id: i64 = sqlx::query_scalar(
        "INSERT INTO regex_filters (name, pattern, action, group_id, created_at, updated_at)
         VALUES ('new', 'new', 'deny', 3, 't', 't') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(next_id, 5);

    delete_group(&pool, 2).await;
    assert!(!group_exists(&pool, 2).await);
    assert_eq!(filter_groups(&pool).await, vec![3, 3]);
}

#[tokio::test]
async fn on_a_fresh_database_deleting_a_group_deletes_its_regex_filters() {
    let pool = db::migrated_pool().await;
    assert_eq!(group_fk_on_delete(&pool).await, "CASCADE");
    sqlx::raw_sql(
        "INSERT INTO groups (id, name) VALUES (2, 'Kids'), (3, 'Office');
         INSERT INTO regex_filters (name, pattern, action, group_id, created_at, updated_at)
         VALUES ('ads', '^ads\\.', 'deny', 2, 't', 't'),
                ('track', 'track', 'deny', 3, 't', 't');",
    )
    .execute(&pool)
    .await
    .unwrap();

    delete_group(&pool, 2).await;

    assert!(!group_exists(&pool, 2).await);
    assert_eq!(filter_groups(&pool).await, vec![3]);
}
