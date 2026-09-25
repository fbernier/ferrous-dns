//! Exercises 20260924000300 (managed_domains.group_id ON DELETE CASCADE) on a
//! database migrated to the previous schema and seeded, and on a fresh one.

use ferrous_dns_application::ports::GroupRepository;
use ferrous_dns_infrastructure::repositories::SqliteGroupRepository;
use sqlx::migrate::Migrator;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use std::borrow::Cow;

#[path = "support/db.rs"]
mod db;

const CASCADE_VERSION: i64 = 20260924000300;

type RuleRow = (
    i64,
    String,
    String,
    String,
    i64,
    Option<String>,
    bool,
    String,
    String,
    Option<String>,
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

async fn rules(pool: &SqlitePool) -> Vec<RuleRow> {
    sqlx::query_as(
        "SELECT id, name, domain, action, group_id, comment, enabled, created_at, updated_at, service_id
         FROM managed_domains ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// Every index and trigger on `managed_domains`, with its SQL.
async fn schema_objects(pool: &SqlitePool) -> Vec<(String, String, Option<String>)> {
    sqlx::query_as(
        "SELECT type, name, sql FROM sqlite_master
         WHERE tbl_name = 'managed_domains' AND type IN ('index', 'trigger')
         ORDER BY type, name",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn group_fk_on_delete(pool: &SqlitePool) -> String {
    sqlx::query_scalar(
        "SELECT on_delete FROM pragma_foreign_key_list('managed_domains') WHERE \"from\" = 'group_id'",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn delete_group(pool: &SqlitePool, id: i64) {
    SqliteGroupRepository::new(pool.clone())
        .delete(id)
        .await
        .expect("managed domains must not pin their group");
}

async fn rule_groups(pool: &SqlitePool) -> Vec<i64> {
    sqlx::query_scalar("SELECT group_id FROM managed_domains ORDER BY id")
        .fetch_all(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn upgrade_keeps_rules_indexes_and_ids_and_cascades_group_deletes() {
    let pool = pool().await;
    migrate_up_to(&pool, CASCADE_VERSION).await;
    sqlx::raw_sql(
        "INSERT INTO groups (id, name) VALUES (2, 'Kids'), (3, 'Office');
         INSERT INTO managed_domains
             (id, name, domain, action, group_id, comment, enabled, created_at, updated_at, service_id)
         VALUES (1, '[YouTube] youtube.com', 'youtube.com', 'deny', 2, NULL, 1, 't1', 'u1', 'youtube'),
                (2, 'work', 'work.example', 'allow', 3, 'keep me', 0, 't2', 'u2', NULL),
                (3, 'gone', 'gone.example', 'deny', 3, NULL, 1, 't3', 'u3', NULL);
         DELETE FROM managed_domains WHERE id = 3;",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(group_fk_on_delete(&pool).await, "NO ACTION");
    let rules_before = rules(&pool).await;
    let objects_before = schema_objects(&pool).await;

    migrate_all(&pool).await;

    assert_eq!(rules(&pool).await, rules_before);
    assert_eq!(schema_objects(&pool).await, objects_before);
    assert_eq!(group_fk_on_delete(&pool).await, "CASCADE");
    let violations: Vec<(String,)> = sqlx::query_as("PRAGMA foreign_key_check")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(violations.is_empty(), "{violations:?}");

    // Row 3 was deleted before the upgrade; its id must not be handed out again.
    let next_id: i64 = sqlx::query_scalar(
        "INSERT INTO managed_domains (name, domain, action, group_id, created_at, updated_at)
         VALUES ('new', 'new.example', 'deny', 3, 't', 't') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(next_id, 4);

    delete_group(&pool, 2).await;
    assert_eq!(rule_groups(&pool).await, vec![3, 3]);
}

#[tokio::test]
async fn on_a_fresh_database_deleting_a_group_deletes_its_rules() {
    let pool = db::migrated_pool().await;
    assert_eq!(group_fk_on_delete(&pool).await, "CASCADE");
    sqlx::raw_sql(
        "INSERT INTO groups (id, name) VALUES (2, 'Kids'), (3, 'Office');
         INSERT INTO managed_domains (name, domain, action, group_id, created_at, updated_at, service_id)
         VALUES ('[YouTube] youtube.com', 'youtube.com', 'deny', 2, 't', 't', 'youtube'),
                ('office', 'office.example', 'allow', 3, 't', 't', NULL);",
    )
    .execute(&pool)
    .await
    .unwrap();

    delete_group(&pool, 2).await;

    assert_eq!(rule_groups(&pool).await, vec![3]);
}

#[tokio::test]
async fn upgrade_drops_rules_of_a_deleted_group_instead_of_failing() {
    let pool = pool().await;
    migrate_up_to(&pool, CASCADE_VERSION).await;
    // Foreign keys off so the seed can name a missing group.
    sqlx::raw_sql(
        "PRAGMA foreign_keys = OFF;
         INSERT INTO groups (id, name) VALUES (2, 'Kids');
         INSERT INTO managed_domains (id, name, domain, action, group_id, created_at, updated_at)
         VALUES (1, 'kept', 'kept.example', 'deny', 2, 't', 't'),
                (2, 'orphan', 'orphan.example', 'deny', 99, 't', 't');
         PRAGMA foreign_keys = ON;",
    )
    .execute(&pool)
    .await
    .unwrap();

    migrate_all(&pool).await;

    assert_eq!(rule_groups(&pool).await, vec![2]);
}
