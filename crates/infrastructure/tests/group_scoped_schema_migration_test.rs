//! Exercises the 20260924000200..202 migrations on a database migrated to the
//! previous schema and seeded with data, plus the subnet canonicalisation run
//! at database open.

use ferrous_dns_application::ports::{ManagedDomainRepository, WhitelistSourceRepository};
use ferrous_dns_infrastructure::repositories::client_subnet_repository::canonicalize_stored_subnets;
use ferrous_dns_infrastructure::repositories::{
    SqliteManagedDomainRepository, SqliteWhitelistSourceRepository,
};
use sqlx::migrate::Migrator;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use std::borrow::Cow;

#[path = "support/db.rs"]
mod db;

const FIRST_NEW_VERSION: i64 = 20260924000200;

async fn pool() -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap()
}

async fn migrate_before_new(pool: &SqlitePool) {
    let mut old: Migrator = sqlx::migrate!("../../migrations");
    old.migrations = Cow::Owned(
        old.migrations
            .iter()
            .filter(|m| m.version < FIRST_NEW_VERSION)
            .cloned()
            .collect(),
    );
    old.run(pool).await.unwrap();
}

async fn migrate_all(pool: &SqlitePool) {
    sqlx::migrate!("../../migrations").run(pool).await.unwrap();
}

async fn seed_previous_schema(pool: &SqlitePool) {
    sqlx::raw_sql(
        "INSERT INTO groups (id, name) VALUES (2, 'Kids'), (3, 'Office');
         INSERT INTO blocklist_sources (id, name, url, group_id, enabled)
             VALUES (1, 'hagezi', 'https://a.example/list', 2, 1),
                    (2, 'oisd', NULL, 3, 0);
         INSERT INTO blocklist_source_groups (source_id, group_id)
             VALUES (1, 2), (1, 3), (2, 3);
         INSERT INTO whitelist_sources (id, name, url, group_id)
             VALUES (1, 'allow', 'https://w.example/list', 3);
         INSERT INTO whitelist_source_groups (source_id, group_id) VALUES (1, 3), (1, 2);
         INSERT INTO managed_domains (name, domain, action, group_id, created_at, updated_at, service_id)
             VALUES ('[YouTube] youtube.com', 'youtube.com', 'deny', 2, 't', 't', 'youtube');
         INSERT INTO query_log (domain, record_type, client_ip, group_id)
             VALUES ('a.example', 'A', '10.0.0.1', 3), ('b.example', 'A', '10.0.0.2', 2);",
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn upgraded() -> SqlitePool {
    let pool = pool().await;
    migrate_before_new(&pool).await;
    seed_previous_schema(&pool).await;
    migrate_all(&pool).await;
    pool
}

#[tokio::test]
async fn upgrade_preserves_sources_their_group_memberships_and_rules() {
    let pool = upgraded().await;

    let pivot: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT source_id, group_id FROM blocklist_source_groups ORDER BY source_id, group_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(pivot, vec![(1, 2), (1, 3), (2, 3)]);

    let sources: Vec<(i64, String, Option<String>, bool)> =
        sqlx::query_as("SELECT id, name, url, enabled FROM blocklist_sources ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        sources,
        vec![
            (
                1,
                "hagezi".into(),
                Some("https://a.example/list".into()),
                true
            ),
            (2, "oisd".into(), None, false),
        ]
    );

    let whitelist = SqliteWhitelistSourceRepository::new(pool.clone());
    assert_eq!(
        whitelist.get_by_id(1).await.unwrap().unwrap().group_ids,
        vec![2, 3]
    );

    let rules: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM managed_domains")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rules, 1);
    let violations: Vec<(String,)> = sqlx::query_as("PRAGMA foreign_key_check")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(violations.is_empty(), "{violations:?}");
}

#[tokio::test]
async fn a_group_with_logged_queries_and_list_memberships_can_be_deleted() {
    for pool in [upgraded().await, db::migrated_pool().await] {
        sqlx::raw_sql(
            "INSERT OR IGNORE INTO groups (id, name) VALUES (3, 'Office');
             INSERT INTO query_log (domain, record_type, client_ip, group_id)
                 VALUES ('c.example', 'A', '10.0.0.3', 3);
             INSERT INTO whitelist_sources (name) VALUES ('first-group-3');
             INSERT INTO whitelist_source_groups (source_id, group_id)
                 SELECT id, 3 FROM whitelist_sources WHERE name = 'first-group-3';",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query("DELETE FROM groups WHERE id = 3")
            .execute(&pool)
            .await
            .expect("history and list memberships must not pin a group");

        let orphaned: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM query_log WHERE domain = 'c.example' AND group_id IS NULL",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(orphaned, 1, "the logged query survives without attribution");
    }
}

#[tokio::test]
async fn blocking_a_service_for_a_second_group_creates_that_groups_rules() {
    for pool in [upgraded().await, db::migrated_pool().await] {
        sqlx::query("INSERT OR IGNORE INTO groups (id, name) VALUES (2, 'Kids'), (3, 'Office')")
            .execute(&pool)
            .await
            .unwrap();
        let repo = SqliteManagedDomainRepository::new(pool.clone());
        let rules = vec![(
            "[YouTube] youtube.com".to_string(),
            "youtube.com".to_string(),
        )];

        repo.bulk_create_for_service("youtube", 2, rules.clone())
            .await
            .unwrap();
        let created = repo
            .bulk_create_for_service("youtube", 3, rules)
            .await
            .unwrap();

        assert_eq!(created, 1);
        let groups: Vec<i64> = sqlx::query_scalar(
            "SELECT group_id FROM managed_domains WHERE service_id = 'youtube' ORDER BY group_id",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(groups, vec![2, 3]);
    }
}

#[tokio::test]
async fn stored_subnets_are_canonicalised_and_duplicates_keep_the_oldest_row() {
    let pool = db::migrated_pool().await;
    sqlx::raw_sql(
        "INSERT INTO groups (id, name) VALUES (2, 'Kids');
         INSERT INTO client_subnets (id, subnet_cidr, group_id) VALUES
             (1, '192.168.1.5/24', 2),
             (2, '192.168.1.0/24', 1),
             (3, '2001:DB8:0:0::1/32', 1),
             (4, '10.0.0.0/8', 1);",
    )
    .execute(&pool)
    .await
    .unwrap();

    canonicalize_stored_subnets(&pool).await.unwrap();
    let rows: Vec<(i64, String, i64)> =
        sqlx::query_as("SELECT id, subnet_cidr, group_id FROM client_subnets ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();

    assert_eq!(
        rows,
        vec![
            (1, "192.168.1.0/24".into(), 2),
            (3, "2001:db8::/32".into(), 1),
            (4, "10.0.0.0/8".into(), 1),
        ]
    );
    assert_eq!(canonicalize_stored_subnets(&pool).await.unwrap(), 0);
}
