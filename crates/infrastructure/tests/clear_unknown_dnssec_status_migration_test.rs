//! `20260924000030_clear_unknown_dnssec_status`, run over a database migrated
//! to the schema before it and holding rows earlier releases wrote.

use sqlx::migrate::Migrator;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Row, SqlitePool};
use std::borrow::Cow;

const VERSION: i64 = 20260924000030;
static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

async fn pool_before_the_migration() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let earlier = Migrator {
        migrations: Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version < VERSION)
                .cloned()
                .collect(),
        ),
        ..Migrator::DEFAULT
    };
    earlier.run(&pool).await.unwrap();
    pool
}

/// Seeds raw rows and the rollups the writer kept for them.
async fn seed(pool: &SqlitePool) {
    sqlx::raw_sql(
        "INSERT INTO query_log (domain, record_type, client_ip, response_time_ms, query_source,
                                dnssec_status, created_at)
         VALUES ('nas.home.lan', 'A', '10.0.0.2', 1, 'client', 'Unknown', '2026-09-20 10:00:05'),
                ('nas.home.lan', 'A', '10.0.0.2', 1, 'client', 'Unknown', '2026-09-20 10:00:40'),
                ('example.com',  'A', '10.0.0.2', 1, 'client', 'Secure',  '2026-09-20 10:00:50'),
                ('example.org',  'A', '10.0.0.2', 1, 'client', NULL,      '2026-09-20 10:01:10');",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::raw_sql(include_str!(
        "../../../migrations/20260923000002_backfill_query_log_rollups.sql"
    ))
    .execute(pool)
    .await
    .unwrap();
}

async fn validated_per_bucket(pool: &SqlitePool) -> Vec<(i64, i64, i64)> {
    sqlx::query(
        "SELECT bucket, dnssec_validated, dnssec_secure FROM query_log_minute
         WHERE query_source = 'client' ORDER BY bucket",
    )
    .fetch_all(pool)
    .await
    .unwrap()
    .into_iter()
    .map(|r| (r.get(0), r.get(1), r.get(2)))
    .collect()
}

#[tokio::test]
async fn unknown_rows_lose_their_status_and_their_validated_count() {
    let pool = pool_before_the_migration().await;
    seed(&pool).await;
    let before = validated_per_bucket(&pool).await;
    assert_eq!(before[0].1, 3, "the backfill counted both Unknown rows");

    MIGRATOR.run(&pool).await.unwrap();

    let unknown: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM query_log WHERE dnssec_status = 'Unknown'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(unknown, 0);
    let after = validated_per_bucket(&pool).await;
    assert_eq!(
        after,
        vec![(before[0].0, 1, 1), (before[1].0, 0, 0)],
        "validated equals the sum of the outcomes again"
    );
}

#[tokio::test]
async fn a_fresh_database_migrates_cleanly() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    MIGRATOR.run(&pool).await.unwrap();
    assert!(validated_per_bucket(&pool).await.is_empty());
}
