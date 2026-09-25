use ferrous_dns_application::ports::{BlocklistRepository, WhitelistRepository};
use ferrous_dns_domain::DomainError;
use ferrous_dns_infrastructure::repositories::blocklist_repository::SqliteBlocklistRepository;
use ferrous_dns_infrastructure::repositories::whitelist_repository::SqliteWhitelistRepository;

#[path = "support/db.rs"]
mod db;

#[tokio::test]
async fn blocklist_get_all_paged_reports_database_error() {
    let pool = db::migrated_pool().await;
    let repo = SqliteBlocklistRepository::new(pool.clone());
    pool.close().await;

    assert!(matches!(
        repo.get_all_paged(10, 0).await,
        Err(DomainError::DatabaseError(_))
    ));
}

#[tokio::test]
async fn whitelist_get_all_reports_database_error() {
    let pool = db::migrated_pool().await;
    let repo = SqliteWhitelistRepository::new(pool.clone());
    pool.close().await;

    assert!(matches!(
        repo.get_all().await,
        Err(DomainError::DatabaseError(_))
    ));
}

#[tokio::test]
async fn blocklist_get_all_tolerates_null_added_at() {
    let pool = db::migrated_pool().await;
    sqlx::query("INSERT INTO blocklist (domain, added_at) VALUES ('ads.example', NULL)")
        .execute(&pool)
        .await
        .unwrap();
    let repo = SqliteBlocklistRepository::new(pool);

    let (page, total) = repo.get_all_paged(10, 0).await.unwrap();
    assert_eq!(total, 1);
    assert_eq!(page[0].domain, "ads.example");
    assert!(page[0].added_at.is_none());
}

#[tokio::test]
async fn whitelist_get_all_tolerates_null_added_at() {
    let pool = db::migrated_pool().await;
    sqlx::query("INSERT INTO whitelist (domain, added_at) VALUES ('ok.example', NULL)")
        .execute(&pool)
        .await
        .unwrap();
    let repo = SqliteWhitelistRepository::new(pool);

    let all = repo.get_all().await.unwrap();
    assert_eq!(all.len(), 1);
    assert!(all[0].added_at.is_none());
}
