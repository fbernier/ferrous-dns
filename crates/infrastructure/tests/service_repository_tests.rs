#[path = "support/db.rs"]
mod db;

use ferrous_dns_application::ports::{
    BlockedServiceRepository, CustomServiceRepository, SafeSearchConfigRepository,
};
use ferrous_dns_domain::{DomainError, SafeSearchEngine, YouTubeMode};
use ferrous_dns_infrastructure::repositories::{
    SqliteBlockedServiceRepository, SqliteCustomServiceRepository, SqliteSafeSearchConfigRepository,
};

#[tokio::test]
async fn test_block_service_missing_group_returns_group_not_found() {
    let repo = SqliteBlockedServiceRepository::new(db::migrated_pool().await);

    let result = repo.block_service("youtube", 999).await;

    assert!(
        matches!(result, Err(DomainError::GroupNotFound(999))),
        "got {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_block_service_twice_is_rejected() {
    let repo = SqliteBlockedServiceRepository::new(db::migrated_pool().await);
    repo.block_service("youtube", 1).await.unwrap();

    let result = repo.block_service("youtube", 1).await;

    assert!(matches!(
        result,
        Err(DomainError::BlockedServiceAlreadyExists(_))
    ));
    assert_eq!(repo.get_blocked_for_group(1).await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_unblock_missing_service_returns_not_found() {
    let repo = SqliteBlockedServiceRepository::new(db::migrated_pool().await);

    assert!(matches!(
        repo.unblock_service("youtube", 1).await,
        Err(DomainError::NotFound(_))
    ));
}

#[tokio::test]
async fn test_safe_search_upsert_round_trips_and_overwrites() {
    let repo = SqliteSafeSearchConfigRepository::new(db::migrated_pool().await);

    repo.upsert(1, SafeSearchEngine::YouTube, true, YouTubeMode::Moderate)
        .await
        .unwrap();
    repo.upsert(1, SafeSearchEngine::YouTube, false, YouTubeMode::Strict)
        .await
        .unwrap();

    let configs = repo.get_by_group(1).await.unwrap();
    assert_eq!(configs.len(), 1);
    assert_eq!(configs[0].engine, SafeSearchEngine::YouTube);
    assert!(!configs[0].enabled);
    assert_eq!(configs[0].youtube_mode, YouTubeMode::Strict);
}

#[tokio::test]
async fn test_safe_search_upsert_missing_group_returns_group_not_found() {
    let repo = SqliteSafeSearchConfigRepository::new(db::migrated_pool().await);

    let result = repo
        .upsert(999, SafeSearchEngine::Google, true, YouTubeMode::Strict)
        .await;

    assert!(
        matches!(result, Err(DomainError::GroupNotFound(999))),
        "got {result:?}"
    );
}

#[tokio::test]
async fn test_custom_service_update_omitted_fields_keep_stored_values() {
    let repo = SqliteCustomServiceRepository::new(db::migrated_pool().await);
    repo.create("svc", "Svc", "Custom", &["a.example".to_string()])
        .await
        .unwrap();

    let updated = repo
        .update("svc", Some("Renamed".to_string()), None, None)
        .await
        .unwrap();

    assert_eq!(updated.name.as_ref(), "Renamed");
    assert_eq!(updated.category_name.as_ref(), "Custom");
    assert_eq!(updated.domains, vec!["a.example".into()]);
}

#[tokio::test]
async fn test_custom_service_rename_does_not_overwrite_undecodable_domains() {
    let pool = db::migrated_pool().await;
    let repo = SqliteCustomServiceRepository::new(pool.clone());
    sqlx::query(
        "INSERT INTO custom_services (service_id, name, category_name, domains, created_at, updated_at)
         VALUES ('svc', 'Svc', 'Custom', 'not json', '2026-01-01 00:00:00', '2026-01-01 00:00:00')",
    )
    .execute(&pool)
    .await
    .unwrap();

    repo.update("svc", Some("Renamed".to_string()), None, None)
        .await
        .unwrap();

    let (domains,): (String,) =
        sqlx::query_as("SELECT domains FROM custom_services WHERE service_id = 'svc'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(domains, "not json");
}

#[tokio::test]
async fn test_custom_service_update_missing_returns_not_found() {
    let repo = SqliteCustomServiceRepository::new(db::migrated_pool().await);

    assert!(matches!(
        repo.update("nope", Some("x".to_string()), None, None).await,
        Err(DomainError::CustomServiceNotFound(_))
    ));
}

#[tokio::test]
async fn test_custom_service_duplicate_id_is_rejected() {
    let repo = SqliteCustomServiceRepository::new(db::migrated_pool().await);
    repo.create("svc", "Svc", "Custom", &[]).await.unwrap();

    assert!(matches!(
        repo.create("svc", "Other", "Custom", &[]).await,
        Err(DomainError::CustomServiceAlreadyExists(_))
    ));
}
