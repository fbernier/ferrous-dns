#[path = "support/db.rs"]
mod db;

use ferrous_dns_application::ports::RegexFilterRepository;
use ferrous_dns_domain::{DomainAction, DomainError};
use ferrous_dns_infrastructure::repositories::SqliteRegexFilterRepository;

async fn repo() -> SqliteRegexFilterRepository {
    SqliteRegexFilterRepository::new(db::migrated_pool().await)
}

async fn create(repo: &SqliteRegexFilterRepository, name: &str, enabled: bool) -> i64 {
    repo.create(
        name.to_string(),
        r"^ads\.".to_string(),
        DomainAction::Allow,
        1,
        Some("note".to_string()),
        enabled,
    )
    .await
    .unwrap()
    .id
    .unwrap()
}

#[tokio::test]
async fn test_create_round_trips_action_and_enabled() {
    let repo = repo().await;
    let id = create(&repo, "f", false).await;

    let stored = repo.get_by_id(id).await.unwrap().unwrap();

    assert_eq!(stored.action, DomainAction::Allow);
    assert!(!stored.enabled);
    assert_eq!(stored.pattern.as_ref(), r"^ads\.");
}

#[tokio::test]
async fn test_create_rejects_invalid_pattern() {
    let repo = repo().await;

    let result = repo
        .create(
            "bad".to_string(),
            "(".to_string(),
            DomainAction::Deny,
            1,
            None,
            true,
        )
        .await;

    assert!(matches!(result, Err(DomainError::InvalidRegexFilter(_))));
    assert!(repo.get_all().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_create_missing_group_returns_group_not_found() {
    let repo = repo().await;

    let result = repo
        .create(
            "orphan".to_string(),
            "x".to_string(),
            DomainAction::Deny,
            999,
            None,
            true,
        )
        .await;

    assert!(
        matches!(result, Err(DomainError::GroupNotFound(999))),
        "got {result:?}"
    );
}

#[tokio::test]
async fn test_update_omitted_fields_keep_stored_values() {
    let repo = repo().await;
    let id = create(&repo, "f", true).await;

    let updated = repo
        .update(id, None, None, Some(DomainAction::Deny), None, None, None)
        .await
        .unwrap();

    assert_eq!(updated.action, DomainAction::Deny);
    assert_eq!(updated.name.as_ref(), "f");
    assert_eq!(updated.pattern.as_ref(), r"^ads\.");
    assert_eq!(updated.comment.as_deref(), Some("note"));
    assert!(updated.enabled);
}

#[tokio::test]
async fn test_update_rejects_invalid_pattern() {
    let repo = repo().await;
    let id = create(&repo, "f", true).await;

    let result = repo
        .update(id, None, Some("(".to_string()), None, None, None, None)
        .await;

    assert!(matches!(result, Err(DomainError::InvalidRegexFilter(_))));
    let stored = repo.get_by_id(id).await.unwrap().unwrap();
    assert_eq!(stored.pattern.as_ref(), r"^ads\.");
}

#[tokio::test]
async fn test_update_to_missing_group_returns_group_not_found() {
    let repo = repo().await;
    let id = create(&repo, "f", true).await;

    let result = repo
        .update(id, None, None, None, Some(999), None, None)
        .await;

    assert!(
        matches!(result, Err(DomainError::GroupNotFound(999))),
        "got {result:?}"
    );
}

#[tokio::test]
async fn test_update_missing_filter_returns_not_found() {
    let repo = repo().await;

    let result = repo
        .update(999, Some("x".to_string()), None, None, None, None, None)
        .await;

    assert!(matches!(result, Err(DomainError::RegexFilterNotFound(999))));
}

#[tokio::test]
async fn test_duplicate_name_is_rejected() {
    let repo = repo().await;
    create(&repo, "dup", true).await;

    let result = repo
        .create(
            "dup".to_string(),
            "y".to_string(),
            DomainAction::Deny,
            1,
            None,
            true,
        )
        .await;

    assert!(matches!(result, Err(DomainError::InvalidRegexFilter(_))));
}

#[tokio::test]
async fn test_get_enabled_skips_disabled() {
    let repo = repo().await;
    create(&repo, "on", true).await;
    let off = create(&repo, "off", true).await;
    repo.update(off, None, None, None, None, None, Some(false))
        .await
        .unwrap();

    let names: Vec<String> = repo
        .get_enabled()
        .await
        .unwrap()
        .into_iter()
        .map(|f| f.name.to_string())
        .collect();

    assert_eq!(names, vec!["on"]);
}
