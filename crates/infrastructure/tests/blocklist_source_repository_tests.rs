use ferrous_dns_application::ports::BlocklistSourceRepository;
use ferrous_dns_domain::DomainError;
use ferrous_dns_infrastructure::repositories::blocklist_source_repository::SqliteBlocklistSourceRepository;
use sqlx::SqlitePool;

#[path = "support/db.rs"]
mod db;

async fn add_group(pool: &SqlitePool, id: i64, name: &str) {
    sqlx::query("INSERT INTO groups (id, name) VALUES (?, ?)")
        .bind(id)
        .bind(name)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_and_get_source() {
    let pool = db::migrated_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool);

    let source = repo
        .create(
            "AdGuard DNS".to_string(),
            Some("https://adguard.com/list.txt".to_string()),
            vec![1],
            Some("Ad blocking list".to_string()),
            true,
        )
        .await
        .unwrap();

    assert!(source.id.is_some());
    assert_eq!(source.name.as_ref(), "AdGuard DNS");
    assert_eq!(source.url.as_deref(), Some("https://adguard.com/list.txt"));
    assert_eq!(source.group_ids, vec![1]);
    assert_eq!(source.comment.as_deref(), Some("Ad blocking list"));
    assert!(source.enabled);
    assert!(source.created_at.is_some());
    assert!(source.updated_at.is_some());

    let fetched = repo.get_by_id(source.id.unwrap()).await.unwrap().unwrap();
    assert_eq!(fetched.name.as_ref(), "AdGuard DNS");
    assert_eq!(fetched.group_ids, vec![1]);
}

#[tokio::test]
async fn test_create_with_multiple_groups() {
    let pool = db::migrated_pool().await;

    add_group(&pool, 2, "Office").await;

    let repo = SqliteBlocklistSourceRepository::new(pool);

    let source = repo
        .create("Shared List".to_string(), None, vec![1, 2], None, true)
        .await
        .unwrap();

    assert_eq!(source.group_ids, vec![1, 2]);

    let fetched = repo.get_by_id(source.id.unwrap()).await.unwrap().unwrap();
    assert_eq!(fetched.group_ids, vec![1, 2]);
}

#[tokio::test]
async fn test_create_duplicate_group_ids_are_collapsed() {
    let pool = db::migrated_pool().await;
    add_group(&pool, 2, "Office").await;
    let repo = SqliteBlocklistSourceRepository::new(pool);

    let source = repo
        .create("Dup Groups".to_string(), None, vec![2, 1, 2], None, true)
        .await
        .unwrap();
    assert_eq!(source.group_ids, vec![1, 2]);

    let fetched = repo.get_by_id(source.id.unwrap()).await.unwrap().unwrap();
    assert_eq!(fetched.group_ids, vec![1, 2]);
}

#[tokio::test]
async fn test_create_unique_name_constraint() {
    let pool = db::migrated_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool);

    repo.create("Duplicate Name".to_string(), None, vec![1], None, true)
        .await
        .unwrap();

    let result = repo
        .create("Duplicate Name".to_string(), None, vec![1], None, false)
        .await;

    assert!(
        matches!(result, Err(DomainError::AlreadyExists(_))),
        "got {result:?}"
    );
}

#[tokio::test]
async fn test_get_all_ordered_by_name() {
    let pool = db::migrated_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool);

    repo.create("Zzz List".to_string(), None, vec![1], None, true)
        .await
        .unwrap();
    repo.create("Aaa List".to_string(), None, vec![1], None, true)
        .await
        .unwrap();
    repo.create("Mmm List".to_string(), None, vec![1], None, true)
        .await
        .unwrap();

    let sources = repo.get_all().await.unwrap();
    assert_eq!(sources.len(), 3);
    assert_eq!(sources[0].name.as_ref(), "Aaa List");
    assert_eq!(sources[1].name.as_ref(), "Mmm List");
    assert_eq!(sources[2].name.as_ref(), "Zzz List");
}

#[tokio::test]
async fn test_get_by_id_not_found() {
    let pool = db::migrated_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool);

    let result = repo.get_by_id(999).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_update_enabled_field() {
    let pool = db::migrated_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool);

    let source = repo
        .create("Toggle List".to_string(), None, vec![1], None, true)
        .await
        .unwrap();
    let id = source.id.unwrap();

    let updated = repo
        .update(id, None, None, None, None, Some(false))
        .await
        .unwrap();

    assert!(!updated.enabled);

    let fetched = repo.get_by_id(id).await.unwrap().unwrap();
    assert!(!fetched.enabled);
}

#[tokio::test]
async fn test_update_name() {
    let pool = db::migrated_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool);

    let source = repo
        .create("Old Name".to_string(), None, vec![1], None, true)
        .await
        .unwrap();

    let updated = repo
        .update(
            source.id.unwrap(),
            Some("New Name".to_string()),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

    assert_eq!(updated.name.as_ref(), "New Name");
}

#[tokio::test]
async fn test_update_group_ids() {
    let pool = db::migrated_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool.clone());

    add_group(&pool, 2, "Office").await;

    let source = repo
        .create("Group Test".to_string(), None, vec![1], None, true)
        .await
        .unwrap();

    let updated = repo
        .update(source.id.unwrap(), None, None, Some(vec![2]), None, None)
        .await
        .unwrap();

    assert_eq!(updated.group_ids, vec![2]);

    let fetched = repo.get_by_id(source.id.unwrap()).await.unwrap().unwrap();
    assert_eq!(fetched.group_ids, vec![2]);
}

#[tokio::test]
async fn test_update_assign_multiple_groups() {
    let pool = db::migrated_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool.clone());

    add_group(&pool, 2, "Office").await;

    let source = repo
        .create("Shared List".to_string(), None, vec![1], None, true)
        .await
        .unwrap();
    let id = source.id.unwrap();

    let updated = repo
        .update(id, None, None, Some(vec![1, 2]), None, None)
        .await
        .unwrap();

    assert_eq!(updated.group_ids, vec![1, 2]);

    let fetched = repo.get_by_id(id).await.unwrap().unwrap();
    assert_eq!(fetched.group_ids, vec![1, 2]);
}

#[tokio::test]
async fn test_update_duplicate_group_ids_are_collapsed() {
    let pool = db::migrated_pool().await;
    add_group(&pool, 2, "Office").await;
    let repo = SqliteBlocklistSourceRepository::new(pool);

    let id = repo
        .create("Dup Groups".to_string(), None, vec![1], None, true)
        .await
        .unwrap()
        .id
        .unwrap();

    let updated = repo
        .update(id, None, None, Some(vec![2, 2]), None, None)
        .await
        .unwrap();
    assert_eq!(updated.group_ids, vec![2]);
    assert_eq!(
        repo.get_by_id(id).await.unwrap().unwrap().group_ids,
        vec![2]
    );
}

#[tokio::test]
async fn test_update_empty_group_ids_clears_assignments() {
    let pool = db::migrated_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool);

    let id = repo
        .create("Ungrouped".to_string(), None, vec![1], None, true)
        .await
        .unwrap()
        .id
        .unwrap();

    let updated = repo
        .update(id, None, None, Some(vec![]), None, None)
        .await
        .unwrap();
    assert!(updated.group_ids.is_empty());
    assert!(repo
        .get_by_id(id)
        .await
        .unwrap()
        .unwrap()
        .group_ids
        .is_empty());
}

#[tokio::test]
async fn test_update_omitted_fields_are_kept() {
    let pool = db::migrated_pool().await;
    add_group(&pool, 2, "Office").await;
    let repo = SqliteBlocklistSourceRepository::new(pool);

    let created = repo
        .create(
            "Keep Me".to_string(),
            Some("https://example.com/list.txt".to_string()),
            vec![1, 2],
            Some("note".to_string()),
            false,
        )
        .await
        .unwrap();
    let id = created.id.unwrap();

    let updated = repo
        .update(id, Some("Renamed".to_string()), None, None, None, None)
        .await
        .unwrap();

    for source in [updated, repo.get_by_id(id).await.unwrap().unwrap()] {
        assert_eq!(source.name.as_ref(), "Renamed");
        assert_eq!(source.url.as_deref(), Some("https://example.com/list.txt"));
        assert_eq!(source.group_ids, vec![1, 2]);
        assert_eq!(source.comment.as_deref(), Some("note"));
        assert!(!source.enabled);
        assert_eq!(source.created_at, created.created_at);
    }
}

#[tokio::test]
async fn test_update_replaces_url() {
    let pool = db::migrated_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool);

    let id = repo
        .create("URL List".to_string(), None, vec![1], None, true)
        .await
        .unwrap()
        .id
        .unwrap();

    let updated = repo
        .update(
            id,
            None,
            Some(Some("https://example.com/new.txt".to_string())),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(updated.url.as_deref(), Some("https://example.com/new.txt"));
}

#[tokio::test]
async fn test_update_rename_to_existing_name() {
    let pool = db::migrated_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool);

    repo.create("Taken".to_string(), None, vec![1], None, true)
        .await
        .unwrap();
    let id = repo
        .create("Other".to_string(), None, vec![1], None, true)
        .await
        .unwrap()
        .id
        .unwrap();

    let result = repo
        .update(id, Some("Taken".to_string()), None, None, None, None)
        .await;
    assert!(
        matches!(result, Err(DomainError::AlreadyExists(_))),
        "got {result:?}"
    );
}

#[tokio::test]
async fn test_get_all_attaches_each_sources_groups() {
    let pool = db::migrated_pool().await;
    add_group(&pool, 2, "Office").await;
    add_group(&pool, 3, "Kids").await;
    let repo = SqliteBlocklistSourceRepository::new(pool);

    repo.create("B".to_string(), None, vec![3, 1], None, true)
        .await
        .unwrap();
    repo.create("A".to_string(), None, vec![2], None, true)
        .await
        .unwrap();
    repo.create("C".to_string(), None, vec![], None, true)
        .await
        .unwrap();

    let groups: Vec<(String, Vec<i64>)> = repo
        .get_all()
        .await
        .unwrap()
        .into_iter()
        .map(|s| (s.name.to_string(), s.group_ids))
        .collect();
    assert_eq!(
        groups,
        vec![
            ("A".to_string(), vec![2]),
            ("B".to_string(), vec![1, 3]),
            ("C".to_string(), vec![]),
        ]
    );
}

#[tokio::test]
async fn test_update_not_found() {
    let pool = db::migrated_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool);

    let result = repo.update(999, None, None, None, None, Some(false)).await;

    assert!(matches!(
        result,
        Err(DomainError::BlocklistSourceNotFound(999))
    ));
}

#[tokio::test]
async fn test_update_clear_url() {
    let pool = db::migrated_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool);

    let source = repo
        .create(
            "URL List".to_string(),
            Some("https://example.com/list.txt".to_string()),
            vec![1],
            None,
            true,
        )
        .await
        .unwrap();

    let updated = repo
        .update(source.id.unwrap(), None, Some(None), None, None, None)
        .await
        .unwrap();

    assert!(updated.url.is_none());
}

#[tokio::test]
async fn test_delete_success() {
    let pool = db::migrated_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool);

    let source = repo
        .create("To Delete".to_string(), None, vec![1], None, true)
        .await
        .unwrap();
    let id = source.id.unwrap();

    repo.delete(id).await.unwrap();

    let fetched = repo.get_by_id(id).await.unwrap();
    assert!(fetched.is_none());
}

#[tokio::test]
async fn test_delete_cascades_pivot_rows() {
    let pool = db::migrated_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool.clone());

    add_group(&pool, 2, "Office").await;

    let source = repo
        .create("Multi Group List".to_string(), None, vec![1, 2], None, true)
        .await
        .unwrap();
    let id = source.id.unwrap();

    repo.delete(id).await.unwrap();

    let pivot_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM blocklist_source_groups WHERE source_id = ?")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(pivot_count, 0);
}

#[tokio::test]
async fn test_delete_not_found() {
    let pool = db::migrated_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool);

    let result = repo.delete(999).await;
    assert!(matches!(
        result,
        Err(DomainError::BlocklistSourceNotFound(999))
    ));
}

#[tokio::test]
async fn test_deleting_a_sources_first_group_only_drops_that_membership() {
    let pool = db::migrated_pool().await;
    add_group(&pool, 2, "Office").await;
    add_group(&pool, 3, "Kids").await;
    let repo = SqliteBlocklistSourceRepository::new(pool.clone());
    let id = repo
        .create("FK Test List".to_string(), None, vec![2, 3], None, true)
        .await
        .unwrap()
        .id
        .unwrap();

    sqlx::query("DELETE FROM groups WHERE id = 2")
        .execute(&pool)
        .await
        .expect("group membership lives in the pivot, which cascades");

    let source = repo.get_by_id(id).await.unwrap().unwrap();
    assert_eq!(source.group_ids, vec![3]);
}
