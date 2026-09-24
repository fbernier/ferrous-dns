#[path = "support/db.rs"]
mod db;

use chrono::NaiveTime;
use ferrous_dns_application::ports::ScheduleProfileRepository;
use ferrous_dns_domain::{DomainError, ScheduleAction, TimeSlot};
use ferrous_dns_infrastructure::repositories::schedule_profile_repository::SqliteScheduleProfileRepository;
use sqlx::SqlitePool;

fn hm(time: &str) -> NaiveTime {
    TimeSlot::parse_time(time).unwrap()
}

async fn repo() -> (SqliteScheduleProfileRepository, SqlitePool) {
    let pool = db::migrated_pool().await;
    (SqliteScheduleProfileRepository::new(pool.clone()), pool)
}

async fn profile(repo: &SqliteScheduleProfileRepository, name: &str) -> i64 {
    repo.create(name.to_string(), chrono_tz::UTC, None)
        .await
        .unwrap()
        .id
        .unwrap()
}

async fn slot(repo: &SqliteScheduleProfileRepository, pid: i64, start: &str, end: &str) -> i64 {
    repo.add_slot(pid, 31, hm(start), hm(end), ScheduleAction::BlockAll)
        .await
        .unwrap()
        .id
        .unwrap()
}

#[tokio::test]
async fn test_create_profile_returns_profile_with_id() {
    let (repo, pool) = repo().await;

    let created = repo
        .create(
            "Test".to_string(),
            chrono_tz::Europe::Lisbon,
            Some("c".to_string()),
        )
        .await
        .unwrap();

    let fetched = repo.get_by_id(created.id.unwrap()).await.unwrap().unwrap();
    assert_eq!(fetched.name.as_ref(), "Test");
    assert_eq!(fetched.timezone, chrono_tz::Europe::Lisbon);
    assert_eq!(fetched.comment.as_deref(), Some("c"));
    let (stored,): (String,) = sqlx::query_as("SELECT timezone FROM schedule_profiles")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, "Europe/Lisbon");
}

#[tokio::test]
async fn test_unparsable_stored_timezone_reads_as_utc() {
    let (repo, pool) = repo().await;
    let id = profile(&repo, "Legacy").await;
    sqlx::query("UPDATE schedule_profiles SET timezone = 'Mars/Olympus' WHERE id = ?")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();

    let fetched = repo.get_by_id(id).await.unwrap().unwrap();

    assert_eq!(fetched.timezone, chrono_tz::UTC);
    assert_eq!(repo.get_all().await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_create_profile_duplicate_name_returns_error() {
    let (repo, _pool) = repo().await;
    profile(&repo, "Dup").await;

    let result = repo.create("Dup".to_string(), chrono_tz::UTC, None).await;

    assert!(
        matches!(&result, Err(DomainError::DuplicateScheduleProfileName(n)) if n == "Dup"),
        "got {result:?}"
    );
}

#[tokio::test]
async fn test_get_by_id_nonexistent_returns_none() {
    let (repo, _pool) = repo().await;

    assert!(repo.get_by_id(999).await.unwrap().is_none());
}

#[tokio::test]
async fn test_get_all_ordered_by_name() {
    let (repo, _pool) = repo().await;
    profile(&repo, "Night").await;
    profile(&repo, "Day").await;

    let names: Vec<String> = repo
        .get_all()
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.name.to_string())
        .collect();

    assert_eq!(names, vec!["Day", "Night"]);
}

#[tokio::test]
async fn test_update_profile_name_and_timezone_keeps_comment() {
    let (repo, _pool) = repo().await;
    let id = repo
        .create("Old".to_string(), chrono_tz::UTC, Some("keep".to_string()))
        .await
        .unwrap()
        .id
        .unwrap();

    let updated = repo
        .update(
            id,
            Some("New".to_string()),
            Some(chrono_tz::Europe::Lisbon),
            None,
        )
        .await
        .unwrap();

    assert_eq!(updated.name.as_ref(), "New");
    assert_eq!(updated.timezone.name(), "Europe/Lisbon");
    assert_eq!(updated.comment.as_deref(), Some("keep"));
}

#[tokio::test]
async fn test_update_comment_only() {
    let (repo, _pool) = repo().await;
    let id = profile(&repo, "Name").await;

    let updated = repo
        .update(id, None, None, Some("note".to_string()))
        .await
        .unwrap();

    assert_eq!(updated.name.as_ref(), "Name");
    assert_eq!(updated.timezone, chrono_tz::UTC);
    assert_eq!(updated.comment.as_deref(), Some("note"));
}

#[tokio::test]
async fn test_update_missing_profile_returns_not_found() {
    let (repo, _pool) = repo().await;

    let result = repo.update(999, Some("X".to_string()), None, None).await;

    assert!(matches!(
        result,
        Err(DomainError::ScheduleProfileNotFound(999))
    ));
}

#[tokio::test]
async fn test_update_to_existing_name_returns_duplicate() {
    let (repo, _pool) = repo().await;
    profile(&repo, "Taken").await;
    let id = profile(&repo, "Other").await;

    let result = repo.update(id, Some("Taken".to_string()), None, None).await;

    assert!(matches!(
        result,
        Err(DomainError::DuplicateScheduleProfileName(_))
    ));
}

#[tokio::test]
async fn test_delete_profile_removes_slots_cascade() {
    let (repo, _pool) = repo().await;
    let id = profile(&repo, "Del").await;
    slot(&repo, id, "08:00", "17:00").await;

    repo.delete(id).await.unwrap();

    assert!(repo.get_by_id(id).await.unwrap().is_none());
    assert!(repo.get_slots(id).await.unwrap().is_empty());
}

#[tokio::test]
async fn test_delete_missing_profile_returns_not_found() {
    let (repo, _pool) = repo().await;

    assert!(matches!(
        repo.delete(999).await,
        Err(DomainError::ScheduleProfileNotFound(999))
    ));
}

#[tokio::test]
async fn test_add_slot_and_get_slots_for_profile() {
    let (repo, pool) = repo().await;
    let pid = profile(&repo, "Slots").await;

    let created = repo
        .add_slot(pid, 31, hm("09:00"), hm("18:00"), ScheduleAction::AllowAll)
        .await
        .unwrap();

    assert_eq!(created.days, 31);
    let slots = repo.get_slots(pid).await.unwrap();
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0].action, ScheduleAction::AllowAll);
    assert_eq!(slots[0].start_time, hm("09:00"));
    assert_eq!(slots[0].end_time, hm("18:00"));
    let (start, end): (String, String) =
        sqlx::query_as("SELECT start_time, end_time FROM time_slots")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!((start.as_str(), end.as_str()), ("09:00", "18:00"));
}

#[tokio::test]
async fn test_get_slots_skips_row_with_malformed_time() {
    let (repo, pool) = repo().await;
    let pid = profile(&repo, "Malformed").await;
    slot(&repo, pid, "08:00", "12:00").await;
    let bad = slot(&repo, pid, "13:00", "17:00").await;
    sqlx::query("UPDATE time_slots SET start_time = '9:00' WHERE id = ?")
        .bind(bad)
        .execute(&pool)
        .await
        .unwrap();

    let slots = repo.get_slots(pid).await.unwrap();

    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0].start_time, hm("08:00"));
}

#[tokio::test]
async fn test_add_slot_to_missing_profile_returns_not_found() {
    let (repo, _pool) = repo().await;

    let result = repo
        .add_slot(999, 31, hm("08:00"), hm("12:00"), ScheduleAction::BlockAll)
        .await;

    assert!(
        matches!(result, Err(DomainError::ScheduleProfileNotFound(999))),
        "got {result:?}"
    );
}

#[tokio::test]
async fn test_delete_slot_removes_only_that_slot() {
    let (repo, _pool) = repo().await;
    let pid = profile(&repo, "TwoSlots").await;
    let s1 = slot(&repo, pid, "08:00", "12:00").await;
    let s2 = slot(&repo, pid, "13:00", "17:00").await;

    repo.delete_slot(s1).await.unwrap();

    let slots = repo.get_slots(pid).await.unwrap();
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0].id, Some(s2));
    assert!(matches!(
        repo.delete_slot(s1).await,
        Err(DomainError::TimeSlotNotFound(_))
    ));
}

#[tokio::test]
async fn test_assign_profile_to_group_replaces_previous() {
    let (repo, _pool) = repo().await;
    let first = profile(&repo, "First").await;
    let second = profile(&repo, "Second").await;

    repo.assign_to_group(1, first).await.unwrap();
    repo.assign_to_group(1, second).await.unwrap();

    assert_eq!(repo.get_group_assignment(1).await.unwrap(), Some(second));
    assert_eq!(
        repo.get_all_group_assignments().await.unwrap(),
        vec![(1, second)]
    );
}

#[tokio::test]
async fn test_unassign_profile_from_group_leaves_profile_intact() {
    let (repo, _pool) = repo().await;
    let pid = profile(&repo, "Unassign").await;
    repo.assign_to_group(1, pid).await.unwrap();

    repo.unassign_from_group(1).await.unwrap();

    assert!(repo.get_group_assignment(1).await.unwrap().is_none());
    assert!(repo.get_by_id(pid).await.unwrap().is_some());
}

#[tokio::test]
async fn test_group_deletion_cascades_assignment() {
    let (repo, pool) = repo().await;
    sqlx::query("INSERT INTO groups (id, name) VALUES (2, 'Kids')")
        .execute(&pool)
        .await
        .unwrap();
    let pid = profile(&repo, "Bedtime").await;
    repo.assign_to_group(2, pid).await.unwrap();

    sqlx::query("DELETE FROM groups WHERE id = 2")
        .execute(&pool)
        .await
        .unwrap();

    assert!(repo.get_group_assignment(2).await.unwrap().is_none());
    assert!(repo.get_by_id(pid).await.unwrap().is_some());
}
