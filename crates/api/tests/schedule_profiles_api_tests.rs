use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use ferrous_dns_api::create_api_router_with_openapi;
use ferrous_dns_application::ports::ScheduleProfileRepository;
use ferrous_dns_application::use_cases::{GetScheduleProfilesUseCase, ManageTimeSlotsUseCase};
use ferrous_dns_domain::ScheduleAction;
use ferrous_dns_infrastructure::repositories::schedule_profile_repository::SqliteScheduleProfileRepository;
use helpers::TestApp;
use std::sync::Arc;
use tower::ServiceExt;

mod helpers;

async fn schedule_app() -> (Router, Arc<SqliteScheduleProfileRepository>) {
    let TestApp {
        mut state, pool, ..
    } = TestApp::new().await;
    let repo = Arc::new(SqliteScheduleProfileRepository::new(pool));
    state.schedule.get_profiles = Arc::new(GetScheduleProfilesUseCase::new(repo.clone()));
    state.schedule.manage_slots = Arc::new(ManageTimeSlotsUseCase::new(repo.clone()));
    (create_api_router_with_openapi(state).0, repo)
}

async fn delete(app: &Router, uri: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn delete_slot_only_removes_slots_of_the_addressed_profile() {
    let (app, repo) = schedule_app().await;
    let owner = repo
        .create("Kids".to_string(), "UTC".to_string(), None)
        .await
        .unwrap();
    let other = repo
        .create("Work".to_string(), "UTC".to_string(), None)
        .await
        .unwrap();
    let (owner_id, other_id) = (owner.id.unwrap(), other.id.unwrap());
    let slot = repo
        .add_slot(
            owner_id,
            0b0111_1111,
            "08:00".to_string(),
            "17:00".to_string(),
            ScheduleAction::BlockAll,
        )
        .await
        .unwrap();
    let slot_id = slot.id.unwrap();

    let status = delete(
        &app,
        &format!("/schedule-profiles/{other_id}/slots/{slot_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(repo.get_slots(owner_id).await.unwrap().len(), 1);

    let status = delete(
        &app,
        &format!("/schedule-profiles/{owner_id}/slots/{slot_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(repo.get_slots(owner_id).await.unwrap().is_empty());
}
