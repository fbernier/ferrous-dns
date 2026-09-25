use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use ferrous_dns_api::create_api_router_with_openapi;
use ferrous_dns_application::ports::ScheduleProfileRepository;
use ferrous_dns_application::use_cases::{
    CreateScheduleProfileUseCase, GetScheduleProfilesUseCase, ManageTimeSlotsUseCase,
};
use ferrous_dns_domain::{ScheduleAction, TimeSlot};
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
    state.schedule.create_profile = Arc::new(CreateScheduleProfileUseCase::new(repo.clone()));
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

async fn post_json(
    app: &Router,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn create_profile_rejects_unknown_timezone() {
    let (app, repo) = schedule_app().await;

    let (status, _) = post_json(
        &app,
        "/schedule-profiles",
        serde_json::json!({ "name": "Kids", "timezone": "Mars/Olympus" }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(repo.get_all().await.unwrap().is_empty());
}

#[tokio::test]
async fn profile_and_slot_responses_keep_iana_and_hhmm_wire_format() {
    let (app, _repo) = schedule_app().await;

    let (status, profile) = post_json(
        &app,
        "/schedule-profiles",
        serde_json::json!({ "name": "Kids", "timezone": "America/Sao_Paulo" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(profile["timezone"], "America/Sao_Paulo");

    let (status, slot) = post_json(
        &app,
        &format!("/schedule-profiles/{}/slots", profile["id"]),
        serde_json::json!({
            "days": 31,
            "start_time": "09:00",
            "end_time": "18:00",
            "action": "block_all"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(slot["start_time"], "09:00");
    assert_eq!(slot["end_time"], "18:00");
}

#[tokio::test]
async fn delete_slot_only_removes_slots_of_the_addressed_profile() {
    let (app, repo) = schedule_app().await;
    let owner = repo
        .create("Kids".to_string(), chrono_tz::UTC, None)
        .await
        .unwrap();
    let other = repo
        .create("Work".to_string(), chrono_tz::UTC, None)
        .await
        .unwrap();
    let (owner_id, other_id) = (owner.id.unwrap(), other.id.unwrap());
    let slot = repo
        .add_slot(
            owner_id,
            0b0111_1111,
            TimeSlot::parse_time("08:00").unwrap(),
            TimeSlot::parse_time("17:00").unwrap(),
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
