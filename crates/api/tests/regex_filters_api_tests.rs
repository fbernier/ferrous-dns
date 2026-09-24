use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use helpers::TestApp;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

mod helpers;

async fn test_app() -> TestApp {
    TestApp::builder().groups(&["Office"]).build().await
}

#[tokio::test]
async fn test_get_all_regex_filters_empty() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(json.is_array());
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_create_regex_filter_deny_success() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Block Ads",
        "pattern": "^ads\\..*\\.com$",
        "action": "deny",
        "group_id": 1,
        "comment": "Block ad domains",
        "enabled": true
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json["id"].is_number());
    assert_eq!(json["name"], "Block Ads");
    assert_eq!(json["pattern"], "^ads\\..*\\.com$");
    assert_eq!(json["action"], "deny");
    assert_eq!(json["group_id"], 1);
    assert_eq!(json["comment"], "Block ad domains");
    assert_eq!(json["enabled"], true);
    assert!(json["created_at"].is_string());
}

#[tokio::test]
async fn test_create_regex_filter_allow_success() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Allow Safe",
        "pattern": "^safe\\.example\\.com$",
        "action": "allow",
        "group_id": 1
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["action"], "allow");
    assert_eq!(json["enabled"], true);
    assert!(json["comment"].is_null());
}

#[tokio::test]
async fn test_create_regex_filter_defaults() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Defaults Test",
        "pattern": "tracker\\..*",
        "action": "deny"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["group_id"], 1);
    assert_eq!(json["enabled"], true);
    assert!(json["comment"].is_null());
}

#[tokio::test]
async fn test_create_regex_filter_invalid_pattern() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Bad Pattern",
        "pattern": "[invalid regex(",
        "action": "deny"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_regex_filter_duplicate_name() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Duplicate",
        "pattern": "^ads\\..*",
        "action": "deny"
    });

    app.clone()
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_create_regex_filter_invalid_action() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Bad Action",
        "pattern": "^ads\\..*",
        "action": "block"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_regex_filter_invalid_group_id() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Bad Group",
        "pattern": "^ads\\..*",
        "action": "deny",
        "group_id": 999
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_regex_filter_by_id_found() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Get By ID",
        "pattern": "^tracker\\..*",
        "action": "deny"
    });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let create_body = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let created: Value = serde_json::from_slice(&create_body).unwrap();
    let id = created["id"].as_i64().unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/regex-filters/{}", id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["id"], id);
    assert_eq!(json["name"], "Get By ID");
    assert_eq!(json["pattern"], "^tracker\\..*");
    assert_eq!(json["action"], "deny");
}

#[tokio::test]
async fn test_get_regex_filter_by_id_not_found() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters/999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_update_regex_filter_toggle_enabled() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Toggle Filter",
        "pattern": "^ads\\..*",
        "action": "deny",
        "enabled": true
    });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let create_body = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let created: Value = serde_json::from_slice(&create_body).unwrap();
    let id = created["id"].as_i64().unwrap();

    let update_payload = json!({ "enabled": false });
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/regex-filters/{}", id))
                .method("PUT")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&update_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["enabled"], false);
}

#[tokio::test]
async fn test_update_regex_filter_change_pattern() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Change Pattern",
        "pattern": "^ads\\..*",
        "action": "deny"
    });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let create_body = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let created: Value = serde_json::from_slice(&create_body).unwrap();
    let id = created["id"].as_i64().unwrap();

    let update_payload = json!({ "pattern": "^tracker\\..*\\.com$" });
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/regex-filters/{}", id))
                .method("PUT")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&update_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["pattern"], "^tracker\\..*\\.com$");
}

#[tokio::test]
async fn test_update_regex_filter_invalid_pattern() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Update Invalid",
        "pattern": "^valid\\..*",
        "action": "deny"
    });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let create_body = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let created: Value = serde_json::from_slice(&create_body).unwrap();
    let id = created["id"].as_i64().unwrap();

    let update_payload = json!({ "pattern": "[invalid regex(" });
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/regex-filters/{}", id))
                .method("PUT")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&update_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_regex_filter_not_found() {
    let app = test_app().await.router;

    let update_payload = json!({ "enabled": false });
    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters/999")
                .method("PUT")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&update_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_regex_filter_success() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "To Delete",
        "pattern": "^ads\\..*",
        "action": "deny"
    });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let create_body = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let created: Value = serde_json::from_slice(&create_body).unwrap();
    let id = created["id"].as_i64().unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/regex-filters/{}", id))
                .method("DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_delete_regex_filter_not_found() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters/999")
                .method("DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_all_regex_filters_multiple() {
    let app = test_app().await.router;

    let filters = vec![
        json!({"name": "Filter A", "pattern": "^ads\\..*", "action": "deny"}),
        json!({"name": "Filter B", "pattern": "^safe\\..*", "action": "allow", "group_id": 2}),
        json!({"name": "Filter C", "pattern": "^tracker\\..*", "action": "deny"}),
    ];

    for filter in &filters {
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/regex-filters")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(filter).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(json.is_array());
    assert_eq!(json.as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn test_regex_filter_name_too_long() {
    let app = test_app().await.router;

    let long_name = "a".repeat(256);
    let payload = json!({
        "name": long_name,
        "pattern": "^ads\\..*",
        "action": "deny"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        response.status() == StatusCode::BAD_REQUEST
            || response.status() == StatusCode::CONFLICT
            || response.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected client error, got {}",
        response.status()
    );
}

#[tokio::test]
async fn test_regex_filter_empty_pattern() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Empty Pattern",
        "pattern": "",
        "action": "deny"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        response.status() == StatusCode::BAD_REQUEST
            || response.status() == StatusCode::CONFLICT
            || response.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected client error, got {}",
        response.status()
    );
}

#[tokio::test]
async fn test_regex_filter_comment_too_long() {
    let app = test_app().await.router;

    let long_comment = "c".repeat(1001);
    let payload = json!({
        "name": "Long Comment",
        "pattern": "^ads\\..*",
        "action": "deny",
        "comment": long_comment
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        response.status() == StatusCode::BAD_REQUEST
            || response.status() == StatusCode::CONFLICT
            || response.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected client error, got {}",
        response.status()
    );
}

#[tokio::test]
async fn test_regex_filter_update_group() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Group Change",
        "pattern": "^ads\\..*",
        "action": "deny",
        "group_id": 1
    });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let create_body = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let created: Value = serde_json::from_slice(&create_body).unwrap();
    let id = created["id"].as_i64().unwrap();

    let update_payload = json!({ "group_id": 2 });
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/regex-filters/{}", id))
                .method("PUT")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&update_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["group_id"], 2);
}
