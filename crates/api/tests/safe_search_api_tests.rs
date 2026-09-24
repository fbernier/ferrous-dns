use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use helpers::{create_test_db, TestApp};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

mod helpers;

async fn test_app() -> TestApp {
    TestApp::builder()
        .groups(&["Office"])
        .sqlite_safe_search()
        .build()
        .await
}

#[tokio::test]
async fn test_get_all_safe_search_configs_empty() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/safe-search/configs")
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
async fn test_get_safe_search_configs_by_group_empty() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/safe-search/configs/1")
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
async fn test_get_safe_search_configs_by_group_not_found() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/safe-search/configs/999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_toggle_safe_search_enable_google() {
    let app = test_app().await.router;

    let payload = json!({
        "engine": "google",
        "enabled": true,
        "youtube_mode": null
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/safe-search/configs/1")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["engine"], "google");
    assert_eq!(json["enabled"], true);
    assert_eq!(json["group_id"], 1);
}

#[tokio::test]
async fn test_toggle_safe_search_youtube_strict() {
    let app = test_app().await.router;

    let payload = json!({
        "engine": "youtube",
        "enabled": true,
        "youtube_mode": "strict"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/safe-search/configs/1")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["engine"], "youtube");
    assert_eq!(json["enabled"], true);
    assert_eq!(json["youtube_mode"], "strict");
}

#[tokio::test]
async fn test_toggle_safe_search_unknown_engine_returns_400() {
    let app = test_app().await.router;

    let payload = json!({
        "engine": "notanengine",
        "enabled": true,
        "youtube_mode": null
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/safe-search/configs/1")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_toggle_safe_search_unknown_youtube_mode_returns_400() {
    let TestApp { router, pool, .. } = test_app().await;

    let payload = json!({
        "engine": "youtube",
        "enabled": true,
        "youtube_mode": "Moderate"
    });

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/safe-search/configs/1")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM safe_search_configs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, 0, "a rejected mode must not be saved as strict");
}

#[tokio::test]
async fn test_toggle_safe_search_group_not_found() {
    let app = test_app().await.router;

    let payload = json!({
        "engine": "bing",
        "enabled": true,
        "youtube_mode": null
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/safe-search/configs/999")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_all_configs_after_toggle() {
    let pool = create_test_db().await;

    // Insert a config directly
    sqlx::query(
        "INSERT INTO safe_search_configs (group_id, engine, enabled, youtube_mode, created_at, updated_at)
         VALUES (1, 'google', 1, 'strict', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
    )
    .execute(&pool)
    .await
    .unwrap();

    let app = TestApp::builder()
        .pool(pool)
        .groups(&["Office"])
        .sqlite_safe_search()
        .build()
        .await
        .router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/safe-search/configs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(json.is_array());
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["engine"], "google");
    assert_eq!(arr[0]["enabled"], true);
}

#[tokio::test]
async fn test_delete_safe_search_configs_by_group() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/safe-search/configs/1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_delete_safe_search_configs_group_not_found() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/safe-search/configs/999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
