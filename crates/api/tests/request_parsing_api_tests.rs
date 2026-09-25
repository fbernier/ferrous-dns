use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use helpers::TestApp;
use serde_json::json;
use tower::ServiceExt;

mod helpers;

async fn post_json(app: Router, uri: &str, body: serde_json::Value) -> StatusCode {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
    .unwrap()
    .status()
}

#[tokio::test]
async fn create_user_rejects_an_unknown_role() {
    let app = TestApp::new().await.router;

    let status = post_json(
        app,
        "/users",
        json!({ "username": "alice", "password": "correct-horse-battery", "role": "superuser" }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn filter_test_rejects_an_unparsable_client_ip() {
    let app = TestApp::new().await.router;

    let status = post_json(
        app,
        "/block-filter/test",
        json!({ "domain": "ads.example.com", "client": "10.0.0.300" }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}
