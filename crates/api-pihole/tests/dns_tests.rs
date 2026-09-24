mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test]
async fn get_blocking_returns_status() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/dns/blocking")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");

    assert!(json["blocking"].is_boolean());
    assert!(json["blocking"].as_bool().unwrap());
}

#[tokio::test]
async fn get_blocking_response_has_timer_field() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/dns/blocking")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");

    assert!(
        json.get("timer").is_some(),
        "response must contain a 'timer' field"
    );
}

async fn post_blocking(app: &axum::Router, body: &'static str) -> Value {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dns/blocking")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    serde_json::from_slice(&body).expect("json")
}

async fn blocking_enabled(app: &axum::Router) -> bool {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dns/blocking")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");
    json["blocking"].as_bool().expect("blocking must be a bool")
}

#[tokio::test]
async fn disabling_blocking_is_applied_to_the_engine() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    post_blocking(&app, r#"{"blocking":false}"#).await;

    assert!(!blocking_enabled(&app).await);
}

#[tokio::test]
async fn enabling_blocking_after_a_disable_is_applied_to_the_engine() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    post_blocking(&app, r#"{"blocking":false}"#).await;
    post_blocking(&app, r#"{"blocking":true}"#).await;

    assert!(blocking_enabled(&app).await);
}

#[tokio::test]
async fn disable_with_timer_re_enables_blocking_when_it_expires() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;
    tokio::time::pause();

    let reply = post_blocking(&app, r#"{"blocking":false,"timer":60}"#).await;
    assert_eq!(reply["timer"], 60);
    // Let the spawned timer task arm its sleep before the clock moves.
    tokio::task::yield_now().await;

    tokio::time::advance(std::time::Duration::from_secs(59)).await;
    assert!(
        !blocking_enabled(&app).await,
        "still disabled before expiry"
    );

    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    tokio::task::yield_now().await;
    assert!(blocking_enabled(&app).await, "re-enabled after expiry");
}

#[tokio::test]
async fn a_new_request_cancels_the_pending_timer() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;
    tokio::time::pause();

    post_blocking(&app, r#"{"blocking":false,"timer":60}"#).await;
    tokio::task::yield_now().await;
    post_blocking(&app, r#"{"blocking":false}"#).await;

    tokio::time::advance(std::time::Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    assert!(!blocking_enabled(&app).await);
}
