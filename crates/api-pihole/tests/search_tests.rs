mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

async fn search(uri: &str) -> Value {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");
    let results = json["results"].as_array().expect("results array");
    assert_eq!(results.len(), 1, "one verdict per searched domain");
    results[0].clone()
}

#[tokio::test]
async fn allowed_domain_is_reported_as_not_blocked() {
    let result = search("/search/example.com").await;

    assert_eq!(result["domain"], "example.com");
    assert_eq!(result["type"], "allow");
    assert_eq!(result["blocked"], false);
}

#[tokio::test]
async fn regex_block_is_reported_as_regex_deny() {
    let result = search("/search/regex.blocked.test").await;

    assert_eq!(result["type"], "deny");
    assert_eq!(result["kind"], "regex");
    assert_eq!(result["blocked"], true);
}

#[tokio::test]
async fn blocklist_block_is_reported_as_exact_deny() {
    let result = search("/search/list.blocked.test").await;

    assert_eq!(result["type"], "deny");
    assert_eq!(result["kind"], "exact");
    assert_eq!(result["blocked"], true);
}

#[tokio::test]
async fn explicit_allow_is_reported_from_the_allowlist() {
    let result = search("/search/allowlisted.test").await;

    assert_eq!(result["type"], "allow");
    assert_eq!(result["source"], "allowlist");
    assert_eq!(result["blocked"], false);
}

#[tokio::test]
async fn client_parameter_selects_the_client_group() {
    let grouped = format!(
        "/search/group.blocked.test?client={}",
        helpers::MOCK_GROUPED_CLIENT
    );

    assert_eq!(search(&grouped).await["blocked"], true);
    assert_eq!(
        search("/search/group.blocked.test?client=10.0.0.99").await["blocked"],
        false
    );
    assert_eq!(
        search("/search/group.blocked.test?client=not-an-ip").await["blocked"],
        false
    );
}

#[tokio::test]
async fn domain_is_matched_case_insensitively_without_root_dot() {
    let result = search("/search/LIST.Blocked.Test.").await;

    assert_eq!(result["domain"], "list.blocked.test");
    assert_eq!(result["blocked"], true);
}
