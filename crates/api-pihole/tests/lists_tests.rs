mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

const SHARED: &str = "https://shared.list/hosts";
const SHARED_ENCODED: &str = "https%3A%2F%2Fshared.list%2Fhosts";

async fn send(app: &Router, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    let builder = Request::builder().method(method).uri(uri);
    let request = match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string())),
        None => builder.body(Body::empty()),
    }
    .expect("failed to build request");

    let response = app.clone().oneshot(request).await.expect("request failed");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("invalid JSON")
    };
    (status, json)
}

async fn create(app: &Router, list_type: &str, address: &str) -> Value {
    let (status, json) = send(
        app,
        "POST",
        &format!("/lists?type={list_type}"),
        Some(json!({ "address": address })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{json}");
    json
}

/// Creates a blocklist and an allowlist that share both address and id.
async fn app_with_colliding_lists() -> (Router, i64) {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;
    let block = create(&app, "block", SHARED).await;
    let allow = create(&app, "allow", SHARED).await;
    assert_eq!(block["id"], allow["id"], "fixture relies on colliding ids");
    let id = block["id"].as_i64().expect("created list must have an id");
    (app, id)
}

fn types_of(json: &Value) -> Vec<&str> {
    json["lists"]
        .as_array()
        .expect("lists must be an array")
        .iter()
        .map(|l| l["type"].as_str().expect("type must be a string"))
        .collect()
}

#[tokio::test]
async fn list_all_returns_empty_array_on_fresh_database() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    let (status, json) = send(&app, "GET", "/lists", None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["lists"], json!([]));
}

#[tokio::test]
async fn create_list_takes_its_type_from_the_query() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    assert_eq!(
        create(&app, "block", "https://block.list/hosts").await["type"],
        "block"
    );
    assert_eq!(
        create(&app, "ALLOW", "https://allow.list/hosts").await["type"],
        "allow"
    );

    let (_, all) = send(&app, "GET", "/lists", None).await;
    assert_eq!(types_of(&all), ["block", "allow"]);
    let (_, allow_only) = send(&app, "GET", "/lists?type=allow", None).await;
    assert_eq!(
        allow_only["lists"][0]["address"],
        "https://allow.list/hosts"
    );
    assert_eq!(types_of(&allow_only), ["allow"]);
}

#[tokio::test]
async fn create_list_keeps_its_comment() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    let (status, json) = send(
        &app,
        "POST",
        "/lists?type=block",
        Some(json!({ "address": "https://commented.list", "comment": "my list" })),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(json["comment"], "my list");
}

#[tokio::test]
async fn a_missing_or_unknown_list_type_is_rejected_without_side_effects() {
    let (app, id) = app_with_colliding_lists().await;
    let body = || Some(json!({ "address": "https://new.list" }));

    for (method, uri, body) in [
        ("POST", "/lists".to_string(), body()),
        ("POST", "/lists?type=deny".to_string(), body()),
        (
            "PUT",
            format!("/lists/{id}"),
            Some(json!({ "enabled": false })),
        ),
        ("DELETE", format!("/lists/{SHARED_ENCODED}"), None),
        ("DELETE", format!("/lists/{id}?type=both"), None),
        ("GET", format!("/lists/{id}?type=both"), None),
        ("GET", "/lists?type=both".to_string(), None),
    ] {
        let (status, json) = send(&app, method, &uri, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {uri}");
        assert_eq!(json["error"]["key"], "bad_request", "{method} {uri}");
    }

    let (_, all) = send(&app, "GET", "/lists", None).await;
    assert_eq!(types_of(&all), ["block", "allow"]);
    assert!(all["lists"]
        .as_array()
        .expect("lists must be an array")
        .iter()
        .all(|l| l["enabled"] == true && l["address"] == SHARED));
}

#[tokio::test]
async fn get_resolves_colliding_lists_by_type() {
    let (app, id) = app_with_colliding_lists().await;

    for (uri, expected) in [
        (format!("/lists/{id}?type=block"), vec!["block"]),
        (format!("/lists/{id}?type=allow"), vec!["allow"]),
        (format!("/lists/{SHARED_ENCODED}?type=allow"), vec!["allow"]),
        (format!("/lists/{SHARED_ENCODED}"), vec!["block", "allow"]),
    ] {
        let (status, json) = send(&app, "GET", &uri, None).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_eq!(types_of(&json), expected, "{uri}");
        assert_eq!(json["lists"][0]["address"], SHARED, "{uri}");
    }
}

#[tokio::test]
async fn put_updates_only_the_list_of_the_given_type() {
    let (app, id) = app_with_colliding_lists().await;

    let (status, json) = send(
        &app,
        "PUT",
        &format!("/lists/{id}?type=allow"),
        Some(json!({ "comment": "allow side", "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(types_of(&json), ["allow"]);
    assert_eq!(json["lists"][0]["comment"], "allow side");

    let (_, block) = send(&app, "GET", &format!("/lists/{id}?type=block"), None).await;
    assert_eq!(block["lists"][0]["enabled"], true);
    assert!(block["lists"][0].get("comment").is_none());

    let (_, allow) = send(
        &app,
        "GET",
        &format!("/lists/{SHARED_ENCODED}?type=allow"),
        None,
    )
    .await;
    assert_eq!(allow["lists"][0]["enabled"], false);
}

#[tokio::test]
async fn delete_removes_only_the_list_of_the_given_type() {
    let (app, id) = app_with_colliding_lists().await;

    let (status, _) = send(
        &app,
        "DELETE",
        &format!("/lists/{SHARED_ENCODED}?type=block"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = send(&app, "GET", &format!("/lists/{id}?type=block"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, json) = send(&app, "GET", &format!("/lists/{id}?type=allow"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(types_of(&json), ["allow"]);

    let (status, _) = send(&app, "DELETE", &format!("/lists/{id}?type=allow"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, all) = send(&app, "GET", "/lists", None).await;
    assert_eq!(all["lists"], json!([]));
}

#[tokio::test]
async fn unknown_lists_are_not_found() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    for (method, uri) in [
        ("GET", "/lists/99999"),
        ("GET", "/lists/https%3A%2F%2Fmissing.list?type=block"),
        ("DELETE", "/lists/99999?type=block"),
    ] {
        let (status, _) = send(&app, method, uri, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}");
    }
    let (status, _) = send(
        &app,
        "PUT",
        "/lists/99999?type=allow",
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn batch_delete_removes_only_the_named_type() {
    let (app, _) = app_with_colliding_lists().await;
    create(&app, "block", "https://other.list/hosts").await;

    let (status, _) = send(
        &app,
        "POST",
        "/lists:batchDelete",
        Some(json!([
            { "item": SHARED, "type": "block" },
            { "item": "https://other.list/hosts", "type": "block" }
        ])),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, all) = send(&app, "GET", "/lists", None).await;
    assert_eq!(types_of(&all), ["allow"]);
    assert_eq!(all["lists"][0]["address"], SHARED);
}

#[tokio::test]
async fn batch_delete_with_an_unknown_type_deletes_nothing() {
    let (app, _) = app_with_colliding_lists().await;

    let (status, _) = send(
        &app,
        "POST",
        "/lists:batchDelete",
        Some(json!([
            { "item": SHARED, "type": "block" },
            { "item": SHARED, "type": "deny" }
        ])),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (_, all) = send(&app, "GET", "/lists", None).await;
    assert_eq!(types_of(&all), ["block", "allow"]);
}
