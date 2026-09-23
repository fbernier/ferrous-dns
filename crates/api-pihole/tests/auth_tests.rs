mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use helpers::auth::{ADMIN_PASSWORD, APP_PASSWORD, TOTP_CODE};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

/// Sends `request` to a clone of `app` and returns the status and JSON body
/// (`Value::Null` for an empty body).
async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
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

fn post_auth(body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/auth")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("failed to build request")
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("failed to build request")
}

fn get_with_header(uri: &str, header: &str, value: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(header, value)
        .body(Body::empty())
        .expect("failed to build request")
}

/// Logs in with `password` and returns the session id.
async fn login(app: &Router, password: &str) -> String {
    let (status, json) = send(app, post_auth(serde_json::json!({ "password": password }))).await;
    assert_eq!(status, StatusCode::OK, "login failed: {json}");
    json["session"]["sid"]
        .as_str()
        .expect("sid must be a string")
        .to_string()
}

async fn auth_app(totp_enrolled: bool) -> Router {
    let pool = helpers::create_test_db().await;
    helpers::create_pihole_test_app_with_auth(pool, totp_enrolled).await
}

// ---------------------------------------------------------------------------
// GET /auth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_auth_returns_unauthenticated_session_when_no_active_session() {
    let app = auth_app(false).await;

    let (status, json) = send(&app, get("/auth")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["session"]["valid"], false);
    assert_eq!(json["session"]["totp"], false);
    assert!(json["session"]["sid"].is_null());
    assert_eq!(json["session"]["validity"], -1);
}

#[tokio::test]
async fn get_auth_reflects_a_valid_session() {
    let app = auth_app(false).await;
    let sid = login(&app, ADMIN_PASSWORD).await;

    let (status, json) = send(&app, get_with_header("/auth", "X-FTL-SID", &sid)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["session"]["valid"], true);
    assert_eq!(json["session"]["sid"], sid.as_str());
    assert!(json["session"]["validity"].as_i64().unwrap() > 0);
}

// ---------------------------------------------------------------------------
// POST /auth — password
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_with_correct_password_returns_session() {
    let app = auth_app(false).await;

    let (status, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": ADMIN_PASSWORD })),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["session"]["valid"], true);
    assert_eq!(json["session"]["message"], "password correct");
    let sid = json["session"]["sid"].as_str().expect("sid must be string");
    assert!(!sid.is_empty(), "sid must be non-empty on successful login");
    assert_eq!(json["session"]["validity"], 24 * 3600);
}

/// `cli/src/wiring/pihole_state.rs` built the state without a `LoginUseCase`,
/// which made `POST /auth` hand out a session for any password even though
/// `[auth]` is enabled.
#[tokio::test]
async fn login_rejects_wrong_password_when_auth_is_enabled() {
    let app = auth_app(false).await;

    let (status, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": "anything-at-all" })),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["session"]["valid"], false);
    assert_eq!(json["session"]["message"], "password incorrect");
    assert!(json["session"]["sid"].is_null());
}

#[tokio::test]
async fn auth_response_schema_contains_all_required_pihole_v6_session_fields() {
    let app = auth_app(false).await;

    let (_, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": ADMIN_PASSWORD })),
    )
    .await;

    let session = &json["session"];
    assert!(
        session["valid"].is_boolean(),
        "session.valid must be boolean"
    );
    assert!(session["totp"].is_boolean(), "session.totp must be boolean");
    assert!(session["sid"].is_string(), "session.sid must be string");
    assert!(
        session.get("csrf").is_some(),
        "session.csrf must be present"
    );
    assert!(
        session["validity"].is_number(),
        "session.validity must be number"
    );
    assert!(
        session["message"].is_string(),
        "session.message must be string"
    );
}

#[tokio::test]
async fn login_answers_like_a_pihole_without_password_when_auth_is_disabled() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let (status, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": "anything" })),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["session"]["valid"], true);
    assert!(json["session"]["sid"].is_null());
    assert_eq!(json["session"]["validity"], -1);
    assert_eq!(json["session"]["message"], "no password set");
}

// ---------------------------------------------------------------------------
// POST /auth — app password (API token)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_with_api_token_as_app_password_returns_session() {
    let app = auth_app(false).await;

    let (status, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": APP_PASSWORD })),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["session"]["message"], "app-password correct");
    let sid = json["session"]["sid"].as_str().expect("sid must be string");
    let (status, _) = send(&app, get_with_header("/stats/summary", "X-FTL-SID", sid)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn app_password_skips_the_second_factor() {
    let app = auth_app(true).await;

    let (status, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": APP_PASSWORD })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["session"]["valid"], true);
}

// ---------------------------------------------------------------------------
// POST /auth — second factor
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_with_totp_enrolled_requires_the_code() {
    let app = auth_app(true).await;

    let (status, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": ADMIN_PASSWORD })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"]["key"], "bad_request");
}

#[tokio::test]
async fn login_with_totp_code_as_number_returns_session() {
    let app = auth_app(true).await;
    let code: u32 = TOTP_CODE.parse().unwrap();

    let (status, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": ADMIN_PASSWORD, "totp": code })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["session"]["valid"], true);
    assert_eq!(json["session"]["totp"], true);
}

#[tokio::test]
async fn login_with_wrong_totp_code_is_unauthorized() {
    let app = auth_app(true).await;

    let (status, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": ADMIN_PASSWORD, "totp": "000000" })),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"]["key"], "unauthorized");
}

// ---------------------------------------------------------------------------
// POST /auth — lockout
// ---------------------------------------------------------------------------

/// A wrong password is tried as an app password too; that second check must
/// not count again, or the configured five attempts would shrink to three.
#[tokio::test]
async fn each_wrong_password_counts_once_toward_the_lockout() {
    let app = auth_app(false).await;
    let wrong = serde_json::json!({ "password": "wrong-password" });

    for attempt in 1..=5 {
        let (status, _) = send(&app, post_auth(wrong.clone())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "attempt {attempt}");
    }

    let (status, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": ADMIN_PASSWORD })),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json["error"]["key"], "rate_limiting");
}

// ---------------------------------------------------------------------------
// DELETE /auth — logout
// ---------------------------------------------------------------------------

#[tokio::test]
async fn logout_returns_no_content() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let request = Request::builder()
        .method("DELETE")
        .uri("/auth")
        .body(Body::empty())
        .expect("failed to build request");
    let (status, _) = send(&app, request).await;

    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn logout_invalidates_the_session() {
    let app = auth_app(false).await;
    let sid = login(&app, ADMIN_PASSWORD).await;

    let request = Request::builder()
        .method("DELETE")
        .uri("/auth")
        .header("X-FTL-SID", &sid)
        .body(Body::empty())
        .expect("failed to build request");
    let (status, _) = send(&app, request).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = send(&app, get_with_header("/stats/summary", "X-FTL-SID", &sid)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_without_a_session_is_unauthorized() {
    let app = auth_app(false).await;

    let request = Request::builder()
        .method("DELETE")
        .uri("/auth")
        .body(Body::empty())
        .expect("failed to build request");
    let (status, _) = send(&app, request).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Protected routes — everything except /auth demands a session
// ---------------------------------------------------------------------------

#[tokio::test]
async fn protected_routes_reject_requests_without_a_session() {
    let cases = [
        ("POST", "/action/gravity", None),
        ("POST", "/action/flush/logs", None),
        ("GET", "/queries", None),
        ("GET", "/stats/summary", None),
        ("GET", "/lists", None),
        (
            "POST",
            "/dns/blocking",
            Some(serde_json::json!({ "blocking": false })),
        ),
        (
            "POST",
            "/domains/deny/exact",
            Some(serde_json::json!({ "domain": "example.com" })),
        ),
    ];

    let mut open = Vec::new();
    for (method, uri, body) in cases {
        let app = auth_app(false).await;

        let body = body.map_or_else(Body::empty, |json| Body::from(json.to_string()));
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(body)
            .expect("failed to build request");
        let (status, _) = send(&app, request).await;

        if status != StatusCode::UNAUTHORIZED {
            open.push(format!("{method} {uri} -> {status}"));
        }
    }

    assert!(
        open.is_empty(),
        "routes served without a session: {open:#?}"
    );
}

#[tokio::test]
async fn protected_route_rejects_unknown_session() {
    let app = auth_app(false).await;

    let (status, json) = send(
        &app,
        get_with_header("/stats/summary", "X-FTL-SID", "not-a-session"),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"]["key"], "unauthorized");
}

#[tokio::test]
async fn protected_route_accepts_every_pihole_sid_carrier() {
    let app = auth_app(false).await;
    let sid = login(&app, ADMIN_PASSWORD).await;

    let requests = [
        get_with_header("/stats/summary", "X-FTL-SID", &sid),
        get_with_header("/stats/summary", "sid", &sid),
        get(&format!("/stats/summary?sid={sid}")),
    ];
    for request in requests {
        let uri = request.uri().clone();
        let headers = request.headers().clone();
        let (status, _) = send(&app, request).await;
        assert_eq!(status, StatusCode::OK, "{uri} {headers:?}");
    }
}

#[tokio::test]
async fn protected_routes_are_open_when_auth_is_disabled() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let (status, _) = send(&app, get("/stats/summary")).await;

    assert_eq!(status, StatusCode::OK);
}
