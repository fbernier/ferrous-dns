use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ferrous_dns_application::ports::{BlockFilterEnginePort, FilterDecision};
use helpers::TestApp;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

mod helpers;

async fn test_app() -> TestApp {
    TestApp::builder().groups(&["Office"]).build().await
}

/// Engine whose `reload` parks until the test releases it.
///
/// `NullBlockFilterEngine::reload` returns immediately, so the sync guard would
/// clear before a second request could observe it and the 409 assertion would
/// race. This double keeps the guard held for as long as the test needs.
struct BlockingReloadEngine {
    started: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl BlockFilterEnginePort for BlockingReloadEngine {
    fn resolve_group(&self, _ip: std::net::IpAddr) -> i64 {
        1
    }
    fn check(&self, _domain: &str, _group_id: i64) -> FilterDecision {
        FilterDecision::Allow
    }
    async fn reload(&self) -> Result<(), ferrous_dns_domain::DomainError> {
        self.started.notify_one();
        self.release.notified().await;
        Ok(())
    }
    async fn load_client_groups(&self) -> Result<(), ferrous_dns_domain::DomainError> {
        Ok(())
    }
    fn compiled_domain_count(&self) -> usize {
        0
    }
    fn store_cname_decision(&self, _domain: &str, _group_id: i64, _ttl_secs: u64) {}
    fn is_blocking_enabled(&self) -> bool {
        true
    }
    fn set_blocking_enabled(&self, _enabled: bool) {}
}

#[tokio::test]
async fn test_get_all_sources_empty() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/blocklist-sources")
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
async fn test_create_source_success() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "AdGuard DNS",
        "url": "https://adguard.com/list.txt",
        "group_id": 1,
        "comment": "Main ad list",
        "enabled": true
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/blocklist-sources")
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
    assert_eq!(json["name"], "AdGuard DNS");
    assert_eq!(json["url"], "https://adguard.com/list.txt");
    assert_eq!(json["group_ids"][0], 1);
    assert_eq!(json["comment"], "Main ad list");
    assert_eq!(json["enabled"], true);
    assert!(json["created_at"].is_string());
}

#[tokio::test]
async fn test_create_source_defaults() {
    let app = test_app().await.router;

    let payload = json!({ "name": "Minimal List" });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/blocklist-sources")
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

    assert_eq!(json["name"], "Minimal List");
    assert_eq!(json["group_ids"][0], 1);
    assert_eq!(json["enabled"], true);
    assert!(json["url"].is_null());
}

#[tokio::test]
async fn test_create_source_duplicate_name() {
    let app = test_app().await.router;

    let payload = json!({ "name": "Duplicate List" });

    app.clone()
        .oneshot(
            Request::builder()
                .uri("/blocklist-sources")
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
                .uri("/blocklist-sources")
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
async fn test_create_source_invalid_url() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Bad URL List",
        "url": "ftp://not-http.com/list.txt"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/blocklist-sources")
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
async fn test_create_source_invalid_group() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Bad Group List",
        "group_id": 999
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/blocklist-sources")
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
async fn test_get_source_by_id() {
    let app = test_app().await.router;

    let payload = json!({ "name": "Get By ID List" });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/blocklist-sources")
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
                .uri(format!("/blocklist-sources/{}", id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["id"], id);
    assert_eq!(json["name"], "Get By ID List");
}

#[tokio::test]
async fn test_get_source_not_found() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/blocklist-sources/999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_update_source_toggle_enabled() {
    let app = test_app().await.router;

    let payload = json!({ "name": "Toggle List", "enabled": true });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/blocklist-sources")
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
                .uri(format!("/blocklist-sources/{}", id))
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
async fn test_update_source_null_url_clears_it_and_absent_url_keeps_it() {
    let app = test_app().await.router;

    let put = |id: i64, body: Value| {
        Request::builder()
            .uri(format!("/blocklist-sources/{id}"))
            .method("PUT")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let read_json = |response: axum::response::Response| async move {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice::<Value>(&body).unwrap()
    };

    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/blocklist-sources")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "name": "Remote List", "url": "https://example.com/a.txt" })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let id = read_json(created).await["id"].as_i64().unwrap();

    let kept = app
        .clone()
        .oneshot(put(id, json!({ "enabled": false })))
        .await
        .unwrap();
    assert_eq!(read_json(kept).await["url"], "https://example.com/a.txt");

    let cleared = app.oneshot(put(id, json!({ "url": null }))).await.unwrap();
    assert_eq!(cleared.status(), StatusCode::OK);
    assert!(read_json(cleared).await["url"].is_null());
}

#[tokio::test]
async fn test_update_source_not_found() {
    let app = test_app().await.router;

    let update_payload = json!({ "enabled": false });
    let response = app
        .oneshot(
            Request::builder()
                .uri("/blocklist-sources/999")
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
async fn test_delete_source_success() {
    let app = test_app().await.router;

    let payload = json!({ "name": "To Delete" });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/blocklist-sources")
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
                .uri(format!("/blocklist-sources/{}", id))
                .method("DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_delete_source_not_found() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/blocklist-sources/999")
                .method("DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_all_sources_after_create() {
    let app = test_app().await.router;

    let sources = vec![
        json!({"name": "List A", "url": "https://example.com/a.txt"}),
        json!({"name": "List B", "group_id": 2}),
    ];

    for source in &sources {
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/blocklist-sources")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(source).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    let response = app
        .oneshot(
            Request::builder()
                .uri("/blocklist-sources")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json.is_array());
    assert_eq!(json.as_array().unwrap().len(), 2);
}

/// Inserts a source directly so the sync tests have an id to address without
/// going through the create endpoint, which triggers a reload of its own.
async fn seed_source(pool: &sqlx::SqlitePool, name: &str) -> i64 {
    sqlx::query("INSERT INTO blocklist_sources (name, url) VALUES (?, ?)")
        .bind(name)
        .bind("https://example.com/list.txt")
        .execute(pool)
        .await
        .unwrap()
        .last_insert_rowid()
}

#[tokio::test]
async fn test_sync_sources_returns_accepted() {
    let TestApp {
        router: app, pool, ..
    } = test_app().await;
    let id = seed_source(&pool, "Syncable List").await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/blocklist-sources/{id}/sync"))
                .method("POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn test_sync_route_is_not_shadowed_by_id_route() {
    // `/blocklist-sources/{id}/sync` must reach the sync handler rather than
    // being swallowed by `/blocklist-sources/{id}`, which has no sub-path.
    let TestApp {
        router: app, pool, ..
    } = test_app().await;
    let id = seed_source(&pool, "Routed List").await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/blocklist-sources/{id}/sync"))
                .method("POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_ne!(response.status(), StatusCode::BAD_REQUEST);
    assert_ne!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn test_sync_unknown_source_returns_not_found() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/blocklist-sources/999/sync")
                .method("POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_sync_sources_conflicts_while_running() {
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let engine = Arc::new(BlockingReloadEngine {
        started: started.clone(),
        release: release.clone(),
    });

    let TestApp {
        router: app, pool, ..
    } = TestApp::builder()
        .groups(&["Office"])
        .sync_engine(engine)
        .build()
        .await;
    let id = seed_source(&pool, "Contended List").await;

    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/blocklist-sources/{id}/sync"))
                .method("POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);

    // Wait until the spawned reload is parked, so the guard is provably held
    // when the second request lands.
    started.notified().await;

    let second = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/blocklist-sources/{id}/sync"))
                .method("POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);

    release.notify_one();
}

#[tokio::test]
async fn test_create_source_has_null_last_synced_at() {
    let app = test_app().await.router;

    let payload = json!({ "name": "Never Synced List", "url": "https://example.com/a.txt" });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/blocklist-sources")
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

    // The key must exist so a rename cannot pass silently, and it must be null
    // because the source has never been fetched.
    assert!(json.get("last_synced_at").is_some());
    assert!(json["last_synced_at"].is_null());
}
