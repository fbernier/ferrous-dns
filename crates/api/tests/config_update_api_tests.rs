use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use ferrous_dns_api::create_api_router_with_openapi;
use ferrous_dns_application::ports::UpstreamReloadPort;
use ferrous_dns_domain::{DomainError, UpstreamPool};
use helpers::{create_test_db, TestApp};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::SqlitePool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tower::ServiceExt;

mod helpers;

/// The update handler resolves a config path up front and refuses to run
/// without one, so each app gets a unique writable temp file (returned too).
async fn test_app(pool: SqlitePool) -> (TestApp, String) {
    let config_path = std::env::temp_dir()
        .join(format!(
            "ferrous_cfg_update_test_{}_{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
        .to_string_lossy()
        .into_owned();
    std::fs::write(&config_path, "").unwrap();
    let app = TestApp::builder()
        .pool(pool)
        .config_path(&config_path)
        .build()
        .await;
    (app, config_path)
}

async fn post_config(app: Router, body: serde_json::Value) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/config")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

async fn get_config(app: Router) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

fn live_servers(pm: &ferrous_dns_infrastructure::dns::PoolManager) -> Vec<String> {
    pm.get_all_servers().iter().map(|a| a.to_string()).collect()
}

#[tokio::test]
async fn test_update_config_rejects_invalid_server() {
    let pool = create_test_db().await;
    let TestApp {
        router: app,
        pool_manager: pm,
        ..
    } = test_app(pool).await.0;

    let (status, json) = post_config(
        app,
        serde_json::json!({
            "dns": { "pools": [
                { "name": "p1", "strategy": "parallel", "priority": 1,
                  "servers": ["not-a-valid-endpoint"] }
            ] }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], false);
    assert!(
        json["error"].as_str().unwrap().contains("Invalid server"),
        "error should name the bad server, got: {}",
        json["error"]
    );
    // A rejected save must not touch the live pools.
    assert!(live_servers(&pm).iter().any(|s| s == "8.8.8.8:53"));
}

#[tokio::test]
async fn test_update_config_rejects_pool_with_only_blank_servers() {
    let pool = create_test_db().await;
    let TestApp {
        router: app,
        pool_manager: pm,
        ..
    } = test_app(pool).await.0;

    let (status, json) = post_config(
        app,
        serde_json::json!({
            "dns": { "pools": [
                { "name": "p1", "strategy": "parallel", "priority": 1,
                  "servers": ["", "   "] }
            ] }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], false);
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("At least one pool"),
        "blank-only servers should leave zero valid pools, got: {}",
        json["error"]
    );
    assert!(live_servers(&pm).iter().any(|s| s == "8.8.8.8:53"));
}

#[tokio::test]
async fn test_update_config_hot_applies_valid_pools_without_restart() {
    let pool = create_test_db().await;
    let TestApp {
        router: app,
        pool_manager: pm,
        ..
    } = test_app(pool).await.0;

    let (status, json) = post_config(
        app,
        serde_json::json!({
            "dns": { "pools": [
                { "name": "p1", "strategy": "parallel", "priority": 1,
                  "servers": ["udp://9.9.9.9:53"] }
            ] }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);
    // Pool-only changes are hot-applied; no restart banner.
    assert_eq!(json["restart_required"], false);

    // The live pool manager must already serve the new upstream.
    let servers = live_servers(&pm);
    assert!(
        servers.iter().any(|s| s == "9.9.9.9:53"),
        "new upstream should be live after save: {servers:?}"
    );
    assert!(
        !servers.iter().any(|s| s == "8.8.8.8:53"),
        "old upstream should be gone after hot reload: {servers:?}"
    );
}

/// Blocks `reload_pools` until released, holding a save mid-flight.
struct GatedReload {
    started: Arc<Notify>,
    release: Arc<Notify>,
}

#[async_trait::async_trait]
impl UpstreamReloadPort for GatedReload {
    async fn reload_pools(&self, _pools: Vec<UpstreamPool>) -> Result<(), DomainError> {
        self.started.notify_one();
        self.release.notified().await;
        Ok(())
    }
}

#[tokio::test]
async fn test_update_config_does_not_overwrite_a_concurrent_config_write() {
    let pool = create_test_db().await;
    let (TestApp { mut state, .. }, _path) = test_app(pool).await;
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    state.dns.reload_upstream = Arc::new(GatedReload {
        started: started.clone(),
        release: release.clone(),
    });
    let config = state.config.clone();
    let app = create_api_router_with_openapi(state).0;

    let save = tokio::spawn(post_config(
        app,
        serde_json::json!({
            "dns": { "pools": [
                { "name": "p1", "strategy": "parallel", "priority": 1,
                  "servers": ["udp://9.9.9.9:53"] }
            ] }
        }),
    ));
    started.notified().await;

    // Stands in for any other config writer, e.g. a local-record or password change.
    let writer_config = config.clone();
    let mut writer = tokio::spawn(async move {
        writer_config.write().await.dns.local_domain = Some("lan".to_string());
    });
    let writer_done = tokio::time::timeout(Duration::from_millis(100), &mut writer)
        .await
        .is_ok();
    release.notify_one();

    let (_, json) = save.await.unwrap();
    assert_eq!(json["success"], true);
    if !writer_done {
        writer.await.unwrap();
    }

    let config = config.read().await;
    assert_eq!(config.dns.local_domain.as_deref(), Some("lan"));
    assert_eq!(config.dns.pools[0].servers, ["udp://9.9.9.9:53"]);
}

#[tokio::test]
async fn test_update_config_non_pool_change_requires_restart() {
    let pool = create_test_db().await;
    let TestApp {
        router: app,
        pool_manager: pm,
        ..
    } = test_app(pool).await.0;

    // pihole_compat defaults to false; flipping it is a non-hot-applied change.
    let (status, json) = post_config(
        app,
        serde_json::json!({ "server": { "pihole_compat": true } }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);
    assert_eq!(
        json["restart_required"], true,
        "a non-pool field change must ask for a restart"
    );
    // No pools were sent, so the live pool set is untouched.
    assert!(live_servers(&pm).iter().any(|s| s == "8.8.8.8:53"));
}

#[tokio::test]
async fn test_update_config_rejects_invalid_sinkhole_ipv4() {
    let pool = create_test_db().await;
    let app = test_app(pool).await.0.router;

    let (status, json) = post_config(
        app,
        serde_json::json!({ "blocking": { "sinkhole_ipv4": "10.0.0.300" } }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], false);
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("Invalid IPv4 sinkhole address"),
        "error should name the bad sinkhole, got: {}",
        json["error"]
    );
}

#[tokio::test]
async fn test_update_config_rejects_invalid_sinkhole_ipv6() {
    let pool = create_test_db().await;
    let app = test_app(pool).await.0.router;

    let (status, json) = post_config(
        app,
        serde_json::json!({ "blocking": { "sinkhole_ipv6": "fd00::zz" } }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], false);
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("Invalid IPv6 sinkhole address"),
        "error should name the bad sinkhole, got: {}",
        json["error"]
    );
}

#[tokio::test]
async fn test_update_config_persists_then_clears_sinkhole() {
    let pool = create_test_db().await;
    let (TestApp { router: app, .. }, path) = test_app(pool).await;

    // A valid custom sinkhole is accepted and written to the config file.
    let (status, json) = post_config(
        app.clone(),
        serde_json::json!({ "blocking": { "sinkhole_ipv4": "192.168.50.50" } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(
        written.contains("192.168.50.50"),
        "config file should carry the custom sinkhole, got:\n{written}"
    );

    // An empty string clears it: the key must disappear from the file.
    let (status, json) = post_config(
        app,
        serde_json::json!({ "blocking": { "sinkhole_ipv4": "" } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);
    let cleared = std::fs::read_to_string(&path).unwrap();
    assert!(
        !cleared.contains("sinkhole_ipv4") && !cleared.contains("192.168.50.50"),
        "cleared sinkhole key must be removed from the file, got:\n{cleared}"
    );
}

#[tokio::test]
async fn test_update_config_persists_mdns_enabled() {
    let pool = create_test_db().await;
    let (TestApp { router: app, .. }, path) = test_app(pool).await;

    let (status, json) =
        post_config(app, serde_json::json!({ "dns": { "mdns_enabled": true } })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);

    // The flag must be written through to the config file under [dns].
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(
        written.contains("mdns_enabled = true"),
        "config file should carry mdns_enabled = true, got:\n{written}"
    );
}

#[tokio::test]
async fn test_get_config_reports_mdns_enabled() {
    let pool = create_test_db().await;
    let app = test_app(pool).await.0.router;

    // Default config: GET reports the flag as false.
    let (status, json) = get_config(app.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["dns"]["mdns_enabled"], false);

    // After enabling it, GET reflects the new value — covers the response DTO mapping.
    let (status, _) = post_config(
        app.clone(),
        serde_json::json!({ "dns": { "mdns_enabled": true } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, json) = get_config(app).await;
    assert_eq!(json["dns"]["mdns_enabled"], true);
}

async fn post_settings(app: Router, body: serde_json::Value) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/settings")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

#[tokio::test]
async fn test_get_config_reports_dns64_defaults() {
    let pool = create_test_db().await;
    let app = test_app(pool).await.0.router;

    let (status, json) = get_config(app).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["dns64"]["enabled"], false);
    assert_eq!(json["dns64"]["prefix"], "64:ff9b::/96");
}

#[tokio::test]
async fn test_update_settings_enables_dns64_and_persists() {
    let pool = create_test_db().await;
    let (TestApp { router: app, .. }, path) = test_app(pool).await;

    let (status, json) = post_settings(
        app.clone(),
        serde_json::json!({
            "never_forward_non_fqdn": false,
            "never_forward_reverse_lookups": false,
            "dns64_enabled": true,
            "nat64_prefix": "64:ff9b::/96"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);

    // Persisted to the config file under [dns64].
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(
        written.contains("[dns64]") && written.contains("prefix = \"64:ff9b::/96\""),
        "config file should carry the [dns64] section, got:\n{written}"
    );

    // And reflected back through GET /config (response DTO mapping).
    let (_, json) = get_config(app).await;
    assert_eq!(json["dns64"]["enabled"], true);
}

#[tokio::test]
async fn test_update_settings_rejects_invalid_dns64_prefix() {
    let pool = create_test_db().await;
    let app = test_app(pool).await.0.router;

    let (status, json) = post_settings(
        app,
        serde_json::json!({
            "never_forward_non_fqdn": false,
            "never_forward_reverse_lookups": false,
            "dns64_enabled": true,
            "nat64_prefix": "64:ff9b::/64"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], false);
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("Invalid DNS64 prefix"),
        "error should name the bad prefix, got: {}",
        json["error"]
    );
}

async fn get_settings(app: Router) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

async fn post_tls_generate(app: Router) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/tls/generate?force=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

#[tokio::test]
async fn test_restart_required_is_pending_until_the_server_restarts() {
    let pool = create_test_db().await;
    let app = test_app(pool.clone()).await.0.router;

    let (status, json) = get_config(app.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json["restart_required"], false,
        "a freshly started server has no restart pending"
    );

    let (status, json) = post_config(
        app.clone(),
        serde_json::json!({ "server": { "pihole_compat": true } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["restart_required"], true);

    // Every page asks the server, so any browser — not only the one that
    // saved — must learn that a restart is pending.
    let (_, json) = get_config(app).await;
    assert_eq!(
        json["restart_required"], true,
        "GET /config must report the pending restart after the save"
    );

    // A restart is a new process with fresh in-memory state.
    let restarted = test_app(pool).await.0.router;
    let (_, json) = get_config(restarted).await;
    assert_eq!(
        json["restart_required"], false,
        "the pending restart must not outlive the restart itself"
    );
}

#[tokio::test]
async fn test_get_config_reports_no_restart_after_pool_only_change() {
    let pool = create_test_db().await;
    let app = test_app(pool).await.0.router;

    let (status, json) = post_config(
        app.clone(),
        serde_json::json!({
            "dns": { "pools": [
                { "name": "p1", "strategy": "parallel", "priority": 1,
                  "servers": ["udp://9.9.9.9:53"] }
            ] }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);

    let (_, json) = get_config(app).await;
    assert_eq!(
        json["restart_required"], false,
        "hot-applied pools must not leave a restart pending"
    );
}

#[tokio::test]
async fn test_update_settings_change_requires_restart() {
    let pool = create_test_db().await;
    let app = test_app(pool).await.0.router;

    let (status, json) = post_settings(
        app.clone(),
        serde_json::json!({
            "never_forward_non_fqdn": false,
            "never_forward_reverse_lookups": false,
            "dns64_enabled": true,
            "nat64_prefix": "64:ff9b::/96"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);
    assert_eq!(
        json["restart_required"], true,
        "changing a DNS setting must ask for a restart"
    );

    let (_, json) = get_config(app).await;
    assert_eq!(json["restart_required"], true);
}

#[tokio::test]
async fn test_update_settings_without_changes_requires_no_restart() {
    let pool = create_test_db().await;
    let app = test_app(pool).await.0.router;

    // Saving the form exactly as loaded changes nothing.
    let (status, current) = get_settings(app.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let (status, json) = post_settings(app.clone(), current).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);
    assert_eq!(
        json["restart_required"], false,
        "an unchanged save must not ask for a restart"
    );

    let (_, json) = get_config(app).await;
    assert_eq!(json["restart_required"], false);
}

#[tokio::test]
async fn test_tls_certificate_generation_leaves_restart_pending() {
    let pool = create_test_db().await;
    let app = test_app(pool).await.0.router;

    let (status, json) = post_tls_generate(app.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["restart_required"], true);

    let (_, json) = get_config(app).await;
    assert_eq!(
        json["restart_required"], true,
        "a new certificate is only served after a restart"
    );
}
