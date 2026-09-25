use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ferrous_dns_domain::{LocalDnsRecord, LocalRecordType};
use helpers::TestApp;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

mod helpers;

async fn test_app() -> TestApp {
    TestApp::builder().groups(&["Office"]).build().await
}

#[tokio::test]
async fn test_list_local_records_returns_empty_list() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/local-records")
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
async fn test_list_local_records_returns_preloaded_records() {
    let TestApp {
        router: app,
        config,
        ..
    } = test_app().await;

    {
        let mut cfg = config.write().await;
        cfg.dns.local_records.push(LocalDnsRecord {
            hostname: "server".to_string(),
            domain: Some("local".to_string()),
            ip: "192.168.1.10".parse().unwrap(),
            record_type: LocalRecordType::A,
            ttl: Some(300),
        });
        cfg.dns.local_records.push(LocalDnsRecord {
            hostname: "ipv6host".to_string(),
            domain: None,
            ip: "::1".parse().unwrap(),
            record_type: LocalRecordType::AAAA,
            ttl: None,
        });
    }

    let response = app
        .oneshot(
            Request::builder()
                .uri("/local-records")
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
    assert_eq!(json[0]["hostname"], "server");
    assert_eq!(json[0]["ip"], "192.168.1.10");
    assert_eq!(json[0]["record_type"], "A");
    assert_eq!(json[0]["ttl"], 300);
    assert_eq!(json[0]["fqdn"], "server.local");
    assert_eq!(json[1]["hostname"], "ipv6host");
    assert_eq!(json[1]["record_type"], "AAAA");
    assert_eq!(json[1]["ttl"], 300);
}

#[tokio::test]
async fn test_create_local_record_with_invalid_ip_returns_bad_request() {
    let app = test_app().await.router;

    let payload = json!({
        "hostname": "myserver",
        "ip": "not-an-ip-address",
        "record_type": "A"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/local-records")
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
async fn test_create_local_record_with_invalid_record_type_returns_bad_request() {
    let app = test_app().await.router;

    let payload = json!({
        "hostname": "myserver",
        "ip": "10.0.0.1",
        "record_type": "MX"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/local-records")
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
async fn test_update_local_record_with_invalid_ip_returns_bad_request() {
    let app = test_app().await.router;

    let payload = json!({
        "hostname": "myserver",
        "ip": "bad-ip",
        "record_type": "A"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/local-records/0")
                .method("PUT")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_local_record_with_invalid_record_type_returns_bad_request() {
    let app = test_app().await.router;

    let payload = json!({
        "hostname": "myserver",
        "ip": "10.0.0.1",
        "record_type": "CNAME"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/local-records/0")
                .method("PUT")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_local_record_not_found_returns_not_found() {
    let app = test_app().await.router;

    let payload = json!({
        "hostname": "myserver",
        "ip": "10.0.0.1",
        "record_type": "A"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/local-records/999")
                .method("PUT")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_local_record_not_found_returns_not_found() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/local-records/999")
                .method("DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_list_local_records_fqdn_without_domain_uses_hostname() {
    let TestApp {
        router: app,
        config,
        ..
    } = test_app().await;

    {
        let mut cfg = config.write().await;
        cfg.dns.local_records.push(LocalDnsRecord {
            hostname: "standalone".to_string(),
            domain: None,
            ip: "10.10.10.1".parse().unwrap(),
            record_type: LocalRecordType::A,
            ttl: Some(60),
        });
    }

    let response = app
        .oneshot(
            Request::builder()
                .uri("/local-records")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json[0]["fqdn"], "standalone");
    assert_eq!(json[0]["ttl"], 60);
}
