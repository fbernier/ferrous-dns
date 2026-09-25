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
    TestApp::builder()
        .groups(&["Office", "Guest"])
        .build()
        .await
}

#[tokio::test]
async fn test_get_client_subnets_empty() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/client-subnets")
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
async fn test_create_subnet_success() {
    let app = test_app().await.router;

    let payload = json!({
        "subnet_cidr": "192.168.1.0/24",
        "group_id": 2,
        "comment": "Office network"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/client-subnets")
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
    assert_eq!(json["subnet_cidr"], "192.168.1.0/24");
    assert_eq!(json["group_id"], 2);
    assert_eq!(json["comment"], "Office network");
    assert!(json["created_at"].is_string());
}

#[tokio::test]
async fn test_create_subnet_invalid_cidr() {
    let app = test_app().await.router;

    let payload = json!({
        "subnet_cidr": "invalid-cidr",
        "group_id": 2
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/client-subnets")
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
async fn test_create_subnet_invalid_group() {
    let app = test_app().await.router;

    let payload = json!({
        "subnet_cidr": "192.168.1.0/24",
        "group_id": 999
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/client-subnets")
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
async fn test_create_subnet_duplicate() {
    let app = test_app().await.router;

    let payload = json!({
        "subnet_cidr": "192.168.1.0/24",
        "group_id": 2
    });

    let response1 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/client-subnets")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response1.status(), StatusCode::CREATED);

    let response2 = app
        .oneshot(
            Request::builder()
                .uri("/client-subnets")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response2.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_get_all_subnets_with_data() {
    let app = test_app().await.router;

    let subnets = vec![
        json!({"subnet_cidr": "192.168.1.0/24", "group_id": 2, "comment": "Office"}),
        json!({"subnet_cidr": "10.0.0.0/8", "group_id": 3, "comment": "Guest"}),
    ];

    for subnet in &subnets {
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/client-subnets")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(subnet).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    let response = app
        .oneshot(
            Request::builder()
                .uri("/client-subnets")
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
    assert_eq!(arr.len(), 2);

    assert!(arr[0]["id"].is_number());
    assert!(arr[0]["subnet_cidr"].is_string());
    assert!(arr[0]["group_id"].is_number());
    assert!(arr[0]["group_name"].is_string());
}

#[tokio::test]
async fn test_delete_subnet_success() {
    let app = test_app().await.router;

    let payload = json!({"subnet_cidr": "192.168.1.0/24", "group_id": 2});
    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/client-subnets")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let subnet_id = json["id"].as_i64().unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/client-subnets/{}", subnet_id))
                .method("DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_delete_subnet_not_found() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/client-subnets/999")
                .method("DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_create_manual_client_success() {
    let app = test_app().await.router;

    let payload = json!({
        "ip_address": "192.168.1.100",
        "group_id": 2,
        "hostname": "test-device",
        "mac_address": "aa:bb:cc:dd:ee:ff"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/clients")
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
    assert_eq!(json["ip_address"], "192.168.1.100");

    assert!(json.get("group_id").is_some());
    assert!(json.get("hostname").is_some());
    assert!(json.get("mac_address").is_some());
}

#[tokio::test]
async fn test_create_manual_client_without_group() {
    let app = test_app().await.router;

    let payload = json!({
        "ip_address": "192.168.1.101",
        "hostname": "test-device-2"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/clients")
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

    assert_eq!(json["ip_address"], "192.168.1.101");
    assert!(json["group_id"].is_null() || json["group_id"].is_number());
}

#[tokio::test]
async fn test_create_manual_client_invalid_ip() {
    let app = test_app().await.router;

    let payload = json!({
        "ip_address": "invalid-ip"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/clients")
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
async fn test_create_manual_client_invalid_group() {
    let app = test_app().await.router;

    let payload = json!({
        "ip_address": "192.168.1.100",
        "group_id": 999
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/clients")
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
async fn test_subnet_enriched_with_group_name() {
    let app = test_app().await.router;

    let payload = json!({"subnet_cidr": "192.168.1.0/24", "group_id": 2});
    app.clone()
        .oneshot(
            Request::builder()
                .uri("/client-subnets")
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
                .uri("/client-subnets")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let subnet = &json.as_array().unwrap()[0];
    assert_eq!(subnet["group_id"], 2);
    assert_eq!(subnet["group_name"], "Office");
}
