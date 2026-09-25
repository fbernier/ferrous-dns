use ferrous_dns_application::ports::ClientRepository;
use ferrous_dns_application::use_cases::CleanupOldClientsUseCase;
use ferrous_dns_domain::Client;
use ferrous_dns_jobs::RetentionJob;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

mod helpers;
use helpers::{make_client, MockClientRepository};

fn make_old_client(id: i64, ip: &str, days_old: i64) -> Client {
    let old = (chrono::Utc::now() - chrono::Duration::days(days_old)).to_rfc3339();
    Client {
        first_seen: Some(old.clone()),
        last_seen: Some(old),
        ..make_client(id, ip)
    }
}

#[tokio::test]
async fn test_retention_job_removes_only_clients_past_retention() {
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![
            make_client(1, "192.168.1.1"),
            make_old_client(2, "192.168.1.2", 25),
            make_old_client(3, "192.168.1.3", 45),
        ])
        .await,
    );
    let use_case = Arc::new(CleanupOldClientsUseCase::new(repo.clone()));

    RetentionJob::new(use_case, 30).spawn();
    sleep(Duration::from_millis(200)).await;

    assert!(repo.get_client_by_ip("192.168.1.1").await.is_some());
    assert!(repo.get_client_by_ip("192.168.1.2").await.is_some());
    assert!(repo.get_client_by_ip("192.168.1.3").await.is_none());
}

#[tokio::test]
async fn test_retention_job_reruns_on_interval() {
    let repo = Arc::new(MockClientRepository::with_clients(Vec::new()).await);
    let use_case = Arc::new(CleanupOldClientsUseCase::new(repo.clone()));

    RetentionJob::new(use_case, 0).with_interval(1).spawn();
    sleep(Duration::from_millis(200)).await;

    repo.get_or_create("10.0.0.5".parse().unwrap())
        .await
        .unwrap();
    assert!(repo.get_client_by_ip("10.0.0.5").await.is_some());

    sleep(Duration::from_millis(1100)).await;

    assert!(
        repo.get_client_by_ip("10.0.0.5").await.is_none(),
        "the second tick should have removed a client last seen before it"
    );
}
