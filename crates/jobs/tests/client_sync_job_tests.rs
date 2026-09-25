use async_trait::async_trait;
use ferrous_dns_application::ports::{ArpReader, ArpTable, HostnameResolver};
use ferrous_dns_application::use_cases::{SyncArpCacheUseCase, SyncHostnamesUseCase};
use ferrous_dns_domain::DomainError;
use ferrous_dns_jobs::ClientSyncJob;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

mod helpers;
use helpers::{make_client, MockClientRepository};

struct MockArpReader {
    table: ArpTable,
    calls: AtomicU64,
}

impl MockArpReader {
    fn with_entries(entries: Vec<(&str, &str)>) -> Self {
        Self {
            table: entries
                .into_iter()
                .map(|(ip, mac)| (ip.parse().unwrap(), mac.to_string()))
                .collect(),
            calls: AtomicU64::new(0),
        }
    }

    fn call_count(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl ArpReader for MockArpReader {
    async fn read_arp_table(&self) -> Result<ArpTable, DomainError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.table.clone())
    }
}

#[derive(Default)]
struct MockHostnameResolver {
    calls: AtomicU64,
}

impl MockHostnameResolver {
    fn call_count(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl HostnameResolver for MockHostnameResolver {
    async fn resolve_hostname(&self, _ip: IpAddr) -> Result<Option<String>, DomainError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(None)
    }
}

#[tokio::test]
async fn test_client_sync_job_runs_each_sync_on_its_own_interval() {
    let repo = Arc::new(MockClientRepository::with_clients(vec![make_client(1, "10.0.0.1")]).await);
    let arp = Arc::new(MockArpReader::with_entries(vec![(
        "10.0.0.1",
        "de:ad:be:ef:00:01",
    )]));
    // No PTR answer keeps the client pending, so every hostname tick queries the resolver.
    let resolver = Arc::new(MockHostnameResolver::default());

    let sync_arp = Arc::new(SyncArpCacheUseCase::new(arp.clone(), repo.clone()));
    let sync_hostnames = Arc::new(SyncHostnamesUseCase::new(repo.clone(), resolver.clone()));

    ClientSyncJob::new(sync_arp, sync_hostnames)
        .with_intervals(1, 3600)
        .spawn();

    sleep(Duration::from_millis(1500)).await;

    assert!(arp.call_count() >= 2);
    assert_eq!(resolver.call_count(), 1);
    let client = repo.get_client_by_ip("10.0.0.1").await.unwrap();
    assert_eq!(client.mac_address.as_deref(), Some("de:ad:be:ef:00:01"));
}
