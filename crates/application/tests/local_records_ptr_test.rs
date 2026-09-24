use async_trait::async_trait;
use ferrous_dns_application::ports::{ConfigRepository, PtrRecordRegistry};
use ferrous_dns_application::use_cases::{
    CreateLocalRecordUseCase, DeleteLocalRecordUseCase, UpdateLocalRecordUseCase,
};
use ferrous_dns_domain::{Config, DomainError, LocalDnsRecord, LocalRecordType};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

struct MockConfigRepository {
    should_fail: bool,
}

impl MockConfigRepository {
    fn ok() -> Arc<Self> {
        Arc::new(Self { should_fail: false })
    }

    fn failing() -> Arc<Self> {
        Arc::new(Self { should_fail: true })
    }
}

#[async_trait]
impl ConfigRepository for MockConfigRepository {
    async fn save_local_records(&self, _config: &Config) -> Result<(), DomainError> {
        if self.should_fail {
            Err(DomainError::IoError("disk full".to_string()))
        } else {
            Ok(())
        }
    }
}

/// Holds the live mapping the way the real registry does, so tests assert
/// what a PTR query would see rather than which calls were made.
#[derive(Default)]
struct MockPtrRegistry {
    entries: Mutex<HashMap<IpAddr, (String, u32)>>,
}

impl MockPtrRegistry {
    fn new_arc() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn preloaded(records: &[LocalDnsRecord]) -> Arc<Self> {
        let registry = Self::new_arc();
        for record in records {
            registry.register(
                record.ip,
                Arc::from(record.fqdn(None)),
                record.ttl_or_default(),
            );
        }
        registry
    }

    fn lookup(&self, ip: &str) -> Option<(String, u32)> {
        self.entries
            .lock()
            .unwrap()
            .get(&ip.parse::<IpAddr>().unwrap())
            .cloned()
    }
}

impl PtrRecordRegistry for MockPtrRegistry {
    fn register(&self, ip: IpAddr, fqdn: Arc<str>, ttl: u32) {
        self.entries
            .lock()
            .unwrap()
            .insert(ip, (fqdn.to_string(), ttl));
    }

    fn unregister(&self, ip: IpAddr) {
        self.entries.lock().unwrap().remove(&ip);
    }
}

fn record(hostname: &str, ip: &str) -> LocalDnsRecord {
    LocalDnsRecord {
        hostname: hostname.to_string(),
        domain: Some("local".to_string()),
        ip: ip.parse().unwrap(),
        record_type: LocalRecordType::A,
        ttl: Some(300),
    }
}

fn config_with(records: &[LocalDnsRecord]) -> Arc<RwLock<Config>> {
    let mut config = Config::default();
    config.dns.local_records = records.to_vec();
    Arc::new(RwLock::new(config))
}

#[tokio::test]
async fn test_create_local_record_registers_ptr_in_registry() {
    let registry = MockPtrRegistry::new_arc();
    let use_case = CreateLocalRecordUseCase::new(config_with(&[]), MockConfigRepository::ok())
        .with_ptr_registry(registry.clone());

    let result = use_case.execute(record("nas", "10.0.10.5")).await;

    assert!(result.is_ok());
    assert_eq!(
        registry.lookup("10.0.10.5"),
        Some(("nas.local".to_string(), 300))
    );
}

#[tokio::test]
async fn test_delete_local_record_unregisters_ptr_in_registry() {
    let records = [record("host", "10.0.10.1")];
    let registry = MockPtrRegistry::preloaded(&records);
    let use_case = DeleteLocalRecordUseCase::new(config_with(&records), MockConfigRepository::ok())
        .with_ptr_registry(registry.clone());

    let result = use_case.execute(0).await;

    assert!(result.is_ok());
    assert_eq!(registry.lookup("10.0.10.1"), None);
}

#[tokio::test]
async fn test_update_local_record_swaps_ptr_in_registry() {
    let records = [record("host", "10.0.10.1")];
    let registry = MockPtrRegistry::preloaded(&records);
    let use_case = UpdateLocalRecordUseCase::new(config_with(&records), MockConfigRepository::ok())
        .with_ptr_registry(registry.clone());

    let result = use_case.execute(0, record("newhost", "10.0.10.9")).await;

    assert!(result.is_ok());
    assert_eq!(registry.lookup("10.0.10.1"), None);
    assert_eq!(
        registry.lookup("10.0.10.9"),
        Some(("newhost.local".to_string(), 300))
    );
}

#[tokio::test]
async fn test_create_local_record_does_not_register_on_save_failure() {
    let registry = MockPtrRegistry::new_arc();
    let use_case = CreateLocalRecordUseCase::new(config_with(&[]), MockConfigRepository::failing())
        .with_ptr_registry(registry.clone());

    let result = use_case.execute(record("nas", "10.0.10.5")).await;

    assert!(result.is_err());
    assert_eq!(registry.lookup("10.0.10.5"), None);
}

#[tokio::test]
async fn test_create_rejects_an_address_of_the_wrong_family() {
    let registry = MockPtrRegistry::new_arc();
    let use_case = CreateLocalRecordUseCase::new(config_with(&[]), MockConfigRepository::ok())
        .with_ptr_registry(registry.clone());

    // `record` builds an A record, so this pairs A with an IPv6 address.
    let result = use_case.execute(record("nas", "fd00::5")).await;

    assert!(matches!(result, Err(DomainError::InvalidIpAddress(_))));
    assert_eq!(registry.lookup("fd00::5"), None);
}
