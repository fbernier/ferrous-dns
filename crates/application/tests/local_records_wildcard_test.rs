//! Wildcard local DNS records (issue #223) at the use-case level: validation of
//! the hostname, and routing each record to the side that can actually answer it
//! — the wildcard index for `*`, the PTR map and DNS cache for an exact name.

use async_trait::async_trait;
use ferrous_dns_application::ports::{ConfigRepository, PtrRecordRegistry, WildcardRecordRegistry};
use ferrous_dns_application::use_cases::{
    CreateLocalRecordUseCase, DeleteLocalRecordUseCase, UpdateLocalRecordUseCase,
};
use ferrous_dns_domain::{Config, DomainError, LocalDnsRecord, LocalRecordType};
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

#[derive(Default)]
struct MockWildcardRegistry {
    registered: Mutex<Vec<(String, LocalRecordType, IpAddr, u32)>>,
    unregistered: Mutex<Vec<(String, LocalRecordType)>>,
}

impl MockWildcardRegistry {
    fn new_arc() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

impl WildcardRecordRegistry for MockWildcardRegistry {
    fn register(&self, suffix: &str, record_type: LocalRecordType, address: IpAddr, ttl: u32) {
        self.registered
            .lock()
            .unwrap()
            .push((suffix.to_string(), record_type, address, ttl));
    }

    fn unregister(&self, suffix: &str, record_type: LocalRecordType) {
        self.unregistered
            .lock()
            .unwrap()
            .push((suffix.to_string(), record_type));
    }
}

#[derive(Default)]
struct MockPtrRegistry {
    registered: Mutex<Vec<(IpAddr, String, u32)>>,
    unregistered: Mutex<Vec<IpAddr>>,
}

impl MockPtrRegistry {
    fn new_arc() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

impl PtrRecordRegistry for MockPtrRegistry {
    fn register(&self, ip: IpAddr, fqdn: Arc<str>, ttl: u32) {
        self.registered
            .lock()
            .unwrap()
            .push((ip, fqdn.to_string(), ttl));
    }

    fn unregister(&self, ip: IpAddr) {
        self.unregistered.lock().unwrap().push(ip);
    }
}

fn default_config() -> Arc<RwLock<Config>> {
    Arc::new(RwLock::new(Config::default()))
}

fn config_with(record: LocalDnsRecord) -> Arc<RwLock<Config>> {
    let mut config = Config::default();
    config.dns.local_records.push(record);
    Arc::new(RwLock::new(config))
}

/// A record as the API edge hands it over: address and type already parsed.
fn new_record(hostname: &str, domain: Option<&str>, ip: &str, ttl: Option<u32>) -> LocalDnsRecord {
    LocalDnsRecord {
        hostname: hostname.to_string(),
        domain: domain.map(str::to_string),
        ip: ip.parse().unwrap(),
        record_type: LocalRecordType::A,
        ttl,
    }
}

fn wildcard_record() -> LocalDnsRecord {
    new_record("*", Some("home.lan"), "192.168.1.10", Some(300))
}

fn exact_record() -> LocalDnsRecord {
    new_record("nas", Some("home.lan"), "192.168.1.50", Some(300))
}

#[tokio::test]
async fn test_create_wildcard_registers_in_the_wildcard_index() {
    let wildcards = MockWildcardRegistry::new_arc();
    let use_case = CreateLocalRecordUseCase::new(default_config(), MockConfigRepository::ok())
        .with_wildcard_registry(wildcards.clone());

    let result = use_case
        .execute(new_record("*", Some("home.lan"), "192.168.1.10", Some(300)))
        .await;

    assert!(result.is_ok());
    let registered = wildcards.registered.lock().unwrap();
    assert_eq!(registered.len(), 1);
    assert_eq!(registered[0].0, "home.lan");
    assert_eq!(registered[0].1, LocalRecordType::A);
    assert_eq!(registered[0].2, "192.168.1.10".parse::<IpAddr>().unwrap());
    assert_eq!(registered[0].3, 300);
}

#[tokio::test]
async fn test_create_wildcard_skips_the_ptr_registry() {
    let ptr = MockPtrRegistry::new_arc();
    let use_case = CreateLocalRecordUseCase::new(default_config(), MockConfigRepository::ok())
        .with_ptr_registry(ptr.clone());

    let result = use_case
        .execute(new_record("*", Some("home.lan"), "192.168.1.10", None))
        .await;

    assert!(result.is_ok());
    assert!(
        ptr.registered.lock().unwrap().is_empty(),
        "a wildcard has no single name to reverse to"
    );
}

#[tokio::test]
async fn test_create_exact_record_leaves_the_wildcard_index_alone() {
    let wildcards = MockWildcardRegistry::new_arc();
    let use_case = CreateLocalRecordUseCase::new(default_config(), MockConfigRepository::ok())
        .with_wildcard_registry(wildcards.clone());

    let result = use_case
        .execute(new_record("nas", Some("home.lan"), "192.168.1.50", None))
        .await;

    assert!(result.is_ok());
    assert!(wildcards.registered.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_create_rejects_a_misplaced_wildcard() {
    let use_case = CreateLocalRecordUseCase::new(default_config(), MockConfigRepository::ok());

    let result = use_case
        .execute(new_record("a.*.b", Some("home.lan"), "192.168.1.10", None))
        .await;

    assert!(matches!(result, Err(DomainError::InvalidDomainName(_))));
}

#[tokio::test]
async fn test_create_rejects_an_invalid_hostname() {
    let use_case = CreateLocalRecordUseCase::new(default_config(), MockConfigRepository::ok());

    let result = use_case
        .execute(new_record("my host", None, "192.168.1.10", None))
        .await;

    assert!(matches!(result, Err(DomainError::InvalidDomainName(_))));
}

#[tokio::test]
async fn test_create_rejects_a_wildcard_in_the_domain_field() {
    let use_case = CreateLocalRecordUseCase::new(default_config(), MockConfigRepository::ok());

    let result = use_case
        .execute(new_record("nas", Some("*.home.lan"), "192.168.1.10", None))
        .await;

    assert!(matches!(result, Err(DomainError::InvalidDomainName(_))));
}

#[tokio::test]
async fn test_create_rejects_a_wildcard_with_nothing_to_anchor_it() {
    // No domain field and no dns.local_domain: the record would cover every
    // query in existence, so it is refused instead of silently stored.
    let use_case = CreateLocalRecordUseCase::new(default_config(), MockConfigRepository::ok());

    let result = use_case
        .execute(new_record("*", None, "192.168.1.10", None))
        .await;

    assert!(matches!(result, Err(DomainError::InvalidDomainName(_))));
}

#[tokio::test]
async fn test_create_wildcard_does_not_register_on_save_failure() {
    let wildcards = MockWildcardRegistry::new_arc();
    let use_case = CreateLocalRecordUseCase::new(default_config(), MockConfigRepository::failing())
        .with_wildcard_registry(wildcards.clone());

    let result = use_case
        .execute(new_record("*", Some("home.lan"), "192.168.1.10", None))
        .await;

    assert!(result.is_err());
    assert!(wildcards.registered.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_delete_wildcard_unregisters_it() {
    let wildcards = MockWildcardRegistry::new_arc();
    let ptr = MockPtrRegistry::new_arc();
    let use_case =
        DeleteLocalRecordUseCase::new(config_with(wildcard_record()), MockConfigRepository::ok())
            .with_wildcard_registry(wildcards.clone())
            .with_ptr_registry(ptr.clone());

    let result = use_case.execute(0).await;

    assert!(result.is_ok());
    let unregistered = wildcards.unregistered.lock().unwrap();
    assert_eq!(unregistered.len(), 1);
    assert_eq!(
        unregistered[0],
        ("home.lan".to_string(), LocalRecordType::A)
    );
    assert!(ptr.unregistered.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_delete_exact_record_leaves_the_wildcard_index_alone() {
    let wildcards = MockWildcardRegistry::new_arc();
    let use_case =
        DeleteLocalRecordUseCase::new(config_with(exact_record()), MockConfigRepository::ok())
            .with_wildcard_registry(wildcards.clone());

    let result = use_case.execute(0).await;

    assert!(result.is_ok());
    assert!(wildcards.unregistered.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_update_from_exact_to_wildcard_moves_the_record() {
    let wildcards = MockWildcardRegistry::new_arc();
    let ptr = MockPtrRegistry::new_arc();
    let use_case =
        UpdateLocalRecordUseCase::new(config_with(exact_record()), MockConfigRepository::ok())
            .with_wildcard_registry(wildcards.clone())
            .with_ptr_registry(ptr.clone());

    let result = use_case
        .execute(
            0,
            new_record("*", Some("home.lan"), "192.168.1.10", Some(120)),
        )
        .await;

    assert!(result.is_ok());
    // The old exact record leaves the PTR map, the new wildcard enters the index.
    assert_eq!(
        ptr.unregistered.lock().unwrap()[0],
        "192.168.1.50".parse::<IpAddr>().unwrap()
    );
    assert!(ptr.registered.lock().unwrap().is_empty());
    let registered = wildcards.registered.lock().unwrap();
    assert_eq!(registered[0].0, "home.lan");
    assert_eq!(registered[0].3, 120);
}

#[tokio::test]
async fn test_update_from_wildcard_to_exact_moves_it_back() {
    let wildcards = MockWildcardRegistry::new_arc();
    let ptr = MockPtrRegistry::new_arc();
    let use_case =
        UpdateLocalRecordUseCase::new(config_with(wildcard_record()), MockConfigRepository::ok())
            .with_wildcard_registry(wildcards.clone())
            .with_ptr_registry(ptr.clone());

    let result = use_case
        .execute(
            0,
            new_record("nas", Some("home.lan"), "192.168.1.50", Some(300)),
        )
        .await;

    assert!(result.is_ok());
    assert_eq!(
        wildcards.unregistered.lock().unwrap()[0],
        ("home.lan".to_string(), LocalRecordType::A)
    );
    assert!(wildcards.registered.lock().unwrap().is_empty());
    let registered = ptr.registered.lock().unwrap();
    assert_eq!(registered[0].1, "nas.home.lan");
}

#[tokio::test]
async fn test_update_rejects_a_misplaced_wildcard() {
    let use_case =
        UpdateLocalRecordUseCase::new(config_with(exact_record()), MockConfigRepository::ok());

    let result = use_case
        .execute(0, new_record("*x", Some("home.lan"), "192.168.1.10", None))
        .await;

    assert!(matches!(result, Err(DomainError::InvalidDomainName(_))));
}
