use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver, PtrRecordRegistry};
use ferrous_dns_domain::{DnsQuery, DomainError, LocalDnsRecord, RecordType};
use ferrous_dns_infrastructure::dns::resolver::{LocalPtrResolver, PtrMap, PtrRegistry};
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::Name;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

struct MockInner;

#[async_trait]
impl DnsResolver for MockInner {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        Err(DomainError::NxDomain)
    }
}

fn make_record(hostname: &str, domain: &str, ip: &str, record_type: &str) -> LocalDnsRecord {
    LocalDnsRecord {
        hostname: hostname.to_string(),
        domain: Some(domain.to_string()),
        ip: ip.parse().unwrap(),
        record_type: record_type.parse().unwrap(),
        ttl: Some(300),
    }
}

fn resolver_with(records: &[LocalDnsRecord], inner: Arc<dyn DnsResolver>) -> LocalPtrResolver {
    LocalPtrResolver::new(
        inner,
        LocalPtrResolver::map_from_local_records(records, Some("local")),
    )
}

fn ptr_query(reverse_name: &str) -> DnsQuery {
    DnsQuery::new(reverse_name, RecordType::PTR)
}

fn a_query(domain: &str) -> DnsQuery {
    DnsQuery::new(domain, RecordType::A)
}

#[tokio::test]
async fn test_ptr_query_for_local_record_returns_wire_data() {
    let records = vec![make_record("server", "local", "10.0.10.1", "A")];
    let inner: Arc<dyn DnsResolver> = Arc::new(MockInner);
    let resolver = resolver_with(&records, inner);

    let query = ptr_query("1.10.0.10.in-addr.arpa");
    let result = resolver.resolve(&query).await;

    assert!(result.is_ok(), "Expected Ok, got {:?}", result);
    let resolution = result.unwrap();
    assert!(
        resolution.upstream_wire_data.is_some(),
        "Expected wire data for PTR hit"
    );
    assert!(resolution.local_dns);
    assert_eq!(resolution.min_ttl, Some(300));
}

/// RFC 1035 §4.1.2: the answer carries the question it answers, which the
/// relay hands to the client as is. Stubs drop answers without one.
#[tokio::test]
async fn synthesized_ptr_answers_echo_the_question() {
    let records = vec![make_record("server", "local", "10.0.10.1", "A")];
    let resolver = resolver_with(&records, Arc::new(MockInner));

    let resolution = resolver
        .resolve(&ptr_query("1.10.0.10.in-addr.arpa"))
        .await
        .unwrap();
    let msg = Message::from_vec(&resolution.upstream_wire_data.unwrap()).unwrap();

    assert_eq!(
        msg.queries,
        [Query::query(
            Name::from_ascii("1.10.0.10.in-addr.arpa.").unwrap(),
            hickory_proto::rr::RecordType::PTR,
        )]
    );
    assert_eq!(msg.answers.len(), 1);
}

#[tokio::test]
async fn test_ptr_query_unknown_ip_passes_through() {
    let records = vec![make_record("server", "local", "10.0.10.1", "A")];
    let inner: Arc<dyn DnsResolver> = Arc::new(MockInner);
    let resolver = resolver_with(&records, inner);

    let query = ptr_query("99.10.0.10.in-addr.arpa");
    let result = resolver.resolve(&query).await;

    assert!(matches!(result, Err(DomainError::NxDomain)));
}

#[tokio::test]
async fn test_a_query_passes_through_without_touching_map() {
    let records = vec![make_record("server", "local", "10.0.10.1", "A")];
    let inner: Arc<dyn DnsResolver> = Arc::new(MockInner);
    let resolver = resolver_with(&records, inner);

    let query = a_query("server.local");
    let result = resolver.resolve(&query).await;

    assert!(matches!(result, Err(DomainError::NxDomain)));
}

#[tokio::test]
async fn test_map_from_local_records_answers_every_entry() {
    let records = vec![
        make_record("host1", "local", "10.0.0.1", "A"),
        make_record("host2", "local", "10.0.0.2", "A"),
        make_record("host3", "local", "10.0.0.3", "A"),
    ];
    let inner: Arc<dyn DnsResolver> = Arc::new(MockInner);
    let resolver = resolver_with(&records, inner);

    for reverse in [
        "1.0.0.10.in-addr.arpa",
        "2.0.0.10.in-addr.arpa",
        "3.0.0.10.in-addr.arpa",
    ] {
        let resolution = resolver.resolve(&ptr_query(reverse)).await.unwrap();
        assert!(resolution.local_dns, "{reverse} must be answered locally");
    }
}

/// Writes to the PTR map while the local layer is awaiting it.
struct RegisteringInner {
    map: Arc<PtrMap>,
    ip: IpAddr,
}

#[async_trait]
impl DnsResolver for RegisteringInner {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        self.map
            .insert(self.ip, (Arc::from("replacement.local"), 60));
        Err(DomainError::NxDomain)
    }
}

#[test]
fn test_upstream_fallback_does_not_hold_the_map_lock() {
    let ip: IpAddr = "10.0.0.7".parse().unwrap();
    let map = Arc::new(PtrMap::default());
    // A label over 63 bytes cannot be encoded, which forces the upstream fallback.
    map.insert(ip, (Arc::from(format!("{}.local", "a".repeat(64))), 60));
    let inner = Arc::new(RegisteringInner {
        map: Arc::clone(&map),
        ip,
    });
    let resolver = LocalPtrResolver::new(inner, map);

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let result = runtime.block_on(resolver.resolve(&ptr_query("7.0.0.10.in-addr.arpa")));
        let _ = done_tx.send(result);
    });

    let result = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("resolve deadlocked writing to a map shard it still held");
    assert!(matches!(result, Err(DomainError::NxDomain)));
}

#[tokio::test]
async fn test_register_adds_entry_to_map() {
    let map = LocalPtrResolver::map_from_local_records(&[], None);
    let resolver = LocalPtrResolver::new(Arc::new(MockInner), Arc::clone(&map));
    let registry = PtrRegistry::new(map);

    let ip: IpAddr = "10.0.0.5".parse().unwrap();
    registry.register(ip, Arc::from("nas.local"), 300);

    let query = ptr_query("5.0.0.10.in-addr.arpa");
    let result = resolver.resolve(&query).await;

    assert!(result.is_ok());
    assert!(result.unwrap().upstream_wire_data.is_some());
}

#[tokio::test]
async fn test_unregister_removes_entry_from_map() {
    let records = vec![make_record("server", "local", "10.0.10.1", "A")];
    let map = LocalPtrResolver::map_from_local_records(&records, None);
    let resolver = LocalPtrResolver::new(Arc::new(MockInner), Arc::clone(&map));
    let registry = PtrRegistry::new(map);

    let ip: IpAddr = "10.0.10.1".parse().unwrap();
    registry.unregister(ip);

    let query = ptr_query("1.10.0.10.in-addr.arpa");
    let result = resolver.resolve(&query).await;

    assert!(matches!(result, Err(DomainError::NxDomain)));
}
