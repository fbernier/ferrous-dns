use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::forwarding::MessageBuilder;

#[test]
fn test_query_id_uniqueness() {
    let mut ids = std::collections::HashSet::new();

    for _ in 0..100 {
        let bytes = MessageBuilder::build_query("test.com", &RecordType::A, false).unwrap();
        ids.insert(u16::from_be_bytes([bytes[0], bytes[1]]));
    }

    assert!(ids.len() > 50, "Should generate varied IDs");
}

#[test]
fn test_dns_header_structure() {
    let bytes = MessageBuilder::build_query("test.com", &RecordType::A, false).unwrap();

    assert!(bytes.len() >= 12);

    assert_eq!(bytes[2] & 0x01, 0x01);

    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
    assert_eq!(qdcount, 1, "Should have 1 question");

    let ancount = u16::from_be_bytes([bytes[6], bytes[7]]);
    assert_eq!(ancount, 0, "Query should have 0 answers");
}
