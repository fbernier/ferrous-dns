//! Integration tests for the domain-verdict block responder
//! (`build_blocked_wire`) for every `BlockResponseMode`.

use ferrous_dns_domain::{BlockResponseMode, DomainError};
use ferrous_dns_infrastructure::dns::ede;
use ferrous_dns_infrastructure::dns::forwarding::RecordTypeMapper;
use ferrous_dns_infrastructure::dns::server::{build_blocked_wire, BlockPolicy, ClientQuery};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

const TTL: u32 = 120;

fn name() -> Name {
    Name::from_str("ads.example.com.").unwrap()
}

fn query(record_type: RecordType) -> Query {
    Query::query(name(), record_type)
}

fn policy(mode: BlockResponseMode) -> BlockPolicy {
    BlockPolicy {
        mode,
        ttl: TTL,
        sinkhole_ipv4: None,
        sinkhole_ipv6: None,
    }
}

/// Asserts the authority section carries exactly one synthetic SOA with the
/// block TTL (so the negative answer is negatively cacheable, RFC 2308).
fn assert_soa(msg: &Message) {
    assert_eq!(msg.authorities.len(), 1, "expected one SOA in authority");
    let soa = &msg.authorities[0];
    assert_eq!(soa.ttl, TTL);
    match &soa.data {
        RData::SOA(record) => assert_eq!(record.minimum, TTL),
        other => panic!("expected SOA in authority, got {other:?}"),
    }
}

// ── build_blocked_wire ───────────────────────────────────────────────────

fn decode(mode: BlockResponseMode, record_type: RecordType) -> Message {
    decode_with(policy(mode), record_type)
}

/// Encodes `record_type`'s question and blocks it under `policy`.
fn blocked(
    policy: BlockPolicy,
    record_type: RecordType,
    edns_dnssec_ok: Option<bool>,
    ede: Option<&ede::ExtendedDnsError>,
) -> Vec<u8> {
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.add_query(query(record_type));
    let question = msg.to_vec().unwrap()[12..].to_vec();
    let query = ClientQuery::new(0x1234, true, &question, edns_dnssec_ok);
    let record_type = RecordTypeMapper::from_hickory(record_type).expect("mapped type");
    build_blocked_wire(&query, record_type, policy, ede)
}

fn decode_with(policy: BlockPolicy, record_type: RecordType) -> Message {
    Message::from_vec(&blocked(policy, record_type, None, None)).expect("valid DNS message")
}

#[test]
fn null_ip_a_query_returns_unspecified_v4_with_ttl() {
    let msg = decode(BlockResponseMode::NullIp, RecordType::A);
    assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
    assert_eq!(msg.answers.len(), 1);
    // Positive answer ⇒ no synthetic SOA.
    assert_eq!(msg.authorities.len(), 0);
    let answer = &msg.answers[0];
    assert_eq!(answer.ttl, TTL);
    match &answer.data {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::UNSPECIFIED),
        other => panic!("expected A 0.0.0.0, got {other:?}"),
    }
}

#[test]
fn null_ip_aaaa_query_returns_unspecified_v6_with_ttl() {
    let msg = decode(BlockResponseMode::NullIp, RecordType::AAAA);
    assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
    assert_eq!(msg.answers.len(), 1);
    assert_eq!(msg.authorities.len(), 0);
    let answer = &msg.answers[0];
    assert_eq!(answer.ttl, TTL);
    match &answer.data {
        RData::AAAA(aaaa) => assert_eq!(aaaa.0, Ipv6Addr::UNSPECIFIED),
        other => panic!("expected AAAA ::, got {other:?}"),
    }
}

#[test]
fn null_ip_a_query_uses_custom_sinkhole_ipv4() {
    let mut p = policy(BlockResponseMode::NullIp);
    p.sinkhole_ipv4 = Some(Ipv4Addr::new(192, 168, 1, 2));
    let msg = decode_with(p, RecordType::A);
    assert_eq!(msg.answers.len(), 1);
    match &msg.answers[0].data {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(192, 168, 1, 2)),
        other => panic!("expected custom A, got {other:?}"),
    }
}

#[test]
fn null_ip_aaaa_query_uses_custom_sinkhole_ipv6() {
    let mut p = policy(BlockResponseMode::NullIp);
    p.sinkhole_ipv6 = Some(Ipv6Addr::from_str("fd00::2").unwrap());
    let msg = decode_with(p, RecordType::AAAA);
    assert_eq!(msg.answers.len(), 1);
    match &msg.answers[0].data {
        RData::AAAA(aaaa) => assert_eq!(aaaa.0, Ipv6Addr::from_str("fd00::2").unwrap()),
        other => panic!("expected custom AAAA, got {other:?}"),
    }
}

#[test]
fn null_ip_aaaa_falls_back_to_unspecified_when_only_v4_set() {
    let mut p = policy(BlockResponseMode::NullIp);
    p.sinkhole_ipv4 = Some(Ipv4Addr::new(192, 168, 1, 2));
    let msg = decode_with(p, RecordType::AAAA);
    match &msg.answers[0].data {
        RData::AAAA(aaaa) => assert_eq!(aaaa.0, Ipv6Addr::UNSPECIFIED),
        other => panic!("expected AAAA ::, got {other:?}"),
    }
}

#[test]
fn null_ip_a_falls_back_to_unspecified_when_only_v6_set() {
    let mut p = policy(BlockResponseMode::NullIp);
    p.sinkhole_ipv6 = Some(Ipv6Addr::from_str("fd00::2").unwrap());
    let msg = decode_with(p, RecordType::A);
    match &msg.answers[0].data {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::UNSPECIFIED),
        other => panic!("expected A 0.0.0.0, got {other:?}"),
    }
}

#[test]
fn null_ip_non_address_query_is_nodata_with_soa() {
    let msg = decode(BlockResponseMode::NullIp, RecordType::MX);
    assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
    assert_eq!(msg.answers.len(), 0);
    assert_soa(&msg);
}

#[test]
fn nxdomain_mode_sets_nxdomain_with_soa_and_no_answer() {
    let msg = decode(BlockResponseMode::NxDomain, RecordType::A);
    assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(msg.answers.len(), 0);
    assert_soa(&msg);
}

#[test]
fn nodata_mode_sets_noerror_with_soa_and_no_answer() {
    let msg = decode(BlockResponseMode::NoData, RecordType::A);
    assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
    assert_eq!(msg.answers.len(), 0);
    assert_soa(&msg);
}

#[test]
fn refused_mode_sets_refused_with_no_answer() {
    let msg = decode(BlockResponseMode::Refused, RecordType::A);
    assert_eq!(msg.metadata.response_code, ResponseCode::Refused);
    assert_eq!(msg.answers.len(), 0);
    assert_eq!(msg.authorities.len(), 0);
}

#[test]
fn edns_request_gets_edns_response_with_ede() {
    let ede = ede::from_domain_error(&DomainError::Blocked);
    let wire = blocked(
        policy(BlockResponseMode::NullIp),
        RecordType::A,
        Some(false),
        ede.as_ref(),
    );
    let msg = Message::from_vec(&wire).expect("valid DNS message");
    let edns = msg
        .edns
        .expect("EDNS OPT (carrying the EDE) should be present");
    let ede = ede.unwrap();
    let mut expected = ede.info_code.to_be_bytes().to_vec();
    expected.extend_from_slice(ede.extra_text.unwrap().as_bytes());
    assert!(
        edns.options().as_ref().iter().any(|(_, opt)| matches!(
            opt,
            hickory_proto::rr::rdata::opt::EdnsOption::Unknown(15, data) if *data == expected
        )),
        "the EDE option must carry the info code and text"
    );
}

#[test]
fn non_edns_request_gets_no_opt() {
    // RFC 6891 §7: no OPT in the reply to a query that carried none.
    let msg = decode(BlockResponseMode::NullIp, RecordType::A);
    assert!(msg.edns.is_none());
}
