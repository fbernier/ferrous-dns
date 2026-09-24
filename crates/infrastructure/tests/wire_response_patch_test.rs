use ferrous_dns_infrastructure::dns::wire_response::{patch_wire_header, set_relay_header};

// --- patch_wire_header: a non-DO client must NEVER receive AD=1 ---

#[test]
fn patch_wire_header_clears_ad_and_writes_the_query_id() {
    // Byte 3 = 0xA3 has AD (0x20) set beside RA and an RCODE; only AD may move.
    let wire = vec![0x00, 0x00, 0x81, 0xA3, 0xCC];
    let patched = patch_wire_header(&wire, 0x1234, true).expect("holds a header");
    assert_eq!(patched[..2], [0x12, 0x34]);
    assert_eq!(patched[3], 0x83, "AD cleared, RA and RCODE untouched");
    assert_eq!(patched[4], 0xCC);
}

/// RFC 1035 §4.1.1: RD is copied from the query. The upstream exchange always
/// set it, so a cached answer carries RD=1 whatever the client asked.
#[test]
fn patch_wire_header_copies_rd_from_the_query() {
    let wire = vec![0x00, 0x00, 0x85, 0x80];
    assert_eq!(patch_wire_header(&wire, 1, false).unwrap()[2], 0x84);
    assert_eq!(
        patch_wire_header(&[0, 0, 0x84, 0x80], 1, true).unwrap()[2],
        0x85
    );
}

#[test]
fn patch_wire_header_declines_a_message_without_flags() {
    assert!(patch_wire_header(&[0xFF, 0xFF, 0x81], 0x1234, true).is_none());
}

// --- set_relay_header: raw-wire header override on the slow path ---

#[test]
fn set_relay_header_writes_id_rd_and_our_ad_verdict() {
    let mut buf = vec![0x00, 0x00, 0x81, 0x83];
    set_relay_header(&mut buf, 0xBEEF, false, true);
    assert_eq!(buf, vec![0xBE, 0xEF, 0x80, 0xA3]);
    set_relay_header(&mut buf, 0xBEEF, true, false);
    assert_eq!(buf, vec![0xBE, 0xEF, 0x81, 0x83]);
}

#[test]
fn set_relay_header_is_a_noop_on_a_buffer_without_flags() {
    let mut buf = vec![0x00, 0x00, 0x81];
    set_relay_header(&mut buf, 0xBEEF, false, true);
    assert_eq!(buf, vec![0x00, 0x00, 0x81]);
}
