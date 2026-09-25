use ferrous_dns_infrastructure::dns::wire_response::set_relay_header;

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
