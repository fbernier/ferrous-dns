//! `wire_response::relay_with_edns` re-sections a cached upstream answer to
//! swap its OPT for ours (`server.rs`, when a client sends a cookie). The bytes
//! come from the upstream, or from an off-path spoofer that won the race.
//!
//! Beyond not panicking: relaying our own output again is a no-op, and when
//! hickory decodes the upstream message it decodes the relayed one to the same
//! RCODE and records under our header and OPT. Messages with a compression
//! pointer into the header are skipped for that check: RFC 1035 forbids them,
//! hickory follows them, and their target moves under the ID rewrite every
//! cached answer gets, relayed or not.
//!
//! The relay knobs come from the upstream ID, which the relay overwrites
//! anyway, so corpus entries stay plain DNS packets.
#![no_main]

use ferrous_dns_infrastructure::dns::wire_response::{self, EdnsReply};
use hickory_proto::op::Message;
use libfuzzer_sys::fuzz_target;

const ID: u16 = 0xABCD;

fuzz_target!(|upstream: &[u8]| {
    let Some(&[hi, lo]) = upstream.get(..2) else {
        return;
    };
    let knobs = u16::from_be_bytes([hi, lo]);
    let (rd, ad) = (knobs & 1 != 0, knobs & 2 != 0);
    let reply = EdnsReply {
        dnssec_ok: knobs & 4 != 0,
        cookie: (knobs & 8 != 0).then_some(&[0x55; 16]),
        ede: None,
    };
    let edns = (knobs & 16 == 0).then_some(&reply);

    let Some(relayed) = wire_response::relay_with_edns(upstream, ID, rd, ad, edns) else {
        return;
    };
    let again = wire_response::relay_with_edns(&relayed, ID, rd, ad, edns);
    assert_eq!(again.as_deref(), Some(&relayed[..]), "relay is not idempotent");

    let points_into_header = upstream
        .windows(2)
        .any(|w| w[0] >= 0xC0 && (u16::from(w[0] & 0x3F) << 8 | u16::from(w[1])) < 12);
    let Ok(source) = Message::from_vec(upstream) else {
        return;
    };
    if points_into_header {
        return;
    }
    let got = Message::from_vec(&relayed).expect("relay made a valid message invalid");
    assert_eq!((got.metadata.id, got.metadata.recursion_desired), (ID, rd));
    assert_eq!(got.metadata.authentic_data, ad);
    assert_eq!(got.metadata.response_code, source.metadata.response_code);
    assert_eq!(got.queries, source.queries);
    assert_eq!(got.answers, source.answers);
    assert_eq!(got.authorities, source.authorities);
    assert_eq!(got.additionals, source.additionals);
    assert_eq!(got.edns.map(|e| e.flags().dnssec_ok), edns.map(|e| e.dnssec_ok));
});
