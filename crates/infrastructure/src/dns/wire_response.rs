use super::ede::{self, ExtendedDnsError};
use super::fast_path::FastPathQuery;
use std::net::IpAddr;

/// The fast path's fixed OPT: `EdnsReply` with DO clear and no options, as a
/// constant so a cache hit copies it instead of encoding it.
const OPT_RECORD: [u8; 11] = [
    0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Capacity of the fixed fast-path cache-hit response buffer. A hit that would
/// exceed it is rejected (`None`) and handled by the slow path instead.
pub const RESPONSE_BUF_LEN: usize = 523;

/// Clones the cached wire bytes under the client's query ID and RD bit, with
/// the Authenticated Data (AD) bit cleared; `None` if `wire` is shorter than
/// the flags.
///
/// The cached-wire fast path is only taken for clients that did **not** set the
/// EDNS DO bit, so per RFC 6840 §5.8 we must never assert AD to them — yet the
/// cached upstream bytes may carry AD=1 from the validating resolver. Clearing
/// it here keeps the fast path compliant without re-parsing the message.
pub fn patch_wire_header(wire: &[u8], id: u16, recursion_desired: bool) -> Option<Vec<u8>> {
    if wire.len() < 4 {
        return None;
    }
    let mut buf = wire.to_vec();
    set_relay_header(&mut buf, id, recursion_desired, false);
    Some(buf)
}

/// Rewrites a relayed response's header for the client: its ID, its RD bit
/// (RFC 1035 §4.1.1 copies RD from the query; upstream always saw RD=1) and
/// our own AD verdict (RFC 4035 bit `0x20` of byte 3). No-op on a buffer
/// shorter than the flags.
pub fn set_relay_header(buf: &mut [u8], id: u16, recursion_desired: bool, authentic_data: bool) {
    let Some([id_hi, id_lo, flags_hi, flags_lo]) = buf.first_chunk_mut::<4>() else {
        return;
    };
    [*id_hi, *id_lo] = id.to_be_bytes();
    *flags_hi = (*flags_hi & !0x01) | u8::from(recursion_desired);
    *flags_lo = (*flags_lo & !0x20) | (u8::from(authentic_data) << 5);
}

/// Over UDP a cached wire answer larger than the client's advertised EDNS
/// buffer (or 512 without EDNS) must be deferred to the slow path, which
/// truncates it with TC=1 (RFC 6891 §6.2.5 / RFC 7766). Returns `true` when the
/// `wire_len` bytes fit and may be served verbatim on the fast path.
pub fn wire_fits_udp_buffer(wire_len: usize, client_max_size: u16) -> bool {
    wire_len <= client_max_size as usize
}

/// Encodes a cache hit into `out`, which may hold a previous response, and
/// returns its length. `None` if it would not fit the client or `out`.
pub fn build_cache_hit_response(
    query: &FastPathQuery,
    query_buf: &[u8],
    addresses: &[IpAddr],
    ttl: u32,
    out: &mut [u8; RESPONSE_BUF_LEN],
) -> Option<usize> {
    if addresses.is_empty() || query.question_end > query_buf.len() {
        return None;
    }

    let question_len = query.question_end - 12;

    let answers_size: usize = addresses.iter().map(address_rr_len).sum();

    let opt_size = if query.has_edns() {
        OPT_RECORD.len()
    } else {
        0
    };
    let total_size = 12 + question_len + answers_size + opt_size;
    let max_size = query.client_max_size as usize;

    // `max_size` is the client's EDNS-advertised buffer (up to 65535), so the
    // size check alone does NOT bound `total_size` to our fixed buffer. Without
    // the `RESPONSE_BUF_LEN` guard a large cached RRset (~32 A or ~18 AAAA
    // records for one name) overflows the slice writes below and panics the
    // worker; reject it here so the slow path serves it instead.
    if total_size > max_size || total_size > RESPONSE_BUF_LEN {
        return None;
    }

    let ancount = addresses.len() as u16;
    // Every byte of `out[..total_size]` is written: `out` is reused, not zeroed.
    out[0..2].copy_from_slice(&query.id.to_be_bytes());
    out[2..4].copy_from_slice(&[0x81, 0x80]);
    out[4..6].copy_from_slice(&1u16.to_be_bytes());
    out[6..8].copy_from_slice(&ancount.to_be_bytes());
    out[8..10].copy_from_slice(&0u16.to_be_bytes());
    out[10..12].copy_from_slice(&u16::from(query.has_edns()).to_be_bytes());

    out[12..12 + question_len].copy_from_slice(&query_buf[12..query.question_end]);

    let mut pos = 12 + question_len;

    for addr in addresses {
        pos += write_address_rr(&mut out[pos..], addr, ttl);
    }

    if query.has_edns() {
        out[pos..pos + OPT_RECORD.len()].copy_from_slice(&OPT_RECORD);
        pos += OPT_RECORD.len();
    }

    Some(pos)
}

/// Answer-section size of one A (16) or AAAA (28) record owned by `C0 0C`.
#[inline]
fn address_rr_len(addr: &IpAddr) -> usize {
    match addr {
        IpAddr::V4(_) => 16,
        IpAddr::V6(_) => 28,
    }
}

/// Writes one A/AAAA record whose owner is a pointer to the first question
/// name (offset 12) at the start of `out`; returns its length.
#[inline]
fn write_address_rr(out: &mut [u8], addr: &IpAddr, ttl: u32) -> usize {
    let (rtype, rdlen): (u16, u16) = match addr {
        IpAddr::V4(_) => (1, 4),
        IpAddr::V6(_) => (28, 16),
    };
    out[0..2].copy_from_slice(&[0xC0, 0x0C]);
    out[2..4].copy_from_slice(&rtype.to_be_bytes());
    out[4..6].copy_from_slice(&CLASS_IN.to_be_bytes());
    out[6..10].copy_from_slice(&ttl.to_be_bytes());
    out[10..12].copy_from_slice(&rdlen.to_be_bytes());
    match addr {
        IpAddr::V4(v4) => out[12..16].copy_from_slice(&v4.octets()),
        IpAddr::V6(v6) => out[12..28].copy_from_slice(&v6.octets()),
    }
    12 + usize::from(rdlen)
}

const CLASS_IN: u16 = 1;
const TYPE_SOA: u16 = 6;
const TYPE_OPT: u16 = 41;
/// EDNS option code of the DNS Cookie (RFC 7873 §4).
pub(crate) const COOKIE_OPTION_CODE: u16 = 10;
/// UDP payload size advertised in every OPT this server writes.
const EDNS_UDP_PAYLOAD: u16 = 4096;
/// `hostmaster.ferrous-dns.invalid.` — the synthetic SOA RNAME.
const SOA_RNAME: &[u8] = b"\x0ahostmaster\x0bferrous-dns\x07invalid\x00";

/// Response codes this server sets in the header (RFC 1035 §4.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Rcode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    Refused = 5,
}

/// Header fields of a response that are not derived from its sections.
#[derive(Debug, Clone, Copy)]
pub struct ResponseHead {
    pub id: u16,
    pub recursion_desired: bool,
    pub authentic_data: bool,
    pub rcode: Rcode,
}

impl ResponseHead {
    fn flags(&self, truncated: bool) -> [u8; 2] {
        let mut hi = 0x80 | u8::from(self.recursion_desired);
        if truncated {
            hi |= 0x02;
        }
        // RA is always set: this server recurses for every client.
        let lo = 0x80 | (u8::from(self.authentic_data) << 5) | self.rcode as u8;
        [hi, lo]
    }
}

/// The response OPT record. Callers pass one iff the query carried OPT —
/// RFC 6891 §7 forbids an OPT in the reply to a query without one.
#[derive(Debug, Clone, Copy)]
pub struct EdnsReply<'a> {
    /// RFC 3225 §3: the DO bit is copied from the query.
    pub dnssec_ok: bool,
    /// Full COOKIE option payload: client cookie followed by server cookie.
    pub cookie: Option<&'a [u8]>,
    pub ede: Option<&'a ExtendedDnsError>,
}

impl EdnsReply<'_> {
    fn write(&self, out: &mut Vec<u8>) {
        let cookie_len = self.cookie.map_or(0, |c| 4 + c.len());
        let ede_len = self.ede.map_or(0, |e| 6 + e.extra_text.len());
        let rdlen = (cookie_len + ede_len) as u16;
        out.push(0);
        out.extend_from_slice(&TYPE_OPT.to_be_bytes());
        out.extend_from_slice(&EDNS_UDP_PAYLOAD.to_be_bytes());
        // Extended RCODE 0, version 0, then the flags word with DO in the top bit.
        out.extend_from_slice(&[0, 0, u8::from(self.dnssec_ok) << 7, 0]);
        out.extend_from_slice(&rdlen.to_be_bytes());
        if let Some(cookie) = self.cookie {
            out.extend_from_slice(&COOKIE_OPTION_CODE.to_be_bytes());
            out.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
            out.extend_from_slice(cookie);
        }
        if let Some(ede) = self.ede {
            let text = ede.extra_text.as_bytes();
            out.extend_from_slice(&ede::OPTION_CODE.to_be_bytes());
            out.extend_from_slice(&((2 + text.len()) as u16).to_be_bytes());
            out.extend_from_slice(&ede.info_code.to_be_bytes());
            out.extend_from_slice(text);
        }
    }
}

/// What follows the question section.
#[derive(Debug, Clone, Copy)]
pub enum ResponseBody<'a> {
    Empty,
    /// A/AAAA answers owned by the first question name.
    Addresses {
        addresses: &'a [IpAddr],
        ttl: u32,
    },
    /// No answer, plus a synthetic SOA in authority so resolvers can cache the
    /// negative answer for `ttl` (RFC 2308).
    NegativeSoa {
        ttl: u32,
    },
}

/// Encodes a response echoing `question` — `qdcount` wire-format questions
/// whose first name is uncompressed, so `C0 0C` addresses it.
pub fn encode_response(
    head: &ResponseHead,
    question: &[u8],
    qdcount: u16,
    body: ResponseBody<'_>,
    edns: Option<&EdnsReply<'_>>,
) -> Vec<u8> {
    let (ancount, nscount, body_len) = match body {
        ResponseBody::Empty => (0, 0, 0),
        ResponseBody::Addresses { addresses, .. } => (
            addresses.len() as u16,
            0,
            addresses.iter().map(address_rr_len).sum(),
        ),
        ResponseBody::NegativeSoa { .. } => (0, 1, 12 + 2 + SOA_RNAME.len() + 20),
    };
    let mut out = Vec::with_capacity(12 + question.len() + body_len + 64);
    write_header(
        &mut out,
        head.id,
        head.flags(false),
        qdcount,
        ancount,
        nscount,
        u16::from(edns.is_some()),
    );
    out.extend_from_slice(question);
    match body {
        ResponseBody::Empty => {}
        ResponseBody::Addresses { addresses, ttl } => {
            for addr in addresses {
                let mut rr = [0u8; 28];
                let len = write_address_rr(&mut rr, addr, ttl);
                out.extend_from_slice(&rr[..len]);
            }
        }
        ResponseBody::NegativeSoa { ttl } => {
            out.extend_from_slice(&[0xC0, 0x0C]);
            out.extend_from_slice(&TYPE_SOA.to_be_bytes());
            out.extend_from_slice(&CLASS_IN.to_be_bytes());
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&((2 + SOA_RNAME.len() + 20) as u16).to_be_bytes());
            // MNAME is the queried name itself; resolvers key the negative
            // cache off MINIMUM, so an exact zone apex is not required.
            out.extend_from_slice(&[0xC0, 0x0C]);
            out.extend_from_slice(SOA_RNAME);
            for field in [1u32, 3600, 600, 604_800, ttl] {
                out.extend_from_slice(&field.to_be_bytes());
            }
        }
    }
    if let Some(edns) = edns {
        edns.write(&mut out);
    }
    out
}

/// Header plus question with TC=1: tells a UDP client to retry over TCP.
pub fn encode_truncated(
    id: u16,
    recursion_desired: bool,
    question: &[u8],
    qdcount: u16,
) -> Vec<u8> {
    let head = ResponseHead {
        id,
        recursion_desired,
        authentic_data: false,
        rcode: Rcode::NoError,
    };
    let mut out = Vec::with_capacity(12 + question.len());
    write_header(&mut out, id, head.flags(true), qdcount, 0, 0, 0);
    out.extend_from_slice(question);
    out
}

fn write_header(out: &mut Vec<u8>, id: u16, flags: [u8; 2], qd: u16, an: u16, ns: u16, ar: u16) {
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&flags);
    for count in [qd, an, ns, ar] {
        out.extend_from_slice(&count.to_be_bytes());
    }
}

/// Re-issues a cached upstream response under the client's header and OPT:
/// ID and RD from the client, AD as given, the upstream OPT dropped and
/// `edns` appended in its place, carrying the upstream's extended RCODE bits.
/// `None` if `upstream` is not a well-formed sequence of sections, holds two
/// OPTs, has records after its OPT (their compression pointers may target
/// bytes that move once the OPT is cut out), or has an extended RCODE that
/// `edns: None` cannot carry.
pub fn relay_with_edns(
    upstream: &[u8],
    id: u16,
    recursion_desired: bool,
    authentic_data: bool,
    edns: Option<&EdnsReply<'_>>,
) -> Option<Vec<u8>> {
    let header = upstream.get(..12)?;
    let count = |i: usize| u16::from_be_bytes([header[i], header[i + 1]]);
    let (qd, an, ns, ar) = (count(4), count(6), count(8), count(10));

    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(upstream, pos)?.checked_add(4)?;
    }
    for _ in 0..usize::from(an) + usize::from(ns) {
        pos = skip_rr(upstream, pos)?.1;
    }
    let sections_end = pos;
    upstream.get(..sections_end)?;

    let mut out = Vec::with_capacity(upstream.len() + 64);
    out.extend_from_slice(&upstream[..sections_end]);
    let mut kept_ar = 0u16;
    let mut extended_rcode: Option<u8> = None;
    for _ in 0..ar {
        let (rtype, end) = skip_rr(upstream, pos)?;
        if rtype == TYPE_OPT {
            if extended_rcode.is_some() {
                return None;
            }
            // The upper eight RCODE bits open the OPT's TTL field (RFC 6891 §6.1.3).
            extended_rcode = Some(upstream[skip_name(upstream, pos)? + 4]);
        } else if extended_rcode.is_some() {
            return None;
        } else {
            out.extend_from_slice(&upstream[pos..end]);
            kept_ar += 1;
        }
        pos = end;
    }
    let extended_rcode = extended_rcode.unwrap_or(0);
    match edns {
        Some(edns) => {
            let opt = out.len();
            edns.write(&mut out);
            // Root owner (1), TYPE (2), CLASS (2), then the TTL's first byte.
            out[opt + 5] = extended_rcode;
            kept_ar += 1;
        }
        None if extended_rcode != 0 => return None,
        None => {}
    }

    set_relay_header(&mut out, id, recursion_desired, authentic_data);
    out[10..12].copy_from_slice(&kept_ar.to_be_bytes());
    Some(out)
}

/// Offset just past the (possibly compressed) name at `pos`.
fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *buf.get(pos)?;
        match len & 0xC0 {
            0xC0 => return buf.get(pos + 1).map(|_| pos + 2),
            0x00 if len == 0 => return Some(pos + 1),
            0x00 => pos += 1 + usize::from(len),
            _ => return None,
        }
    }
}

/// `(type, end offset)` of the resource record at `pos`.
fn skip_rr(buf: &[u8], pos: usize) -> Option<(u16, usize)> {
    let fixed = skip_name(buf, pos)?;
    let f = buf.get(fixed..fixed + 10)?;
    let rtype = u16::from_be_bytes([f[0], f[1]]);
    let end = fixed + 10 + usize::from(u16::from_be_bytes([f[8], f[9]]));
    buf.get(..end)?;
    Some((rtype, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::rdata::opt::EdnsOption;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::str::FromStr;

    fn question(name: &str, qtype: RecordType) -> Vec<u8> {
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(Name::from_str(name).unwrap(), qtype));
        msg.to_vec().unwrap()[12..].to_vec()
    }

    fn head(rcode: Rcode) -> ResponseHead {
        ResponseHead {
            id: 0xBEEF,
            recursion_desired: true,
            authentic_data: true,
            rcode,
        }
    }

    #[test]
    fn fast_path_opt_constant_is_the_plain_edns_reply() {
        let mut written = Vec::new();
        EdnsReply {
            dnssec_ok: false,
            cookie: None,
            ede: None,
        }
        .write(&mut written);
        assert_eq!(written, OPT_RECORD);
    }

    #[test]
    fn cache_hit_encoding_ignores_previous_buffer_contents() {
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
        query.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        query.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        let parsed = super::super::fast_path::parse_query(&query).unwrap();
        let addresses = ["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()];

        let mut clean = [0u8; RESPONSE_BUF_LEN];
        let mut dirty = [0xA5u8; RESPONSE_BUF_LEN];
        let clean_len =
            build_cache_hit_response(&parsed, &query, &addresses, 60, &mut clean).unwrap();
        let dirty_len =
            build_cache_hit_response(&parsed, &query, &addresses, 60, &mut dirty).unwrap();
        assert_eq!(&dirty[..dirty_len], &clean[..clean_len]);
        assert_eq!(
            Message::from_vec(&clean[..clean_len])
                .unwrap()
                .answers
                .len(),
            2
        );
    }

    #[test]
    fn address_response_decodes_with_header_answers_and_opt() {
        let q = question("example.com.", RecordType::AAAA);
        let addresses = ["2001:db8::1".parse().unwrap(), "192.0.2.1".parse().unwrap()];
        let cookie = [7u8; 16];
        let wire = encode_response(
            &head(Rcode::NoError),
            &q,
            1,
            ResponseBody::Addresses {
                addresses: &addresses,
                ttl: 300,
            },
            Some(&EdnsReply {
                dnssec_ok: true,
                cookie: Some(&cookie),
                ede: None,
            }),
        );

        let msg = Message::from_vec(&wire).unwrap();
        assert_eq!(msg.id, 0xBEEF);
        assert_eq!(msg.message_type, MessageType::Response);
        assert!(msg.recursion_desired && msg.recursion_available && msg.authentic_data);
        assert!(!msg.truncation);
        assert_eq!(msg.response_code, ResponseCode::NoError);
        assert_eq!(
            msg.queries[0].name(),
            &Name::from_str("example.com.").unwrap()
        );
        let answers: Vec<_> = msg
            .answers
            .iter()
            .map(|r| (r.name.clone(), r.ttl, r.data.clone()))
            .collect();
        let owner = Name::from_str("example.com.").unwrap();
        assert_eq!(
            answers,
            [
                (
                    owner.clone(),
                    300,
                    RData::AAAA("2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().into())
                ),
                (
                    owner,
                    300,
                    RData::A("192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap().into())
                ),
            ]
        );
        let edns = msg.edns.unwrap();
        assert!(edns.flags().dnssec_ok);
        assert_eq!(edns.max_payload(), EDNS_UDP_PAYLOAD);
        assert!(edns
            .options()
            .as_ref()
            .iter()
            .any(|(_, o)| matches!(o, EdnsOption::Unknown(10, d) if d == &cookie)));
    }

    #[test]
    fn negative_soa_is_cacheable_for_the_block_ttl() {
        let q = question("ads.example.com.", RecordType::A);
        let wire = encode_response(
            &head(Rcode::NxDomain),
            &q,
            1,
            ResponseBody::NegativeSoa { ttl: 120 },
            None,
        );

        let msg = Message::from_vec(&wire).unwrap();
        assert_eq!(msg.response_code, ResponseCode::NXDomain);
        assert!(msg.answers.is_empty() && msg.edns.is_none());
        let soa = &msg.authorities[0];
        assert_eq!(soa.ttl, 120);
        match &soa.data {
            RData::SOA(soa) => {
                assert_eq!(soa.mname, Name::from_str("ads.example.com.").unwrap());
                assert_eq!(
                    soa.rname,
                    Name::from_str("hostmaster.ferrous-dns.invalid.").unwrap()
                );
                assert_eq!(soa.minimum, 120);
            }
            other => panic!("expected SOA, got {other:?}"),
        }
    }

    #[test]
    fn truncated_response_carries_tc_and_the_question_only() {
        let q = question("big.example.com.", RecordType::TXT);
        let msg = Message::from_vec(&encode_truncated(9, false, &q, 1)).unwrap();
        assert!(msg.truncation && !msg.recursion_desired);
        assert_eq!(msg.queries.len(), 1);
        assert!(msg.answers.is_empty() && msg.edns.is_none());
    }

    #[test]
    fn relay_replaces_the_upstream_opt_and_keeps_every_other_record() {
        let owner = Name::from_str("mail.example.com.").unwrap();
        let mut upstream = Message::new(0x1111, MessageType::Response, OpCode::Query);
        upstream.metadata.recursion_desired = true;
        upstream.metadata.recursion_available = true;
        upstream.add_query(Query::query(owner.clone(), RecordType::MX));
        upstream.add_answer(Record::from_rdata(
            owner.clone(),
            60,
            RData::MX(hickory_proto::rr::rdata::MX::new(
                10,
                Name::from_str("mx.example.com.").unwrap(),
            )),
        ));
        upstream.add_additional(Record::from_rdata(
            Name::from_str("mx.example.com.").unwrap(),
            60,
            RData::A("192.0.2.25".parse::<std::net::Ipv4Addr>().unwrap().into()),
        ));
        let mut edns = Edns::new();
        edns.options_mut()
            .insert(EdnsOption::Unknown(10, vec![0xAA; 16]));
        upstream.set_edns(edns);
        let upstream = upstream.to_vec().unwrap();

        let ours = [0x55u8; 16];
        let relayed = relay_with_edns(
            &upstream,
            0x2222,
            false,
            true,
            Some(&EdnsReply {
                dnssec_ok: true,
                cookie: Some(&ours),
                ede: None,
            }),
        )
        .unwrap();

        let msg = Message::from_vec(&relayed).unwrap();
        assert_eq!(msg.id, 0x2222);
        assert!(!msg.recursion_desired && msg.authentic_data);
        assert_eq!(msg.answers.len(), 1);
        assert_eq!(
            msg.additionals.len(),
            1,
            "the A glue survives, the OPT does not"
        );
        let cookies: Vec<_> = msg
            .edns
            .unwrap()
            .options()
            .as_ref()
            .iter()
            .filter_map(|(_, o)| match o {
                EdnsOption::Unknown(10, d) => Some(d.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(cookies, [ours.to_vec()]);

        let without = relay_with_edns(&upstream, 1, true, false, None).unwrap();
        assert!(Message::from_vec(&without).unwrap().edns.is_none());
    }

    #[test]
    fn relay_rejects_sections_that_overrun_the_message() {
        let mut upstream = Message::new(1, MessageType::Response, OpCode::Query);
        upstream.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        let mut wire = upstream.to_vec().unwrap();
        wire[7] = 1; // ANCOUNT claims a record the message does not hold
        assert!(relay_with_edns(&wire, 1, true, false, None).is_none());
    }

    /// RFC 6891 does not require OPT to be the last additional record. A
    /// record after it may compress its owner against another post-OPT name,
    /// and those offsets move when the OPT is cut out.
    #[test]
    fn relay_never_breaks_compression_behind_a_dropped_opt() {
        let mut wire = vec![0x11, 0x11, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 3];
        wire.extend_from_slice(b"\x07example\x03com\x00\x00\x10\x00\x01"); // question @12
        wire.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]); // OPT first
        let glue = wire.len() as u8;
        wire.extend_from_slice(b"\x03ns1\xC0\x0C\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04");
        wire.extend_from_slice(&[192, 0, 2, 53]);
        wire.extend_from_slice(&[0xC0, glue, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]); // -> glue owner
        wire.extend_from_slice(&[
            0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x35,
        ]);
        let upstream = Message::from_vec(&wire).expect("hickory accepts the upstream message");
        let owners = |m: &Message| {
            m.additionals
                .iter()
                .map(|r| r.name.clone())
                .collect::<Vec<_>>()
        };

        let ours = EdnsReply {
            dnssec_ok: false,
            cookie: Some(&[0x55; 16]),
            ede: None,
        };
        if let Some(relayed) = relay_with_edns(&wire, 1, true, false, Some(&ours)) {
            let relayed = Message::from_vec(&relayed).expect("relayed message decodes");
            assert_eq!(owners(&relayed), owners(&upstream));
        }
    }
}
