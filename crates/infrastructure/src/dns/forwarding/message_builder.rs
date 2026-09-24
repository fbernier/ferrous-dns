use super::record_type_map::RecordTypeMapper;
use super::response_validator::ResponseValidator;
use ferrous_dns_domain::{DomainError, RecordType};
use hickory_proto::rr::Name;
use std::str::FromStr;

pub(super) const CLIENT_COOKIE_LEN: usize = 8;
pub(super) const COOKIE_OPTION_CODE: u16 = 10;
/// RFC 1035 §3.1: a wire-format name is at most 255 octets.
const MAX_QNAME_LEN: usize = 255;

/// EDNS0 UDP payload size advertised on every outgoing upstream query.
///
/// 1232 is the DNS Flag Day 2020 recommendation: it fits inside the minimum
/// IPv6 MTU (1280) minus headers, so responses are never IP-fragmented. That
/// matters twice over — middleboxes routinely drop IP fragments (which shows up
/// as an unexplained timeout, not an error), and fragment-based cache poisoning
/// depends on the second fragment, which carries neither UDP header nor TXID.
/// Responses that no longer fit come back with TC=1 and are retried over TCP.
pub const EDNS_MAX_PAYLOAD: u16 = 1232;

/// Anti-spoofing measures for an upstream query, applied to every record type.
/// The default sends a DNS Cookie (graceful, so always safe) and leaves 0x20 off,
/// since some upstreams normalize QNAME case.
#[derive(Clone, Copy, Debug)]
pub struct HardeningOpts {
    /// Inject a random client DNS Cookie (RFC 7873, EDNS option 10) and validate
    /// its echo on the response.
    pub cookie: bool,
    /// Randomize QNAME letter case (draft-vixie-dns-0x20) and validate the echo.
    pub qname_0x20: bool,
}

impl Default for HardeningOpts {
    fn default() -> Self {
        Self {
            cookie: true,
            qname_0x20: false,
        }
    }
}

pub struct MessageBuilder;

impl MessageBuilder {
    pub fn build_query(
        domain: &str,
        record_type: &RecordType,
        dnssec_ok: bool,
    ) -> Result<Vec<u8>, DomainError> {
        let qname = QName::encode(domain)?;
        let mut id = [0u8; 2];
        Self::fill_random(&mut id);
        let qtype = u16::from(RecordTypeMapper::to_hickory(record_type));
        Ok(assemble_query(
            u16::from_be_bytes(id),
            &qname,
            qtype,
            dnssec_ok,
            None,
        ))
    }

    /// Builds an upstream query with optional anti-spoofing hardening and returns
    /// the wire bytes alongside a [`ResponseValidator`] capturing the per-query
    /// expectations (txid, question name/type, client cookie).
    ///
    /// Transaction-ID and question validation apply whatever `opts` says.
    pub fn build_query_hardened(
        domain: &str,
        record_type: &RecordType,
        dnssec_ok: bool,
        opts: HardeningOpts,
    ) -> Result<(Vec<u8>, ResponseValidator), DomainError> {
        let mut qname = QName::encode(domain)?;
        if opts.qname_0x20 {
            qname.randomize_case();
        }
        let hickory_type = RecordTypeMapper::to_hickory(record_type);

        // One draw for both secrets: each OS RNG call is a syscall where the
        // vDSO getrandom is unavailable.
        let mut secrets = [0u8; 2 + CLIENT_COOKIE_LEN];
        let drawn = if opts.cookie { secrets.len() } else { 2 };
        Self::fill_random(&mut secrets[..drawn]);
        let id = u16::from_be_bytes([secrets[0], secrets[1]]);
        let client_cookie = opts.cookie.then(|| {
            let mut cookie = [0u8; CLIENT_COOKIE_LEN];
            cookie.copy_from_slice(&secrets[2..]);
            cookie
        });

        let bytes = assemble_query(
            id,
            &qname,
            u16::from(hickory_type),
            dnssec_ok,
            client_cookie.as_ref(),
        );
        let validator = ResponseValidator::new(
            id,
            qname.wire(),
            hickory_type,
            client_cookie,
            opts.qname_0x20,
        );
        Ok((bytes, validator))
    }

    fn fill_random(buf: &mut [u8]) {
        // getrandom 0.3 goes through libc, which serves it from the vDSO on
        // glibc >= 2.41 / Linux >= 6.11 (~25 ns vs ~200 ns for the syscall).
        if getrandom::fill(buf).is_err() {
            for b in buf.iter_mut() {
                *b = fastrand::u8(..);
            }
        }
    }
}

/// An uncompressed wire-format QNAME.
struct QName {
    buf: [u8; MAX_QNAME_LEN],
    len: usize,
}

impl QName {
    /// Encodes `domain` (presentation form, trailing dot optional), lowercased.
    /// Plain LDH names are encoded directly; anything else — escapes, Unicode
    /// (IDN to punycode) — goes through hickory's parser so both agree on
    /// which labels a name has.
    fn encode(domain: &str) -> Result<Self, DomainError> {
        if let Some(qname) = Self::encode_plain(domain) {
            return Ok(qname);
        }
        let name = Name::from_str(domain).map_err(|e| {
            DomainError::InvalidDomainName(format!("Invalid domain '{}': {}", domain, e))
        })?;
        let mut qname = Self {
            buf: [0; MAX_QNAME_LEN],
            len: 0,
        };
        for label in name.iter() {
            qname.push_label(label)?;
        }
        qname.finish()?;
        Ok(qname)
    }

    /// `None` for anything outside `[A-Za-z0-9_*-]` labels of 1..=63 bytes.
    fn encode_plain(domain: &str) -> Option<Self> {
        let trimmed = domain.strip_suffix('.').unwrap_or(domain);
        let mut qname = Self {
            buf: [0; MAX_QNAME_LEN],
            len: 0,
        };
        if !trimmed.is_empty() {
            for label in trimmed.split('.') {
                let plain = !label.is_empty()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'*'));
                if !plain {
                    return None;
                }
                qname.push_label(label.as_bytes()).ok()?;
            }
        }
        qname.finish().ok()?;
        qname.buf[..qname.len].make_ascii_lowercase();
        Some(qname)
    }

    fn push_label(&mut self, label: &[u8]) -> Result<(), DomainError> {
        let end = self.len + 1 + label.len();
        if label.is_empty() || label.len() > 63 || end >= MAX_QNAME_LEN {
            return Err(DomainError::InvalidDomainName(
                "label empty, over 63 bytes, or name over 255 bytes".into(),
            ));
        }
        self.buf[self.len] = label.len() as u8;
        self.buf[self.len + 1..end].copy_from_slice(label);
        self.len = end;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), DomainError> {
        if self.len >= MAX_QNAME_LEN {
            return Err(DomainError::InvalidDomainName("name over 255 bytes".into()));
        }
        self.buf[self.len] = 0;
        self.len += 1;
        Ok(())
    }

    fn wire(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Randomizes the case of every ASCII letter (draft-vixie-dns-0x20). Length
    /// bytes are at most 63, below `A`, so they are never mistaken for letters.
    fn randomize_case(&mut self) {
        let mut bits = [0u8; MAX_QNAME_LEN.div_ceil(8)];
        MessageBuilder::fill_random(&mut bits[..self.len.div_ceil(8)]);
        for (i, b) in self.buf[..self.len].iter_mut().enumerate() {
            if b.is_ascii_alphabetic() && (bits[i / 8] >> (i % 8)) & 1 == 1 {
                *b ^= 0x20;
            }
        }
    }
}

/// A recursion-desired query for `qname`/`qtype` class IN with one OPT
/// advertising [`EDNS_MAX_PAYLOAD`], DO as given, and the client cookie if any.
fn assemble_query(
    id: u16,
    qname: &QName,
    qtype: u16,
    dnssec_ok: bool,
    cookie: Option<&[u8; CLIENT_COOKIE_LEN]>,
) -> Vec<u8> {
    let options_len = cookie.map_or(0, |c| 4 + c.len());
    let mut out = Vec::with_capacity(12 + qname.len + 4 + 11 + options_len);
    out.extend_from_slice(&id.to_be_bytes());
    // RD set; one question, one additional (the OPT).
    out.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1]);
    out.extend_from_slice(qname.wire());
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0, 0, 41]);
    out.extend_from_slice(&EDNS_MAX_PAYLOAD.to_be_bytes());
    // Extended RCODE 0, version 0, then the flags word with DO in the top bit.
    out.extend_from_slice(&[0, 0, u8::from(dnssec_ok) << 7, 0]);
    out.extend_from_slice(&(options_len as u16).to_be_bytes());
    if let Some(cookie) = cookie {
        out.extend_from_slice(&COOKIE_OPTION_CODE.to_be_bytes());
        out.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
        out.extend_from_slice(cookie);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::opt::EdnsOption;

    /// Reference encoding of the same query through hickory.
    fn hickory_query(
        id: u16,
        domain: &str,
        rt: RecordType,
        dnssec_ok: bool,
        cookie: Option<[u8; 8]>,
    ) -> Vec<u8> {
        let mut query = Query::new();
        query.set_name(Name::from_str(domain).unwrap());
        query.set_query_type(RecordTypeMapper::to_hickory(&rt));
        query.set_query_class(hickory_proto::rr::DNSClass::IN);
        let mut edns = Edns::new();
        edns.set_max_payload(EDNS_MAX_PAYLOAD);
        edns.set_dnssec_ok(dnssec_ok);
        edns.set_version(0);
        if let Some(cookie) = cookie {
            edns.options_mut()
                .insert(EdnsOption::Unknown(COOKIE_OPTION_CODE, cookie.to_vec()));
        }
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(query);
        message.set_edns(edns);
        message.to_vec().unwrap()
    }

    #[test]
    fn wire_query_matches_hickory_encoding() {
        let cases = [
            ("example.com", RecordType::A, false, None),
            ("www.Example.COM.", RecordType::AAAA, true, Some([7u8; 8])),
            (".", RecordType::DNSKEY, true, None),
            (
                "_dmarc.sub-1.example.org",
                RecordType::TXT,
                false,
                Some([1, 2, 3, 4, 5, 6, 7, 8]),
            ),
            ("bücher.example", RecordType::A, false, None),
            (r"a\.b.example", RecordType::A, false, None),
        ];
        for (domain, rt, dnssec_ok, cookie) in cases {
            let qname = QName::encode(domain).unwrap();
            let qtype = u16::from(RecordTypeMapper::to_hickory(&rt));
            assert_eq!(
                assemble_query(0x1234, &qname, qtype, dnssec_ok, cookie.as_ref()),
                hickory_query(0x1234, domain, rt, dnssec_ok, cookie),
                "{domain}"
            );
        }
    }

    #[test]
    fn randomized_case_only_flips_letters() {
        let mut qname = QName::encode("a1-b.example.com").unwrap();
        let plain = qname.wire().to_vec();
        qname.randomize_case();
        assert_eq!(qname.wire().len(), plain.len());
        assert!(qname.wire().eq_ignore_ascii_case(&plain));
        for (got, want) in qname.wire().iter().zip(&plain) {
            if !want.is_ascii_alphabetic() {
                assert_eq!(got, want);
            }
        }
    }

    #[test]
    fn over_long_names_are_rejected() {
        let label = "a".repeat(63);
        let too_long = [label.as_str(); 4].join(".");
        assert!(QName::encode(&too_long).is_err());
        assert!(QName::encode(&"b".repeat(64)).is_err());
    }
}
