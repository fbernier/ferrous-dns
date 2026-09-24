use crate::dns::ede::{self, ExtendedDnsError};
use crate::dns::fast_path;
use crate::dns::forwarding::RecordTypeMapper;
use crate::dns::wire_response::{self, EdnsReply, Rcode, ResponseBody, ResponseHead};
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{
    BlockResponseMode, ClientProtocol, DnsRequest, DnssecStatus, DomainError, EdnsCookie,
    RecordType,
};
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

const DEFAULT_TTL: u32 = 60;

/// How domain-verdict blocks (blocklist, DGA, tunneling, C2 filter) are answered.
///
/// Snapshotted from `[blocking]` config at boot; applied to the wire response so
/// blocked answers become cacheable (default `NullIp`) instead of the legacy,
/// non-cacheable `REFUSED` that caused clients to retry aggressively.
#[derive(Debug, Clone, Copy)]
pub struct BlockPolicy {
    pub mode: BlockResponseMode,
    pub ttl: u32,
    /// Custom A target for `NullIp` blocks; `None` falls back to `0.0.0.0`.
    pub sinkhole_ipv4: Option<Ipv4Addr>,
    /// Custom AAAA target for `NullIp` blocks; `None` falls back to `::`.
    pub sinkhole_ipv6: Option<Ipv6Addr>,
}

#[derive(Clone)]
pub struct DnsServerHandler {
    use_case: Arc<HandleDnsQueryUseCase>,
    block_policy: BlockPolicy,
}

impl DnsServerHandler {
    pub fn new(use_case: Arc<HandleDnsQueryUseCase>, block_policy: BlockPolicy) -> Self {
        Self {
            use_case,
            block_policy,
        }
    }

    /// Normalizes a domain received from Hickory for downstream use: strips the
    /// trailing root dot and lowercases ASCII bytes (RFC 1035 §2.3.3 — DNS is
    /// case-insensitive). Returns `Cow::Borrowed` when the trimmed slice is
    /// already lowercase (zero-alloc fast path); otherwise owns a lowercased
    /// copy.
    fn normalize_domain(domain: &str) -> Cow<'_, str> {
        let trimmed = domain.trim_end_matches('.');
        if trimmed.bytes().all(|b| !b.is_ascii_uppercase()) {
            Cow::Borrowed(trimmed)
        } else {
            Cow::Owned(trimmed.to_ascii_lowercase())
        }
    }

    pub fn try_fast_path(
        &self,
        domain: &str,
        record_type: RecordType,
        client_ip: IpAddr,
        protocol: ClientProtocol,
    ) -> Option<(Arc<Vec<IpAddr>>, u32)> {
        self.use_case
            .try_cache_direct(domain, record_type, client_ip, protocol)
    }

    /// Returns a ready-to-send cached wire response for non-IP record types (NS,
    /// CNAME, SOA, PTR, MX, TXT): the query ID is patched to `query_id` and the
    /// AD bit is cleared. Clearing AD here — rather than relying on every caller
    /// to do it — keeps the cached-wire fast path compliant for non-DO clients
    /// (RFC 6840 §5.8) by construction.
    pub fn try_fast_path_wire(
        &self,
        domain: &str,
        record_type: RecordType,
        client_ip: IpAddr,
        query_id: u16,
        client_max_size: u16,
        protocol: ClientProtocol,
    ) -> Option<(Vec<u8>, u32)> {
        let (wire, ttl) =
            self.use_case
                .try_cache_wire_direct(domain, record_type, client_ip, protocol)?;
        // Oversized-for-UDP hits bail to the slow path (handle_raw_udp_fallback),
        // which sets TC=1 — mirrors build_cache_hit_response for A/AAAA.
        if !wire_response::wire_fits_udp_buffer(wire.len(), client_max_size) {
            return None;
        }
        let patched = wire_response::patch_wire_id_clear_ad(&wire, query_id)?;
        Some((patched, ttl))
    }

    /// The resolution path for every query the inline cache path did not
    /// answer, over every transport. The query is decoded with the same wire
    /// parser as the cache fast path and the response is written straight to
    /// wire; hickory only parses queries that parser declines (IDN or escaped
    /// names, uncommon types, several questions), whose cache keys must match
    /// `Name::to_utf8()`.
    pub async fn handle_raw_udp_fallback(
        &self,
        raw: &[u8],
        client_ip: IpAddr,
        protocol: ClientProtocol,
    ) -> Option<Vec<u8>> {
        let (query, request) = parse_client_query(raw, client_ip, protocol)?;

        // Over UDP, the client-advertised EDNS buffer (or 512 without EDNS) caps
        // the response size; larger answers must be truncated with TC=1 so the
        // client retries over TCP. TCP, DoT and DoH carry their own length
        // framing, and DoQ rides on UDP but frames responses explicitly (RFC
        // 9250), so none of them is subject to the limit.
        let udp_limit = matches!(protocol, ClientProtocol::Udp).then(|| {
            query
                .edns
                .map_or(512, |e| usize::from(e.udp_payload.max(512)))
        });
        let maybe_truncate = |bytes: Vec<u8>| match udp_limit {
            Some(limit) if bytes.len() > limit => query.truncated(),
            _ => bytes,
        };

        let resolution = match self.use_case.execute(&request).await {
            Ok(res) => res,
            Err(e) => return Some(self.error_response(&query, request.record_type, &e)),
        };

        // RFC 6840 §5.8: advertise Authenticated Data only to DNSSEC-aware clients
        // (DO bit), when we validated the answer as Secure, and the client did not
        // set CD (which signals it wants to do its own validation, not trust ours).
        let set_ad = query.edns.is_some_and(|e| e.dnssec_ok)
            && !query.cd
            && resolution.dnssec_status == Some(DnssecStatus::Secure.as_str());
        let cookie = self.response_cookie(&request, client_ip);
        let cookie = cookie.as_ref().map(EdnsCookie::as_bytes);

        if resolution.addresses.is_empty() {
            if let Some(ref wire_data) = resolution.upstream_wire_data {
                // 0x20 case randomization never reaches this far: responses are
                // canonicalized at the upstream choke point, before they enter
                // the cache (see ResponseValidator::canonicalize). Injecting our
                // server cookie is the only reason to rewrite the upstream OPT.
                if cookie.is_some() {
                    let reply = query.edns_reply(cookie, None);
                    if let Some(bytes) = wire_response::relay_with_edns(
                        wire_data,
                        query.id,
                        query.rd,
                        set_ad,
                        reply.as_ref(),
                    ) {
                        return Some(maybe_truncate(bytes));
                    }
                }
                // No cookie to inject, or an upstream message `relay_with_edns`
                // cannot re-section safely: relay it with the ID and AD
                // patched. This hands the upstream's own OPT to the client
                // verbatim, including the COOKIE echoed back at us. Harmless
                // (RFC 7873 §5.3 has clients ignore unsolicited cookies; ours
                // is random per query and the server cookie is bound to our IP).
                let mut response = wire_data.to_vec();
                if response.len() >= 2 {
                    response[0..2].copy_from_slice(&query.id.to_be_bytes());
                }
                wire_response::set_ad_bit(&mut response, set_ad);
                return Some(maybe_truncate(response));
            }
        }

        let body = if resolution.addresses.is_empty() {
            ResponseBody::Empty
        } else {
            ResponseBody::Addresses {
                addresses: &resolution.addresses,
                ttl: resolution.min_ttl.unwrap_or(DEFAULT_TTL),
            }
        };
        Some(maybe_truncate(query.respond(
            Rcode::NoError,
            set_ad,
            body,
            cookie,
            None,
        )))
    }

    fn error_response(
        &self,
        query: &ClientQuery<'_>,
        record_type: RecordType,
        err: &DomainError,
    ) -> Vec<u8> {
        let ede = ede::from_domain_error(err);
        let rcode = match err {
            DomainError::Blocked
            | DomainError::DgaDomainDetected
            | DomainError::DnsTunnelingDetected
            | DomainError::FilteredQuery(_) => {
                return build_blocked_wire(query, record_type, self.block_policy, ede.as_ref());
            }
            DomainError::DnsRateLimitedSlip => return query.truncated(),
            DomainError::DnsRateLimited | DomainError::DnsCookieInvalid => Rcode::Refused,
            DomainError::NxDomain | DomainError::LocalNxDomain => {
                return query.respond(Rcode::NxDomain, false, ResponseBody::Empty, None, None);
            }
            _ => Rcode::ServFail,
        };
        query.respond(rcode, false, ResponseBody::Empty, None, ede.as_ref())
    }

    /// COOKIE option payload for the reply: the client cookie followed by our
    /// server cookie for it (RFC 7873 §5.2). `None` without a client cookie.
    fn response_cookie(&self, request: &DnsRequest, client_ip: IpAddr) -> Option<EdnsCookie> {
        let raw = request.edns_cookie.as_ref()?.as_bytes();
        let client: [u8; 8] = raw.get(..8)?.try_into().ok()?;
        let server = self
            .use_case
            .cookie_guard()
            .generate_server_cookie(client_ip, &client);
        let mut payload = [0u8; 8 + 32];
        payload[..8].copy_from_slice(&client);
        payload[8..8 + server.len()].copy_from_slice(&server);
        Some(EdnsCookie::from_bytes(&payload[..8 + server.len()]))
    }
}

/// The OPT fields of a client query that shape its response.
#[derive(Debug, Clone, Copy)]
struct ClientEdns {
    dnssec_ok: bool,
    udp_payload: u16,
}

/// What a response needs from its query, whichever parser decoded it.
pub struct ClientQuery<'a> {
    id: u16,
    rd: bool,
    cd: bool,
    /// `Some` iff the query carried OPT.
    edns: Option<ClientEdns>,
    /// Wire-format question section with an uncompressed first name.
    question: Cow<'a, [u8]>,
    qdcount: u16,
}

impl<'a> ClientQuery<'a> {
    /// A query with one uncompressed question, for building responses directly.
    pub fn new(id: u16, rd: bool, question: &'a [u8], edns_dnssec_ok: Option<bool>) -> Self {
        Self {
            id,
            rd,
            cd: false,
            edns: edns_dnssec_ok.map(|dnssec_ok| ClientEdns {
                dnssec_ok,
                udp_payload: 512,
            }),
            question: Cow::Borrowed(question),
            qdcount: 1,
        }
    }

    fn edns_reply<'r>(
        &self,
        cookie: Option<&'r [u8]>,
        ede: Option<&'r ExtendedDnsError>,
    ) -> Option<EdnsReply<'r>> {
        self.edns.map(|e| EdnsReply {
            dnssec_ok: e.dnssec_ok,
            cookie,
            ede,
        })
    }

    fn respond(
        &self,
        rcode: Rcode,
        authentic_data: bool,
        body: ResponseBody<'_>,
        cookie: Option<&[u8]>,
        ede: Option<&ExtendedDnsError>,
    ) -> Vec<u8> {
        let head = ResponseHead {
            id: self.id,
            recursion_desired: self.rd,
            authentic_data,
            rcode,
        };
        wire_response::encode_response(
            &head,
            &self.question,
            self.qdcount,
            body,
            self.edns_reply(cookie, ede).as_ref(),
        )
    }

    fn truncated(&self) -> Vec<u8> {
        wire_response::encode_truncated(self.id, self.rd, &self.question, self.qdcount)
    }
}

/// Decodes a client query into its response shape and the resolver request.
/// `None` drops the query: it is malformed, or of a type we do not resolve.
fn parse_client_query(
    raw: &[u8],
    client_ip: IpAddr,
    protocol: ClientProtocol,
) -> Option<(ClientQuery<'_>, DnsRequest)> {
    if let Some(q) = fast_path::parse_query(raw) {
        // Options the wire parser cannot walk are left to hickory's decoder.
        if let Ok(cookie) = q.edns_cookie(raw) {
            let mut request = DnsRequest::new(q.domain(), q.record_type, client_ip)
                .with_checking_disabled(q.checking_disabled)
                .with_protocol(protocol);
            if let Some(cookie) = cookie {
                request = request.with_cookie(cookie);
            }
            let query = ClientQuery {
                id: q.id,
                rd: q.recursion_desired,
                cd: q.checking_disabled,
                edns: q.has_edns.then_some(ClientEdns {
                    dnssec_ok: q.wants_dnssec,
                    udp_payload: q.client_max_size,
                }),
                question: Cow::Borrowed(q.question(raw)),
                qdcount: 1,
            };
            return Some((query, request));
        }
    }
    parse_client_query_hickory(raw, client_ip, protocol)
}

fn parse_client_query_hickory(
    raw: &[u8],
    client_ip: IpAddr,
    protocol: ClientProtocol,
) -> Option<(ClientQuery<'static>, DnsRequest)> {
    let mut msg = Message::from_vec(raw).ok()?;
    let first = msg.queries.first()?;
    let record_type = RecordTypeMapper::from_hickory(first.query_type())?;
    let domain_name = first.name().to_utf8();
    let domain = DnsServerHandler::normalize_domain(&domain_name);

    let mut request = DnsRequest::new(domain.as_ref(), record_type, client_ip)
        .with_checking_disabled(msg.checking_disabled)
        .with_protocol(protocol);
    let cookie = msg.edns.as_ref().and_then(|edns| {
        edns.options()
            .as_ref()
            .iter()
            .find_map(|(_, opt)| match opt {
                EdnsOption::Unknown(10, data) => Some(data.as_slice()),
                _ => None,
            })
    });
    if let Some(cookie) = cookie {
        request = request.with_cookie(cookie);
    }

    // Re-encoded behind a header so any compression pointer hickory emits is
    // relative to the message start, exactly where the response places it.
    let qdcount = u16::try_from(msg.queries.len()).ok()?;
    let mut questions = Message::new(0, MessageType::Query, OpCode::Query);
    questions.add_queries(std::mem::take(&mut msg.queries));
    let mut question = questions.to_vec().ok()?;
    question.drain(..12);

    let query = ClientQuery {
        id: msg.id,
        rd: msg.recursion_desired,
        cd: msg.checking_disabled,
        edns: msg.edns.as_ref().map(|edns| ClientEdns {
            dnssec_ok: edns.flags().dnssec_ok,
            udp_payload: edns.max_payload(),
        }),
        question: Cow::Owned(question),
        qdcount,
    };
    Some((query, request))
}

/// Builds the response for a domain-verdict block, honouring the configured
/// [`BlockPolicy`]. `NullIp` synthesizes a cacheable `0.0.0.0`/`::` answer
/// (NODATA for non-A/AAAA queries); other modes set the matching response
/// code with an empty answer section. Negative answers (NXDOMAIN / NODATA)
/// carry a synthetic SOA so they can be negatively cached. `Refused` keeps
/// the legacy error response.
pub fn build_blocked_wire(
    query: &ClientQuery<'_>,
    record_type: RecordType,
    policy: BlockPolicy,
    ede: Option<&ExtendedDnsError>,
) -> Vec<u8> {
    let negative = ResponseBody::NegativeSoa { ttl: policy.ttl };
    let (rcode, sinkhole) = match policy.mode {
        BlockResponseMode::Refused => {
            return query.respond(Rcode::Refused, false, ResponseBody::Empty, None, ede);
        }
        BlockResponseMode::NxDomain => (Rcode::NxDomain, None),
        BlockResponseMode::NoData => (Rcode::NoError, None),
        BlockResponseMode::NullIp => (
            Rcode::NoError,
            match record_type {
                RecordType::A => Some(IpAddr::V4(
                    policy.sinkhole_ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED),
                )),
                RecordType::AAAA => Some(IpAddr::V6(
                    policy.sinkhole_ipv6.unwrap_or(Ipv6Addr::UNSPECIFIED),
                )),
                _ => None,
            },
        ),
    };
    let body = match sinkhole.as_ref() {
        Some(address) => ResponseBody::Addresses {
            addresses: std::slice::from_ref(address),
            ttl: policy.ttl,
        },
        None => negative,
    };
    query.respond(rcode, false, body, None, ede)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));

    /// `(flags, name, qtype, OPT as (payload, DO, options))`
    type Case = (u16, &'static str, u16, Option<(u16, bool, &'static [u8])>);

    fn encode(id: u16, (flags, name, qtype, opt): Case) -> Vec<u8> {
        let mut buf = id.to_be_bytes().to_vec();
        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, u8::from(opt.is_some())]);
        for label in name.split('.').filter(|l| !l.is_empty()) {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&[0, 1]);
        if let Some((payload, dnssec_ok, options)) = opt {
            buf.extend_from_slice(&[0, 0, 41]);
            buf.extend_from_slice(&payload.to_be_bytes());
            buf.extend_from_slice(&[0, 0, u8::from(dnssec_ok) << 7, 0]);
            buf.extend_from_slice(&(options.len() as u16).to_be_bytes());
            buf.extend_from_slice(options);
        }
        buf
    }

    /// Every field the slow path reads must decode the same through the wire
    /// parser as through hickory, or answers would depend on which one ran.
    #[test]
    fn wire_parse_matches_hickory_parse() {
        const COOKIE: &[u8] = &[0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        const COOKIE_AFTER_PADDING: &[u8] = &[
            0, 12, 0, 3, 0, 0, 0, // padding
            0, 10, 0, 24, 9, 9, 9, 9, 9, 9, 9, 9, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2,
        ];
        let cases: &[Case] = &[
            (0x0100, "example.com", 1, None),
            (0x0000, "Example.COM", 28, None),
            (0x0110, "a.b.example.com", 1, Some((1232, false, &[]))),
            (0x0100, "example.com", 15, Some((4096, true, COOKIE))),
            (
                0x0130,
                "_dmarc.example.com",
                16,
                Some((300, true, COOKIE_AFTER_PADDING)),
            ),
            (0x0100, "", 2, Some((512, false, COOKIE))),
        ];
        for (i, &case) in cases.iter().enumerate() {
            let raw = encode(0x4000 + i as u16, case);
            let wire = fast_path::parse_query(&raw).expect("wire parser accepts the case");
            assert!(wire.edns_cookie(&raw).is_ok(), "case {i}");
            let (wq, wr) = parse_client_query(&raw, CLIENT, ClientProtocol::Udp).unwrap();
            let (hq, hr) = parse_client_query_hickory(&raw, CLIENT, ClientProtocol::Udp).unwrap();

            assert_eq!(wr.domain, hr.domain, "case {i}");
            assert_eq!(wr.record_type, hr.record_type, "case {i}");
            assert_eq!(wr.checking_disabled, hr.checking_disabled, "case {i}");
            assert_eq!(
                wr.edns_cookie.as_ref().map(EdnsCookie::as_bytes),
                hr.edns_cookie.as_ref().map(EdnsCookie::as_bytes),
                "case {i}"
            );
            assert_eq!((wq.id, wq.rd, wq.cd), (hq.id, hq.rd, hq.cd), "case {i}");
            assert_eq!(
                wq.edns.map(|e| (e.dnssec_ok, e.udp_payload.max(512))),
                hq.edns.map(|e| (e.dnssec_ok, e.udp_payload.max(512))),
                "case {i}"
            );
            assert_eq!(
                (&*wq.question, wq.qdcount),
                (&*hq.question, hq.qdcount),
                "case {i}"
            );
        }
    }

    #[test]
    fn malformed_edns_options_are_decoded_by_hickory() {
        // Option length 8 with 4 bytes present: the wire parser declines, and
        // the query is decoded exactly as hickory decodes it.
        let raw = encode(
            1,
            (
                0x0100,
                "example.com",
                1,
                Some((1232, false, &[0, 10, 0, 8, 1, 2, 3, 4])),
            ),
        );
        let wire = fast_path::parse_query(&raw).expect("the fixed header still parses");
        assert!(wire.edns_cookie(&raw).is_err());
        let routed = parse_client_query(&raw, CLIENT, ClientProtocol::Udp).map(|(q, r)| {
            (
                q.question.into_owned(),
                r.edns_cookie.map(|c| c.as_bytes().to_vec()),
            )
        });
        let hickory =
            parse_client_query_hickory(&raw, CLIENT, ClientProtocol::Udp).map(|(q, r)| {
                (
                    q.question.into_owned(),
                    r.edns_cookie.map(|c| c.as_bytes().to_vec()),
                )
            });
        assert_eq!(routed, hickory);
    }
}
