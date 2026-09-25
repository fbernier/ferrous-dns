use super::message_builder::{HardeningOpts, MessageBuilder};
use super::response_parser::{DnsResponse, ResponseParser};
use super::response_validator::ResponseValidator;
use crate::dns::transport;
use ferrous_dns_domain::{DnsProtocol, DomainError, RecordType, UpstreamAddr};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Budget for the TCP retry when the UDP attempt already spent the whole timeout.
const TC_RETRY_FLOOR: Duration = Duration::from_millis(500);

/// Queries `local_dns_server` — the LAN router — for local names and private
/// PTRs. Its answers are relayed to clients as raw wire bytes, so it gets the
/// same anti-spoofing as the upstream pools: a hardened query, the shared UDP
/// transport (which skips datagrams from another source or with another
/// transaction ID), response validation, and a TCP retry on truncation.
pub struct DnsForwarder {
    hardening: HardeningOpts,
}

impl DnsForwarder {
    /// `hardening` should be the upstream pools', so `qname_case_randomization`
    /// covers the local server too.
    pub fn new(hardening: HardeningOpts) -> Self {
        Self { hardening }
    }

    pub async fn query(
        &self,
        server: SocketAddr,
        domain: &str,
        record_type: &RecordType,
        timeout_ms: u64,
    ) -> Result<DnsResponse, DomainError> {
        let (query_bytes, validator) =
            MessageBuilder::build_query_hardened(domain, record_type, false, self.hardening)?;
        let udp = DnsProtocol::Udp {
            addr: UpstreamAddr::Resolved(server),
        };
        let (response, _) = exchange_with_tc_retry(
            &udp,
            &query_bytes,
            &validator,
            Duration::from_millis(timeout_ms),
        )
        .await?;
        Ok(response)
    }
}

/// One validated round trip over `protocol`, retried over TCP when a UDP answer
/// comes back truncated. Also returns whether the TCP retry produced the answer.
pub(crate) async fn exchange_with_tc_retry(
    protocol: &DnsProtocol,
    query_bytes: &[u8],
    validator: &ResponseValidator,
    timeout: Duration,
) -> Result<(DnsResponse, bool), DomainError> {
    let start = Instant::now();
    let response = exchange(protocol, query_bytes, validator, timeout).await?;
    let DnsProtocol::Udp { addr } = protocol else {
        return Ok((response, false));
    };
    if !response.truncated {
        return Ok((response, false));
    }

    let tcp = DnsProtocol::Tcp { addr: addr.clone() };
    let remaining = timeout
        .checked_sub(start.elapsed())
        .unwrap_or(TC_RETRY_FLOOR);
    let response = exchange(&tcp, query_bytes, validator, remaining).await?;
    Ok((response, true))
}

/// One round trip over `protocol`. Validation runs before anything reads the
/// answer — so a forged TC=1 cannot waste a TCP retry — and our 0x20 case is
/// stripped right after, so nothing downstream ever holds a randomized QNAME.
async fn exchange(
    protocol: &DnsProtocol,
    query_bytes: &[u8],
    validator: &ResponseValidator,
    timeout: Duration,
) -> Result<DnsResponse, DomainError> {
    let reply = transport::get_or_create_transport(protocol)?
        .send(query_bytes, timeout)
        .await?;
    let mut response = ResponseParser::parse_bytes(reply)?;
    validator.validate(&response, protocol)?;
    validator.canonicalize(&mut response);
    Ok(response)
}
