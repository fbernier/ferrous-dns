use super::strategy::ServerDisplays;
use crate::dns::forwarding::{DnsResponse, ResponseParser, ResponseValidator};
use crate::dns::transport;
use ferrous_dns_domain::{DnsProtocol, DomainError};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct QueryAttemptResult {
    pub response: DnsResponse,
    pub server_addr: SocketAddr,
    pub latency_ms: u64,
    pub server_display: Arc<str>,
}

fn get_display(protocol: &DnsProtocol, cache: &ServerDisplays) -> Arc<str> {
    cache
        .get(protocol)
        .map(Arc::clone)
        .unwrap_or_else(|| Arc::from(protocol.to_string()))
}

pub async fn query_server(
    protocol: &DnsProtocol,
    query_bytes: &[u8],
    timeout_ms: u64,
    validator: &ResponseValidator,
    server_displays: &Arc<ServerDisplays>,
) -> Result<QueryAttemptResult, DomainError> {
    let start = Instant::now();
    let timeout_duration = Duration::from_millis(timeout_ms);

    let dns_transport = transport::get_or_create_transport(protocol)?;

    let transport_response = dns_transport.send(query_bytes, timeout_duration).await?;

    let mut dns_response = ResponseParser::parse_bytes(transport_response.bytes)?;

    // Reject spoofed/off-path responses before acting on them (incl. before the
    // TCP-on-truncation retry below), so a forged TC=1 packet can't waste a retry.
    validator.validate(&dns_response, protocol)?;
    // Only now that the case echo has been checked: strip our 0x20 randomization,
    // so nothing downstream (cache included) ever holds a randomized QNAME.
    validator.canonicalize(&mut dns_response);

    if dns_response.truncated {
        if let DnsProtocol::Udp { addr } = protocol {
            let tcp_protocol = DnsProtocol::Tcp { addr: addr.clone() };
            let tcp_transport = transport::get_or_create_transport(&tcp_protocol)?;

            let remaining = timeout_duration
                .checked_sub(start.elapsed())
                .unwrap_or(Duration::from_millis(500));

            let tcp_response = tcp_transport.send(query_bytes, remaining).await?;
            let mut tcp_dns_response = ResponseParser::parse_bytes(tcp_response.bytes)?;
            validator.validate(&tcp_dns_response, &tcp_protocol)?;
            validator.canonicalize(&mut tcp_dns_response);

            let latency_ms = start.elapsed().as_millis() as u64;
            let server_addr = protocol
                .socket_addr()
                .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));

            return Ok(QueryAttemptResult {
                response: tcp_dns_response,
                server_addr,
                latency_ms,
                server_display: get_display(&tcp_protocol, server_displays),
            });
        }
    }

    let latency_ms = start.elapsed().as_millis() as u64;
    let server_addr = protocol
        .socket_addr()
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));

    Ok(QueryAttemptResult {
        response: dns_response,
        server_addr,
        latency_ms,
        server_display: get_display(protocol, server_displays),
    })
}
