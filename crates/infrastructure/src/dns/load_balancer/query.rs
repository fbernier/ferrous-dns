use super::strategy::{QueryContext, ServerDisplays, UpstreamResult};
use crate::dns::forwarding::forwarder::exchange_with_tc_retry;
use ferrous_dns_domain::{DnsProtocol, DomainError};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn get_display(protocol: &DnsProtocol, cache: &ServerDisplays) -> Arc<str> {
    cache
        .get(protocol)
        .map(Arc::clone)
        .unwrap_or_else(|| Arc::from(protocol.to_string()))
}

/// One attempt against `protocol` within the pool query described by `ctx`.
pub(super) async fn query_server(
    ctx: &QueryContext<'_>,
    protocol: &DnsProtocol,
) -> Result<UpstreamResult, DomainError> {
    let start = Instant::now();
    let (response, tcp_retry) = exchange_with_tc_retry(
        protocol,
        ctx.query_bytes,
        ctx.validator,
        Duration::from_millis(ctx.timeout_ms),
    )
    .await?;

    let display = get_display(protocol, ctx.server_displays);
    Ok(UpstreamResult {
        response,
        latency_ms: start.elapsed().as_millis() as u64,
        pool_name: Arc::clone(ctx.pool_name),
        // Keeps the configured name: the TCP retry reaches the same server.
        server_display: if tcp_retry {
            Arc::from(format!("{display} (tcp retry)"))
        } else {
            display
        },
    })
}
