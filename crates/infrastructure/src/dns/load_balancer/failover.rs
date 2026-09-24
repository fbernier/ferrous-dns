use super::query::query_server;
use super::strategy::{QueryContext, UpstreamResult};
use ferrous_dns_domain::DomainError;
use tracing::{debug, warn};

/// Tries servers in configured order, moving on only when one fails.
pub(super) async fn query(ctx: &QueryContext<'_>) -> Result<UpstreamResult, DomainError> {
    if ctx.servers.is_empty() {
        return Err(DomainError::TransportNoHealthyServers);
    }
    debug!(strategy = "failover", servers = ctx.servers.len(), domain = %ctx.domain, "Trying sequentially");

    for (index, protocol) in ctx.servers.iter().enumerate() {
        match query_server(ctx, protocol).await {
            Ok(r) => {
                debug!(server = %r.server, latency_ms = r.latency_ms, position = index, "Server responded");
                return Ok(r);
            }
            Err(e) => {
                warn!(protocol = %protocol, error = %e, position = index, "Failing over");
            }
        }
    }
    Err(DomainError::TransportAllServersUnreachable)
}
