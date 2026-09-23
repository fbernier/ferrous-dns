use super::balanced::BalancedStrategy;
use super::failover::FailoverStrategy;
use super::parallel::ParallelStrategy;
use crate::dns::forwarding::{DnsResponse, ResponseValidator};
use ferrous_dns_domain::{DnsProtocol, DomainError};
use rustc_hash::FxBuildHasher;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

/// Display name per configured upstream. Keys are config, not client input,
/// so the non-DoS-resistant Fx hasher is safe here.
pub type ServerDisplays = HashMap<Arc<DnsProtocol>, Arc<str>, FxBuildHasher>;

#[derive(Debug, Clone)]
pub struct UpstreamResult {
    pub response: DnsResponse,
    pub server: SocketAddr,
    pub latency_ms: u64,
    pub pool_name: Arc<str>,
    pub server_display: Arc<str>,
}

pub struct QueryContext<'a> {
    pub servers: &'a [&'a Arc<DnsProtocol>],
    pub domain: &'a Arc<str>,
    pub timeout_ms: u64,
    pub query_bytes: Arc<[u8]>,
    pub validator: &'a Arc<ResponseValidator>,
    pub pool_name: &'a Arc<str>,
    pub server_displays: &'a Arc<ServerDisplays>,
}

pub enum Strategy {
    Parallel(ParallelStrategy),
    Balanced(BalancedStrategy),
    Failover(FailoverStrategy),
}

impl Strategy {
    pub async fn query_refs(&self, ctx: &QueryContext<'_>) -> Result<UpstreamResult, DomainError> {
        match self {
            Self::Parallel(s) => s.query_refs(ctx).await,
            Self::Balanced(s) => s.query_refs(ctx).await,
            Self::Failover(s) => s.query_refs(ctx).await,
        }
    }
}
