use ferrous_dns_application::ports::{
    AggregateStatus, IpFamily, ResolvedEndpointHealth, UpstreamGroupHealth, UpstreamStatus,
};
use serde::Serialize;
use utoipa::ToSchema;

pub fn upstream_status_str(status: UpstreamStatus) -> &'static str {
    match status {
        UpstreamStatus::Healthy => "Healthy",
        UpstreamStatus::Unhealthy => "Unhealthy",
        UpstreamStatus::Unknown => "Unknown",
    }
}

fn aggregate_status_str(status: AggregateStatus) -> &'static str {
    match status {
        AggregateStatus::Healthy => "Healthy",
        AggregateStatus::Partial => "Partial",
        AggregateStatus::Unhealthy => "Unhealthy",
        AggregateStatus::Unknown => "Unknown",
    }
}

pub fn ip_family_str(family: IpFamily) -> &'static str {
    match family {
        IpFamily::Ipv4 => "ipv4",
        IpFamily::Ipv6 => "ipv6",
        IpFamily::Unknown => "unknown",
    }
}

/// Per-IP endpoint detail within a server group.
#[derive(Debug, Serialize, ToSchema)]
pub struct ResolvedEndpointResponse {
    pub address: String,
    /// `ipv4`, `ipv6` or `unknown`.
    #[schema(value_type = String)]
    pub family: &'static str,
    /// `Healthy`, `Unhealthy` or `Unknown`.
    #[schema(value_type = String)]
    pub status: &'static str,
    pub latency_ms: Option<u64>,
    pub last_error: Option<String>,
    pub consecutive_failures: u16,
}

impl From<ResolvedEndpointHealth> for ResolvedEndpointResponse {
    fn from(r: ResolvedEndpointHealth) -> Self {
        Self {
            address: r.address,
            family: ip_family_str(r.family),
            status: upstream_status_str(r.status),
            latency_ms: r.latency_ms,
            last_error: r.last_error,
            consecutive_failures: r.consecutive_failures,
        }
    }
}

/// Grouped health: one entry per configured upstream server.
#[derive(Debug, Serialize, ToSchema)]
pub struct UpstreamGroupResponse {
    pub address: String,
    /// `Healthy`, `Partial`, `Unhealthy` or `Unknown`.
    #[schema(value_type = String)]
    pub status: &'static str,
    pub resolved: Vec<ResolvedEndpointResponse>,
    pub pool_name: String,
    /// `Parallel`, `Failover` or `Balanced`.
    pub strategy: String,
}

impl From<UpstreamGroupHealth> for UpstreamGroupResponse {
    fn from(g: UpstreamGroupHealth) -> Self {
        Self {
            address: g.address,
            status: aggregate_status_str(g.status),
            resolved: g
                .resolved
                .into_iter()
                .map(ResolvedEndpointResponse::from)
                .collect(),
            pool_name: g.pool_name,
            strategy: g.strategy.to_string(),
        }
    }
}
