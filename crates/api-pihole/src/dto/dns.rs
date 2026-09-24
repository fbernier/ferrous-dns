use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Pi-hole v6 GET/POST /api/dns/blocking response.
#[derive(Debug, Serialize, ToSchema)]
pub struct BlockingStatusResponse {
    pub blocking: bool,
    /// Seconds until the blocking mode flips back; `null` when no timer is pending.
    pub timer: Option<u64>,
}

/// Pi-hole v6 POST /api/dns/blocking request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetBlockingRequest {
    pub blocking: bool,
    /// Seconds after which `blocking` flips back; absent or 0 means no timer.
    pub timer: Option<u64>,
}
