use super::data::{CachedData, CachedDnssecStatus};
use ferrous_dns_domain::RecordType;

/// How permanent records at a name apply to the requested record type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalRecordStatus {
    /// No permanent record answers or owns this query.
    NotLocal,
    /// The requested type has a permanent entry, including non-address types.
    Present,
    /// A permanent A/AAAA record owns the name, but this type is not configured.
    MissingType,
}

pub trait DnsCacheAccess: Send + Sync {
    fn get(
        &self,
        domain: &str,
        record_type: &RecordType,
    ) -> Option<(CachedData, Option<CachedDnssecStatus>, Option<u32>)>;

    /// Checks the requested type and name ownership in one lookup.
    fn local_record_status(&self, domain: &str, record_type: &RecordType) -> LocalRecordStatus;

    fn insert(
        &self,
        domain: &str,
        record_type: RecordType,
        data: CachedData,
        ttl: u32,
        dnssec_status: Option<CachedDnssecStatus>,
    );

    /// Phase 6: records a transient upstream error that was explicitly NOT
    /// cached as a negative response (timeout, connection refused/reset,
    /// no healthy servers, etc.). Default is a no-op so test doubles don't
    /// have to implement metrics.
    #[inline]
    fn record_transient_upstream_error(&self) {}
}
