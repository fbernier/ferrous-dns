/// Background job: eviction of stale hijack IPs and status reporting.
///
/// Used by the background eviction job to clean up expired data.
pub trait NxdomainHijackProbeTarget: Send + Sync + 'static {
    /// Removes hijack IPs not re-confirmed within the configured TTL.
    fn evict_stale_ips(&self);
    /// Returns the number of currently known hijack IPs.
    fn hijack_ip_count(&self) -> usize;
    /// Returns the number of upstreams currently detected as hijacking.
    fn hijacking_upstream_count(&self) -> usize;
}
