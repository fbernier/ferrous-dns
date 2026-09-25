/// Background job: eviction of stale C2 IPs and status reporting.
///
/// Used by the background eviction job to clean up expired data.
pub trait ResponseIpFilterEvictionTarget: Send + Sync + 'static {
    /// Removes IPs not re-confirmed within the configured TTL.
    fn evict_stale_ips(&self);
    /// Returns the number of currently blocked C2 IPs.
    fn blocked_ip_count(&self) -> usize;
}
