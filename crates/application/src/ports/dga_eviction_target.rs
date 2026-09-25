/// Port for evicting stale DGA tracking entries.
///
/// Used by the background eviction job to clean up expired data.
pub trait DgaEvictionTarget: Send + Sync + 'static {
    /// Removes stale entries older than the configured TTL.
    fn evict_stale(&self);
    /// Returns the number of currently tracked client stats.
    fn tracked_count(&self) -> usize;
    /// Returns the number of currently flagged domains.
    fn flagged_count(&self) -> usize;
}
