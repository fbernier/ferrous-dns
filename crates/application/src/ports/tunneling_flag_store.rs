/// Port for checking whether a domain has been flagged by the background
/// tunneling analysis task.
///
/// Implemented by the infrastructure layer's `TunnelingDetector`.
/// Called on the hot path — implementations must be O(1) and lock-free.
pub trait TunnelingFlagStore: Send + Sync {
    /// Returns `true` if the domain has been flagged as a tunneling endpoint.
    fn is_flagged(&self, domain: &str) -> bool;
}
