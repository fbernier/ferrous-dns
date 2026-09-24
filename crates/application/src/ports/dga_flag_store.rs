/// Port for checking whether a domain has been flagged by the background
/// DGA analysis task.
///
/// Implemented by the infrastructure layer's `DgaDetector`.
/// Called on the hot path — implementations must be O(1) and lock-free.
pub trait DgaFlagStore: Send + Sync {
    /// Returns `true` if the domain has been flagged as a DGA domain.
    fn is_flagged(&self, domain: &str) -> bool;
}
