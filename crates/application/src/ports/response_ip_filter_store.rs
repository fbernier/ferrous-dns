use std::net::IpAddr;

/// Hot-path: O(1) check if an IP is a known C2 IP from threat feeds.
///
/// Implemented by the infrastructure layer's `ResponseIpFilterDetector`.
/// Called on the hot path — implementations must be O(1) and lock-free.
pub trait ResponseIpFilterStore: Send + Sync {
    /// Returns `true` if the IP is in a downloaded C2 threat feed.
    fn is_blocked_ip(&self, ip: &IpAddr) -> bool;
}
