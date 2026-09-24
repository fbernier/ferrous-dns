use std::net::IpAddr;

/// Hot-path: O(1) check if an IP is a known NXDomain hijack IP.
///
/// Implemented by the infrastructure layer's `NxdomainHijackDetector`.
/// Called on the hot path — implementations must be O(1) and lock-free.
pub trait NxdomainHijackIpStore: Send + Sync {
    /// Returns `true` if the IP belongs to an ISP's NXDomain hijack server.
    fn is_hijack_ip(&self, ip: &IpAddr) -> bool;
}
