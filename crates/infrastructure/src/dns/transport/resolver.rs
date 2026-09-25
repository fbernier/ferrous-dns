use ferrous_dns_domain::DomainError;
use std::net::SocketAddr;
use std::time::Duration;

/// Resolves a hostname to all its IP addresses (IPv4 + IPv6).
pub async fn resolve_all(
    hostname: &str,
    port: u16,
    timeout: Duration,
) -> Result<Vec<SocketAddr>, DomainError> {
    let target = || format!("{hostname}:{port}");

    let addrs: Vec<SocketAddr> =
        tokio::time::timeout(timeout, tokio::net::lookup_host((hostname, port)))
            .await
            .map_err(|_| DomainError::TransportTimeout { server: target() })?
            .map_err(|e| {
                DomainError::IoError(format!("DNS resolution failed for {}: {}", target(), e))
            })?
            .collect();

    if addrs.is_empty() {
        return Err(DomainError::IoError(format!(
            "No addresses found for {}",
            target()
        )));
    }

    Ok(addrs)
}
