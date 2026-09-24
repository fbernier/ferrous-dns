use super::require_resolved;
use super::udp_pool::UdpSocketPool;
use bytes::Bytes;
use ferrous_dns_domain::{DomainError, UpstreamAddr};
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::Instant;
use tracing::debug;

static DEFAULT_UDP_POOL: LazyLock<Arc<UdpSocketPool>> =
    LazyLock::new(|| Arc::new(UdpSocketPool::new(4, 64)));

const MAX_UDP_RESPONSE_SIZE: usize = 4096;

fn same_message_id(query_bytes: &[u8], response_bytes: &[u8]) -> bool {
    matches!(
        (query_bytes.get(..2), response_bytes.get(..2)),
        (Some(query_id), Some(response_id)) if query_id == response_id
    )
}

/// Receive datagrams on `socket` until one arrives from the expected server
/// with the matching DNS message ID, or `deadline` passes.
///
/// The socket comes from a pool and is not connected, so it may deliver a late
/// response left over from a previous query on it, or a datagram from any
/// other source. Both are dropped and the loop keeps waiting until the
/// deadline, since they say nothing about the query currently in flight.
async fn recv_matching(
    socket: &UdpSocket,
    query_bytes: &[u8],
    server_addr: SocketAddr,
    deadline: Instant,
) -> Result<Bytes, DomainError> {
    let mut recv_buf = [0u8; MAX_UDP_RESPONSE_SIZE];

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(DomainError::IoError(format!(
                "Timeout waiting for UDP response from {}",
                server_addr
            )));
        }

        let (bytes_received, from_addr) =
            match tokio::time::timeout(remaining, socket.recv_from(&mut recv_buf)).await {
                Err(_) => {
                    return Err(DomainError::IoError(format!(
                        "Timeout waiting for UDP response from {}",
                        server_addr
                    )))
                }
                Ok(Err(e)) => {
                    return Err(DomainError::IoError(format!(
                        "Failed to receive UDP response from {}: {}",
                        server_addr, e
                    )))
                }
                Ok(Ok(v)) => v,
            };

        if from_addr.ip() != server_addr.ip() {
            debug!(
                server = %server_addr,
                actual = %from_addr.ip(),
                "Draining UDP datagram from unexpected source (anti-spoofing)"
            );
            continue;
        }
        let response = &recv_buf[..bytes_received];
        if !same_message_id(query_bytes, response) {
            debug!(
                server = %server_addr,
                "Draining stale/duplicate UDP datagram (message ID mismatch)"
            );
            continue;
        }

        return Ok(Bytes::copy_from_slice(response));
    }
}

pub struct UdpTransport {
    upstream_addr: UpstreamAddr,
    pool: Arc<UdpSocketPool>,
}

impl UdpTransport {
    pub fn new(upstream_addr: UpstreamAddr) -> Self {
        Self::with_pool(upstream_addr, Arc::clone(&DEFAULT_UDP_POOL))
    }

    pub fn with_pool(upstream_addr: UpstreamAddr, pool: Arc<UdpSocketPool>) -> Self {
        Self {
            upstream_addr,
            pool,
        }
    }

    pub async fn send(
        &self,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<Bytes, DomainError> {
        let server_addr = require_resolved(&self.upstream_addr, "UDP")?;

        // Admission, send, and receive share the caller's single query budget.
        let deadline = Instant::now() + timeout;
        let mut pooled = tokio::time::timeout_at(deadline, self.pool.acquire(server_addr))
            .await
            // Local saturation must stay failover-eligible, like any transport timeout.
            .map_err(|_| DomainError::TransportTimeout {
                server: server_addr.to_string(),
            })?
            .map_err(|e| DomainError::IoError(format!("Failed to acquire UDP socket: {e}")))?;

        let socket = pooled.socket();

        let bytes_sent =
            tokio::time::timeout_at(deadline, socket.send_to(message_bytes, server_addr))
                .await
                .map_err(|_| {
                    DomainError::IoError(format!("Timeout sending UDP query to {}", server_addr))
                })?
                .map_err(|e| {
                    DomainError::IoError(format!(
                        "Failed to send UDP query to {}: {}",
                        server_addr, e
                    ))
                })?;

        debug!(server = %server_addr, bytes_sent, "UDP query sent");

        // On any failure (incl. timeout) the socket may still have our
        // response in flight, so poison it rather than returning it to the
        // pool where it would corrupt the next query.
        let bytes = match recv_matching(socket, message_bytes, server_addr, deadline).await {
            Ok(bytes) => bytes,
            Err(e) => {
                pooled.poison();
                return Err(e);
            }
        };

        debug!(
            server = %server_addr,
            bytes_received = bytes.len(),
            "UDP response received"
        );

        Ok(bytes)
    }
}
