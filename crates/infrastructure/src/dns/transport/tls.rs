use super::tcp::{connect_tcp, exchange_framed, IdlePool};
use super::{require_resolved, tls_client_config};
use bytes::Bytes;
use ferrous_dns_domain::{DomainError, UpstreamAddr};
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::{timeout_at, Instant};
use tokio_rustls::client::TlsStream;
use tracing::debug;

const MAX_IDLE_PER_HOST: usize = 12;

static SHARED_TLS_CONFIG: LazyLock<Arc<rustls::ClientConfig>> =
    LazyLock::new(|| Arc::new(tls_client_config()));

pub struct TlsTransport {
    upstream_addr: UpstreamAddr,
    server_name: ServerName<'static>,
    // Per transport, i.e. per (address, hostname): a connection to one resolved
    // address must never answer for another, or health checks lie.
    idle: IdlePool<TlsStream<TcpStream>>,
}

impl TlsTransport {
    pub fn new(upstream_addr: UpstreamAddr, hostname: &str) -> Result<Self, DomainError> {
        let server_name = ServerName::try_from(hostname.to_owned()).map_err(|e| {
            DomainError::ConfigError(format!("Invalid TLS hostname '{hostname}': {e}"))
        })?;
        Ok(Self {
            upstream_addr,
            server_name,
            idle: IdlePool::new(MAX_IDLE_PER_HOST),
        })
    }

    async fn connect_new(
        &self,
        server_addr: SocketAddr,
        deadline: Instant,
    ) -> Result<TlsStream<TcpStream>, DomainError> {
        let tcp_stream = connect_tcp(server_addr, deadline, "TLS").await?;
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(&SHARED_TLS_CONFIG));

        let tls_stream = timeout_at(
            deadline,
            connector.connect(self.server_name.clone(), tcp_stream),
        )
        .await
        .map_err(|_| {
            DomainError::IoError(format!("Timeout during TLS handshake with {}", server_addr))
        })?
        .map_err(|e| {
            DomainError::IoError(format!("TLS handshake failed with {}: {}", server_addr, e))
        })?;

        debug!(server = %server_addr, server_name = ?self.server_name, "TLS connection established");
        Ok(tls_stream)
    }

    pub async fn send(
        &self,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<Bytes, DomainError> {
        let server_addr = require_resolved(&self.upstream_addr, "TLS")?;
        let deadline = Instant::now() + timeout;

        if let Some(mut stream) = self.idle.take() {
            match exchange_framed(&mut stream, message_bytes, deadline, server_addr, "TLS").await {
                Ok(response) => {
                    debug!(server = %server_addr, "TLS query via pooled connection");
                    self.idle.park(stream);
                    return Ok(Bytes::from(response));
                }
                Err(e) if Instant::now() >= deadline => return Err(e),
                Err(_) => {
                    debug!(server = %server_addr, "Pooled TLS connection stale, reconnecting");
                }
            }
        }

        let mut stream = self.connect_new(server_addr, deadline).await?;
        let response =
            exchange_framed(&mut stream, message_bytes, deadline, server_addr, "TLS").await?;

        debug!(
            server = %server_addr,
            response_len = response.len(),
            "TLS response received"
        );

        self.idle.park(stream);
        Ok(Bytes::from(response))
    }
}
