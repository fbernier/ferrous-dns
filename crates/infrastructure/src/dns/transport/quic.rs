use super::tcp::{read_with_length_prefix, send_with_length_prefix};
use super::{endpoint_for, quic_client_endpoint, require_resolved};
use bytes::{Buf, Bytes};
use dashmap::DashMap;
use ferrous_dns_domain::{DomainError, UpstreamAddr};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tracing::debug;

type PoolKey = (SocketAddr, Arc<str>);

static QUIC_ENDPOINT_V4: LazyLock<Result<quinn::Endpoint, String>> =
    LazyLock::new(|| quic_client_endpoint(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)), b"doq"));

static QUIC_ENDPOINT_V6: LazyLock<Result<quinn::Endpoint, String>> =
    LazyLock::new(|| quic_client_endpoint(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)), b"doq"));

const QUIC_CONN_TTL: Duration = Duration::from_secs(300);

static QUIC_POOL: LazyLock<DashMap<PoolKey, (quinn::Connection, Instant)>> =
    LazyLock::new(DashMap::new);

pub struct QuicTransport {
    upstream_addr: UpstreamAddr,
    hostname: Arc<str>,
}

impl QuicTransport {
    pub fn new(upstream_addr: UpstreamAddr, hostname: Arc<str>) -> Self {
        Self {
            upstream_addr,
            hostname,
        }
    }

    fn resolved_addr(&self) -> Result<SocketAddr, DomainError> {
        require_resolved(&self.upstream_addr, "QUIC")
    }

    fn pool_key(&self) -> Result<PoolKey, DomainError> {
        let server_addr = self.resolved_addr()?;
        Ok((server_addr, Arc::clone(&self.hostname)))
    }

    async fn get_or_connect(&self, timeout: Duration) -> Result<quinn::Connection, DomainError> {
        let key = self.pool_key()?;

        if let Some(entry) = QUIC_POOL.get(&key) {
            let (conn, created_at) = entry.value();
            if created_at.elapsed() < QUIC_CONN_TTL && conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
            drop(entry);
            QUIC_POOL.remove(&key);
        }

        let conn = self.connect_new(timeout).await?;
        let now = Instant::now();
        match QUIC_POOL.entry(key) {
            dashmap::Entry::Occupied(e) => {
                let (existing, created_at) = e.get();
                if created_at.elapsed() < QUIC_CONN_TTL && existing.close_reason().is_none() {
                    Ok(existing.clone())
                } else {
                    e.replace_entry((conn.clone(), now));
                    Ok(conn)
                }
            }
            dashmap::Entry::Vacant(e) => {
                e.insert((conn.clone(), now));
                Ok(conn)
            }
        }
    }

    async fn connect_new(&self, timeout: Duration) -> Result<quinn::Connection, DomainError> {
        let server_addr = self.resolved_addr()?;
        let endpoint = endpoint_for(&server_addr, &QUIC_ENDPOINT_V4, &QUIC_ENDPOINT_V6)?;

        let connecting = endpoint
            .connect(server_addr, self.hostname.as_ref())
            .map_err(|e| {
                DomainError::IoError(format!(
                    "Failed to initiate QUIC connection to {}: {}",
                    server_addr, e
                ))
            })?;

        tokio::time::timeout(timeout, connecting)
            .await
            .map_err(|_| DomainError::TransportTimeout {
                server: server_addr.to_string(),
            })?
            .map_err(|e| DomainError::TransportConnectionRefused {
                server: format!("{}({}): {}", self.hostname, server_addr, e),
            })
    }

    /// Sends with Message ID 0, as RFC 9250 §4.2.1 requires on DoQ, and gives the
    /// answer back the caller's ID so validation downstream is transport-agnostic.
    async fn send_on_stream(
        conn: &quinn::Connection,
        message_bytes: &[u8],
        timeout: Duration,
        server_addr: SocketAddr,
    ) -> Result<Vec<u8>, DomainError> {
        let Some((id, rest)) = message_bytes.split_first_chunk::<2>() else {
            return Err(DomainError::IoError(format!(
                "DNS message to {server_addr} is shorter than its ID"
            )));
        };
        let deadline = Instant::now() + timeout;

        let (mut send_stream, mut recv_stream) = tokio::time::timeout(timeout, conn.open_bi())
            .await
            .map_err(|_| DomainError::TransportTimeout {
                server: server_addr.to_string(),
            })?
            .map_err(|e| {
                DomainError::IoError(format!(
                    "Failed to open QUIC stream to {}: {}",
                    server_addr, e
                ))
            })?;

        let remaining = deadline.saturating_duration_since(Instant::now());
        tokio::time::timeout(
            remaining,
            send_with_length_prefix(&mut send_stream, Buf::chain(&[0u8; 2][..], rest)),
        )
        .await
        .map_err(|_| DomainError::TransportTimeout {
            server: server_addr.to_string(),
        })??;

        send_stream.finish().map_err(|e| {
            DomainError::IoError(format!(
                "Failed to finish QUIC send stream to {}: {}",
                server_addr, e
            ))
        })?;

        let remaining = deadline.saturating_duration_since(Instant::now());
        let mut response =
            tokio::time::timeout(remaining, read_with_length_prefix(&mut recv_stream))
                .await
                .map_err(|_| DomainError::TransportTimeout {
                    server: server_addr.to_string(),
                })??;
        if let Some(response_id) = response.first_chunk_mut::<2>() {
            *response_id = *id;
        }
        Ok(response)
    }

    pub async fn send(
        &self,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<Bytes, DomainError> {
        let deadline = Instant::now() + timeout;
        let server_addr = self.resolved_addr()?;
        let conn = self.get_or_connect(timeout).await?;

        match Self::send_on_stream(&conn, message_bytes, timeout, server_addr).await {
            Ok(response_bytes) => {
                debug!(server = %server_addr, "QUIC query via pooled connection");
                return Ok(Bytes::from(response_bytes));
            }
            Err(_) => {
                if let Ok(key) = self.pool_key() {
                    QUIC_POOL.remove(&key);
                }
                debug!(server = %server_addr, "QUIC connection stale, reconnecting");
            }
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(DomainError::TransportTimeout {
                server: server_addr.to_string(),
            });
        }

        let conn = self.connect_new(remaining).await?;
        QUIC_POOL.insert(self.pool_key()?, (conn.clone(), Instant::now()));

        let remaining = deadline.saturating_duration_since(Instant::now());
        let response_bytes =
            Self::send_on_stream(&conn, message_bytes, remaining, server_addr).await?;

        debug!(
            server = %server_addr,
            response_len = response_bytes.len(),
            "QUIC response received"
        );

        Ok(Bytes::from(response_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::{QuicTransport, QUIC_POOL};
    use ferrous_dns_domain::UpstreamAddr;
    use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::io::AsyncReadExt;

    const TIMEOUT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn test_doq_sends_message_id_zero_and_restores_it_on_the_answer() {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut server_tls = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
            )
            .unwrap();
        server_tls.alpn_protocols = vec![b"doq".to_vec()];
        let server = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(
                QuicServerConfig::try_from(server_tls).unwrap(),
            )),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let mut client_tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"doq".to_vec()];
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(client_tls).unwrap(),
        )));

        let transport = QuicTransport::new(UpstreamAddr::Resolved(server_addr), "localhost".into());
        let query = [0xAB, 0xCD, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];

        let serve = async {
            let connection = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let len = usize::from(recv.read_u16().await.unwrap());
            let mut received = vec![0; len];
            recv.read_exact(&mut received).await.unwrap();
            // Echo verbatim: a conforming server answers with the ID it was sent.
            let mut reply = (len as u16).to_be_bytes().to_vec();
            reply.extend_from_slice(&received);
            send.write_all(&reply).await.unwrap();
            send.finish().unwrap();
            connection.closed().await;
            received
        };
        let ask = async {
            let connection = client
                .connect(server_addr, "localhost")
                .unwrap()
                .await
                .unwrap();
            QUIC_POOL.insert(
                (server_addr, Arc::from("localhost")),
                (connection.clone(), Instant::now()),
            );
            let answer = transport.send(&query, TIMEOUT).await;
            QUIC_POOL.remove(&(server_addr, Arc::from("localhost")));
            connection.close(0u32.into(), b"done");
            answer
        };

        let (received, answer) = tokio::time::timeout(TIMEOUT, async { tokio::join!(serve, ask) })
            .await
            .expect("DoQ exchange timed out");

        assert_eq!(
            &received[..2],
            &[0, 0],
            "DoQ queries must carry Message ID 0"
        );
        assert_eq!(&received[2..], &query[2..]);
        assert_eq!(answer.unwrap().as_ref(), &query[..]);
    }
}
