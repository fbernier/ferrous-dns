use super::{
    doh_response_too_large, endpoint_for, quic_client_endpoint, resolver, split_authority,
    MAX_DOH_MESSAGE_SIZE,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use ferrous_dns_domain::DomainError;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tracing::debug;

type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

fn stream_error(https_url: &str, error: h3::error::StreamError) -> DomainError {
    match error {
        h3::error::StreamError::ConnectionError { .. }
        | h3::error::StreamError::RemoteClosing { .. } => DomainError::TransportConnectionReset {
            server: format!("{https_url}: {error}"),
        },
        _ => DomainError::IoError(format!("H3 request to {https_url} failed: {error}")),
    }
}

static H3_QUIC_ENDPOINT_V4: LazyLock<Result<quinn::Endpoint, String>> =
    LazyLock::new(|| quic_client_endpoint(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)), b"h3"));

static H3_QUIC_ENDPOINT_V6: LazyLock<Result<quinn::Endpoint, String>> =
    LazyLock::new(|| quic_client_endpoint(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)), b"h3"));

const H3_CONN_TTL: Duration = Duration::from_secs(300);

static H3_POOL: LazyLock<DashMap<Arc<str>, (H3SendRequest, Instant)>> = LazyLock::new(DashMap::new);

pub struct H3Transport {
    https_url: String,
    hostname: String,
    port: u16,
    pool_key: Arc<str>,
    resolved_addrs: Vec<SocketAddr>,
}

impl H3Transport {
    pub fn new(h3_url: String, resolved_addrs: Vec<SocketAddr>) -> Self {
        let without_scheme = h3_url.strip_prefix("h3://").unwrap_or(&h3_url);
        let authority = without_scheme.split('/').next().unwrap_or(without_scheme);
        let (hostname, port) = split_authority(authority, 443);
        let hostname = hostname.to_owned();
        let https_url = h3_url.replacen("h3://", "https://", 1);
        let pool_key: Arc<str> = Arc::from(format!("{}:{}", hostname, port));
        Self {
            https_url,
            hostname,
            port,
            pool_key,
            resolved_addrs,
        }
    }

    async fn resolve_addr(&self, timeout: Duration) -> Result<SocketAddr, DomainError> {
        if let Some(addr) = self.resolved_addrs.first() {
            return Ok(*addr);
        }
        let addrs = resolver::resolve_all(&self.hostname, self.port, timeout).await?;
        addrs.first().copied().ok_or_else(|| {
            DomainError::IoError(format!(
                "No address found for {}:{}",
                self.hostname, self.port
            ))
        })
    }

    async fn connect_new(&self, timeout: Duration) -> Result<H3SendRequest, DomainError> {
        let addr = self.resolve_addr(timeout).await?;
        let endpoint = endpoint_for(&addr, &H3_QUIC_ENDPOINT_V4, &H3_QUIC_ENDPOINT_V6)?;

        let connecting = endpoint.connect(addr, &self.hostname).map_err(|e| {
            DomainError::IoError(format!(
                "Failed to initiate H3 connection to {}: {}",
                addr, e
            ))
        })?;

        let quinn_conn = tokio::time::timeout(timeout, connecting)
            .await
            .map_err(|_| DomainError::TransportTimeout {
                server: addr.to_string(),
            })?
            .map_err(|e| DomainError::TransportConnectionRefused {
                server: format!("{}({}): {}", self.hostname, addr, e),
            })?;

        let h3_conn = h3_quinn::Connection::new(quinn_conn);
        let (mut driver, send_request) = h3::client::new(h3_conn).await.map_err(|e| {
            DomainError::IoError(format!("Failed to create H3 client for {}: {}", addr, e))
        })?;

        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        Ok(send_request)
    }

    async fn get_or_connect(&self, timeout: Duration) -> Result<H3SendRequest, DomainError> {
        if let Some(entry) = H3_POOL.get(&self.pool_key) {
            let (request, created_at) = entry.value();
            if created_at.elapsed() < H3_CONN_TTL {
                return Ok(request.clone());
            }
            drop(entry);
            H3_POOL.remove(&self.pool_key);
        }
        let request = self.connect_new(timeout).await?;
        let now = Instant::now();
        match H3_POOL.entry(Arc::clone(&self.pool_key)) {
            dashmap::Entry::Occupied(e) => {
                let (existing, created_at) = e.get();
                if created_at.elapsed() < H3_CONN_TTL {
                    Ok(existing.clone())
                } else {
                    e.replace_entry((request.clone(), now));
                    Ok(request)
                }
            }
            dashmap::Entry::Vacant(e) => {
                e.insert((request.clone(), now));
                Ok(request)
            }
        }
    }

    async fn execute_request(
        send_request: &mut H3SendRequest,
        https_url: &str,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<Bytes, DomainError> {
        let deadline = Instant::now() + timeout;

        let request = http::Request::builder()
            .method("POST")
            .uri(https_url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .header("content-length", message_bytes.len())
            .body(())
            .map_err(|e| DomainError::IoError(format!("Failed to build H3 request: {}", e)))?;

        let mut stream = tokio::time::timeout(timeout, send_request.send_request(request))
            .await
            .map_err(|_| DomainError::TransportTimeout {
                server: https_url.to_string(),
            })?
            .map_err(|e| stream_error(https_url, e))?;

        let remaining = deadline.saturating_duration_since(Instant::now());
        tokio::time::timeout(
            remaining,
            stream.send_data(Bytes::copy_from_slice(message_bytes)),
        )
        .await
        .map_err(|_| DomainError::TransportTimeout {
            server: https_url.to_string(),
        })?
        .map_err(|e| stream_error(https_url, e))?;

        let remaining = deadline.saturating_duration_since(Instant::now());
        tokio::time::timeout(remaining, stream.finish())
            .await
            .map_err(|_| DomainError::TransportTimeout {
                server: https_url.to_string(),
            })?
            .map_err(|e| stream_error(https_url, e))?;

        let remaining = deadline.saturating_duration_since(Instant::now());
        let response = tokio::time::timeout(remaining, stream.recv_response())
            .await
            .map_err(|_| DomainError::TransportTimeout {
                server: https_url.to_string(),
            })?
            .map_err(|e| stream_error(https_url, e))?;

        if !response.status().is_success() {
            return Err(DomainError::IoError(format!(
                "H3 server {} returned HTTP {}",
                https_url,
                response.status().as_u16()
            )));
        }

        let content_length = response
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if content_length.is_some_and(|length| length > MAX_DOH_MESSAGE_SIZE as u64) {
            return Err(doh_response_too_large(https_url));
        }
        let mut body = BytesMut::with_capacity(content_length.unwrap_or(0) as usize);
        while let Some(chunk) = {
            let remaining = deadline.saturating_duration_since(Instant::now());
            tokio::time::timeout(remaining, stream.recv_data())
                .await
                .map_err(|_| DomainError::TransportTimeout {
                    server: https_url.to_string(),
                })?
                .map_err(|e| stream_error(https_url, e))?
        } {
            if chunk.remaining() > MAX_DOH_MESSAGE_SIZE - body.len() {
                return Err(doh_response_too_large(https_url));
            }
            body.put(chunk);
        }

        Ok(body.freeze())
    }

    pub async fn send(
        &self,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<Bytes, DomainError> {
        let deadline = Instant::now() + timeout;
        let mut send_request = self.get_or_connect(timeout).await?;

        match Self::execute_request(&mut send_request, &self.https_url, message_bytes, timeout)
            .await
        {
            Ok(response_bytes) => {
                debug!(url = %self.https_url, "DoH3 query via pooled connection");
                return Ok(response_bytes);
            }
            Err(error @ DomainError::TransportConnectionReset { .. }) => {
                H3_POOL.remove(&self.pool_key);
                debug!(url = %self.https_url, error = %error, "H3 connection unavailable, reconnecting");
            }
            Err(error) => return Err(error),
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(DomainError::TransportTimeout {
                server: self.pool_key.to_string(),
            });
        }

        let mut fresh_request = self.connect_new(remaining).await?;
        H3_POOL.insert(
            Arc::clone(&self.pool_key),
            (fresh_request.clone(), Instant::now()),
        );

        let remaining = deadline.saturating_duration_since(Instant::now());
        let response_bytes = Self::execute_request(
            &mut fresh_request,
            &self.https_url,
            message_bytes,
            remaining,
        )
        .await?;

        debug!(
            url = %self.https_url,
            response_len = response_bytes.len(),
            "DoH3 response received"
        );

        Ok(response_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::{H3Transport, H3_POOL};
    use bytes::{Buf, Bytes};
    use ferrous_dns_domain::DomainError;
    use http::{header::CONTENT_LENGTH, Method, StatusCode};
    use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use std::future::Future;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const TIMEOUT: Duration = Duration::from_secs(5);
    const TEST_TIMEOUT: Duration = Duration::from_secs(15);

    struct Loopback {
        server: quinn::Endpoint,
        client: quinn::Endpoint,
        transport: H3Transport,
    }

    impl Loopback {
        fn new() -> Self {
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
            server_tls.alpn_protocols = vec![b"h3".to_vec()];
            let config = quinn::ServerConfig::with_crypto(Arc::new(
                QuicServerConfig::try_from(server_tls).unwrap(),
            ));
            let server = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();

            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert.der().clone()).unwrap();
            let mut client_tls = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            client_tls.alpn_protocols = vec![b"h3".to_vec()];
            let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
                QuicClientConfig::try_from(client_tls).unwrap(),
            )));
            let addr = server.local_addr().unwrap();
            let transport = H3Transport::new(
                format!("h3://localhost:{}/dns-query", addr.port()),
                vec![addr],
            );
            Self {
                server,
                client,
                transport,
            }
        }

        async fn connect(&self) -> quinn::Connection {
            self.client
                .connect(self.server.local_addr().unwrap(), "localhost")
                .unwrap()
                .await
                .unwrap()
        }

        fn close(&self) {
            H3_POOL.remove(&self.transport.pool_key);
            self.server.close(0u32.into(), b"test complete");
            self.client.close(0u32.into(), b"test complete");
        }

        async fn run(&self, peers: impl Future<Output = ()>) {
            let result = tokio::time::timeout(TEST_TIMEOUT, peers).await;
            self.close();
            tokio::time::timeout(TEST_TIMEOUT, async {
                tokio::join!(self.server.wait_idle(), self.client.wait_idle());
            })
            .await
            .expect("QUIC shutdown timed out");
            result.expect("H3 exchange timed out");
        }
    }

    impl Drop for Loopback {
        fn drop(&mut self) {
            self.close();
        }
    }

    #[tokio::test]
    async fn test_h3_reconnects_after_connection_failure() {
        let peer = Loopback::new();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let server = async {
            let connection = peer.server.accept().await.unwrap().await.unwrap();
            ready_rx.await.unwrap();
            connection.close(0u32.into(), b"connection retired");
            // Refusal proves a new handshake was attempted without trusting test roots globally.
            peer.server
                .accept()
                .await
                .expect("missing reconnect")
                .refuse();
        };
        let client = async {
            let (mut driver, sender) =
                h3::client::new(h3_quinn::Connection::new(peer.connect().await))
                    .await
                    .unwrap();
            ready_tx.send(()).unwrap();
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
            H3_POOL.insert(
                Arc::clone(&peer.transport.pool_key),
                (sender, Instant::now()),
            );
            let result = peer.transport.send(&[0; 12], TIMEOUT).await;
            assert!(
                matches!(result, Err(DomainError::TransportConnectionRefused { .. })),
                "{result:?}"
            );
        };
        peer.run(async {
            tokio::join!(server, client);
        })
        .await;
    }

    #[tokio::test]
    async fn test_h3_request_framing_and_connection_reuse() {
        enum Reply {
            Status(StatusCode),
            AdvertisedSize(u64),
            StreamingBody(Bytes),
            Reset,
            CompleteBody(Bytes),
        }
        let replies = [
            Reply::CompleteBody(Bytes::from_static(b"response")),
            Reply::Status(StatusCode::LENGTH_REQUIRED),
            Reply::AdvertisedSize(65_536),
            Reply::StreamingBody(Bytes::from(vec![0; 65_536])),
            Reply::Reset,
            Reply::CompleteBody(Bytes::from(vec![42; 65_535])),
        ];
        let peer = Loopback::new();
        let (consumed_tx, mut consumed_rx) = tokio::sync::mpsc::channel(1);
        let server = async {
            let connection = peer.server.accept().await.unwrap().await.unwrap();
            let mut server = h3::server::Connection::new(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
            for reply in &replies {
                let (request, mut stream) = server
                    .accept()
                    .await
                    .unwrap()
                    .unwrap()
                    .resolve_request()
                    .await
                    .unwrap();
                let mut body_len = 0;
                while let Some(chunk) = stream.recv_data().await.unwrap() {
                    body_len += chunk.remaining();
                }
                assert_eq!(request.method(), Method::POST);
                assert_eq!(request.uri().path(), "/dns-query");
                assert_eq!(request.headers()[CONTENT_LENGTH], body_len.to_string());

                match reply {
                    Reply::Reset => stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED),
                    _ => {
                        let response = http::Response::builder()
                            .header("content-type", "application/dns-message");
                        let response = match reply {
                            Reply::Status(status) => response.status(*status),
                            Reply::AdvertisedSize(size) => response.header(CONTENT_LENGTH, *size),
                            Reply::CompleteBody(body) => {
                                response.header(CONTENT_LENGTH, body.len())
                            }
                            _ => response,
                        };
                        stream
                            .send_response(response.body(()).unwrap())
                            .await
                            .unwrap();
                        if let Reply::StreamingBody(body) | Reply::CompleteBody(body) = reply {
                            stream.send_data(body.clone()).await.unwrap();
                        }
                        if let Reply::CompleteBody(_) = reply {
                            stream.finish().await.unwrap();
                        }
                    }
                }
                // Error replies stay open: rejection must not wait for EOF.
                consumed_rx.recv().await.unwrap();
            }
        };
        let client = async {
            let (mut driver, sender) =
                h3::client::new(h3_quinn::Connection::new(peer.connect().await))
                    .await
                    .unwrap();
            H3_POOL.insert(
                Arc::clone(&peer.transport.pool_key),
                (sender, Instant::now()),
            );
            let exchange = async {
                for (index, reply) in replies.iter().enumerate() {
                    let query = vec![0; 12 + index];
                    let result = peer.transport.send(&query, TIMEOUT).await;
                    match reply {
                        Reply::CompleteBody(expected) => {
                            assert_eq!(result.unwrap(), *expected)
                        }
                        _ => assert!(matches!(result, Err(DomainError::IoError(_))), "{result:?}"),
                    }
                    consumed_tx.send(()).await.unwrap();
                }
            };
            tokio::select! {
                () = exchange => {},
                error = std::future::poll_fn(|cx| driver.poll_close(cx)) => panic!("H3 connection closed: {error}"),
            }
        };
        peer.run(async {
            tokio::join!(server, client);
        })
        .await;
    }

    #[test]
    fn test_h3_url_with_ipv6_literal_targets_the_address() {
        let transport = H3Transport::new("h3://[2606:4700::1111]:8443/dns-query".into(), vec![]);
        assert_eq!(
            (transport.hostname.as_str(), transport.port),
            ("2606:4700::1111", 8443)
        );
    }
}
