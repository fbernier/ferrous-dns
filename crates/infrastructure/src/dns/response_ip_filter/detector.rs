use dashmap::DashMap;
use ferrous_dns_application::ports::{ResponseIpFilterEvictionTarget, ResponseIpFilterStore};
use ferrous_dns_application::use_cases::dns::coarse_timer::coarse_now_ns;
use ferrous_dns_domain::{DomainError, ResponseIpFilterConfig};
use rustc_hash::FxBuildHasher;
use std::net::IpAddr;
use std::time::Duration;
use tracing::{debug, info, warn};

const NS_PER_SEC: u64 = 1_000_000_000;
/// Largest feed body accepted; a feed past it is skipped rather than buffered.
const MAX_FEED_BYTES: usize = 64 * 1024 * 1024;

/// Downloads C2 IP threat feeds and provides O(1) hot-path lookup.
///
/// Known C2 IPs are looked up on the hot path and aged out in the background.
/// The fetch loop runs as an async task, downloading feeds at the configured
/// interval.
pub struct ResponseIpFilterDetector {
    config: ResponseIpFilterConfig,
    /// C2 IP → last time a feed listed it (coarse ns), for TTL eviction.
    pub blocked_ips: DashMap<IpAddr, u64, FxBuildHasher>,
}

impl ResponseIpFilterDetector {
    pub fn new(config: &ResponseIpFilterConfig) -> Self {
        Self {
            config: config.clone(),
            blocked_ips: DashMap::with_hasher(FxBuildHasher),
        }
    }

    /// Runs the fetch loop, downloading IP feeds at the configured interval.
    ///
    /// Fetches immediately on startup so protection is active from the first
    /// DNS query. Then sleeps `refresh_interval_secs` between subsequent fetches.
    /// Runs until the tokio runtime shuts down (same pattern as probe/analysis loops).
    pub async fn run_fetch_loop(self: std::sync::Arc<Self>, http_client: reqwest::Client) {
        info!(
            urls = self.config.ip_list_urls.len(),
            refresh_secs = self.config.refresh_interval_secs,
            "Response IP filter fetch loop starting"
        );

        loop {
            self.fetch_all_lists(&http_client).await;

            tokio::time::sleep(Duration::from_secs(self.config.refresh_interval_secs)).await;
        }
    }

    async fn fetch_all_lists(&self, http_client: &reqwest::Client) {
        let now_ns = coarse_now_ns();
        let mut total_new = 0usize;
        let mut fetch_errors = 0usize;

        for url in &self.config.ip_list_urls {
            match fetch_ip_list(url, http_client, MAX_FEED_BYTES).await {
                Ok(ips) => {
                    for ip in ips {
                        if self.blocked_ips.insert(ip, now_ns).is_none() {
                            total_new += 1;
                        }
                    }
                }
                Err(e) => {
                    fetch_errors += 1;
                    warn!(url = %url, error = %e, "Failed to fetch C2 IP list");
                }
            }
        }

        let total = self.blocked_ips.len();
        if fetch_errors > 0 && total == 0 {
            warn!(
                failed = fetch_errors,
                urls = self.config.ip_list_urls.len(),
                "All C2 IP feeds failed — no IPs loaded for response filtering"
            );
        } else {
            info!(new_ips = total_new, total, "C2 IP list updated");
        }
    }
}

impl ResponseIpFilterStore for ResponseIpFilterDetector {
    fn is_blocked_ip(&self, ip: &IpAddr) -> bool {
        self.blocked_ips.contains_key(ip)
    }
}

impl ResponseIpFilterEvictionTarget for ResponseIpFilterDetector {
    fn evict_stale_ips(&self) {
        let now_ns = coarse_now_ns();
        let ttl_ns = self.config.ip_ttl_secs.saturating_mul(NS_PER_SEC);

        self.blocked_ips.retain(|ip, confirmed_ns| {
            let keep = now_ns.saturating_sub(*confirmed_ns) <= ttl_ns;
            if !keep {
                debug!(ip = %ip, "Evicted stale C2 IP");
            }
            keep
        });
    }

    fn blocked_ip_count(&self) -> usize {
        self.blocked_ips.len()
    }
}

async fn fetch_ip_list(
    url: &str,
    client: &reqwest::Client,
    max_bytes: usize,
) -> Result<Vec<IpAddr>, DomainError> {
    let mut response = client
        .get(url)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| DomainError::IoError(format!("fetch error for {url}: {e}")))?;

    if !response.status().is_success() {
        return Err(DomainError::IoError(format!(
            "HTTP {} for {url}",
            response.status().as_u16()
        )));
    }

    let too_large = || DomainError::IoError(format!("feed {url} exceeds {max_bytes} bytes"));
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| DomainError::IoError(format!("read error for {url}: {e}")))?
    {
        if chunk.len() > max_bytes - body.len() {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }

    Ok(parse_ip_list(&String::from_utf8_lossy(&body)))
}

/// Parses an IP list in standard format: one IP per line, `#` comments, blank lines ignored.
fn parse_ip_list(text: &str) -> Vec<IpAddr> {
    text.lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .filter_map(|line| line.parse::<IpAddr>().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Serves `response` to one request and keeps the connection open, so a
    /// reader that waits for EOF hangs.
    async fn serve_once(response: String) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(socket.read_u8().await.unwrap());
            }
            socket.write_all(response.as_bytes()).await.unwrap();
            std::future::pending::<()>().await;
        });
        format!("http://{addr}/feed")
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder().no_proxy().build().unwrap()
    }

    #[tokio::test]
    async fn oversized_feeds_are_rejected_while_streaming() {
        let body = "192.0.2.1\n".repeat(20);
        let advertised = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let streamed = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n",
            body.len()
        );
        for response in [advertised, streamed] {
            let url = serve_once(response).await;
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                fetch_ip_list(&url, &client(), body.len() - 1),
            )
            .await
            .expect("an oversized feed must be rejected without waiting for EOF");
            assert!(matches!(result, Err(DomainError::IoError(_))), "{result:?}");
        }
    }

    #[tokio::test]
    async fn feed_of_exactly_the_cap_is_parsed() {
        let body = "192.0.2.1\n2001:db8::1\n";
        let url = serve_once(format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ))
        .await;
        let ips = fetch_ip_list(&url, &client(), body.len()).await.unwrap();
        assert_eq!(
            ips,
            [
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse().unwrap()
            ]
        );
    }

    #[test]
    fn parse_ip_list_handles_comments_and_blanks() {
        let text = "# Header comment\n\
                     1.2.3.4\n\
                     \n\
                     5.6.7.8 # inline comment\n\
                     # another comment\n\
                     2001:db8::1\n\
                     not_an_ip\n";
        let ips = parse_ip_list(text);
        assert_eq!(ips.len(), 3);
        assert_eq!(ips[0], "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(ips[1], "5.6.7.8".parse::<IpAddr>().unwrap());
        assert_eq!(ips[2], "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_ip_list_empty_input() {
        assert!(parse_ip_list("").is_empty());
        assert!(parse_ip_list("# only comments\n# here").is_empty());
    }

    #[test]
    fn parse_ip_list_whitespace_only_lines() {
        let text = "  \n\t\n1.2.3.4\n   \n";
        let ips = parse_ip_list(text);
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_ip_list_ipv6_addresses() {
        let text = "2001:db8::1\n::1\nfe80::1\n";
        let ips = parse_ip_list(text);
        assert_eq!(ips.len(), 3);
    }

    #[test]
    fn parse_ip_list_mixed_v4_v6() {
        let text = "1.2.3.4\n2001:db8::1\n5.6.7.8\n::1\n";
        let ips = parse_ip_list(text);
        assert_eq!(ips.len(), 4);
    }

    #[test]
    fn parse_ip_list_skips_invalid_lines() {
        let text = "1.2.3.4\nnot_an_ip\nexample.com\n999.999.999.999\n5.6.7.8\n";
        let ips = parse_ip_list(text);
        assert_eq!(ips.len(), 2);
    }
}
