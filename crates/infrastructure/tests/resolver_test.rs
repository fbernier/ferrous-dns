use ferrous_dns_infrastructure::dns::transport::resolver;
use std::time::Duration;

#[tokio::test]
#[ignore = "live network: resolves dns.google; run with --ignored"]
async fn test_resolve_all_returns_multiple_ips() {
    let addrs = resolver::resolve_all("dns.google", 53, Duration::from_secs(5))
        .await
        .expect("dns.google should resolve");

    assert!(
        addrs.len() >= 2,
        "dns.google should resolve to at least 2 IPs, got {}",
        addrs.len()
    );
}

#[tokio::test]
#[ignore = "live network: resolves dns.google; run with --ignored"]
async fn test_resolve_all_includes_ipv6() {
    let addrs = resolver::resolve_all("dns.google", 53, Duration::from_secs(5))
        .await
        .expect("dns.google should resolve");

    let has_v6 = addrs.iter().any(|a| a.is_ipv6());
    assert!(
        has_v6,
        "dns.google should include at least one IPv6 address, got: {:?}",
        addrs
    );
}

#[tokio::test]
async fn test_resolve_all_preserves_port_for_ipv6_literal() {
    let addrs = resolver::resolve_all("::1", 853, Duration::from_secs(5))
        .await
        .expect("an IPv6 literal resolves without DNS");

    assert_eq!(
        addrs,
        vec!["[::1]:853".parse::<std::net::SocketAddr>().unwrap()]
    );
}

#[tokio::test]
async fn test_resolve_all_invalid_hostname() {
    let result = resolver::resolve_all(
        "this.hostname.definitely.does.not.exist.invalid",
        53,
        Duration::from_secs(5),
    )
    .await;

    assert!(result.is_err(), "Invalid hostname should return error");
}
