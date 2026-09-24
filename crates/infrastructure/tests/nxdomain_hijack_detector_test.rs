use ferrous_dns_application::ports::{NxdomainHijackIpStore, NxdomainHijackProbeTarget};
use ferrous_dns_application::use_cases::dns::coarse_timer::coarse_now_ns;
use ferrous_dns_domain::NxdomainHijackConfig;
use ferrous_dns_infrastructure::dns::NxdomainHijackDetector;
use std::sync::Arc;

fn test_config() -> NxdomainHijackConfig {
    NxdomainHijackConfig {
        enabled: true,
        hijack_ip_ttl_secs: 1,
        ..Default::default()
    }
}

#[test]
fn unknown_ip_is_not_hijack() {
    let detector = NxdomainHijackDetector::new(&test_config());
    let ip = "1.2.3.4".parse().unwrap();
    assert!(!detector.is_hijack_ip(&ip));
}

#[test]
fn stale_ips_are_evicted() {
    let detector = NxdomainHijackDetector::new(&test_config());
    let ip = "203.0.113.99".parse().unwrap();
    detector
        .hijack_ips
        .insert(ip, coarse_now_ns() - 10_000_000_000);

    assert!(detector.is_hijack_ip(&ip));
    detector.evict_stale_ips();
    assert!(!detector.is_hijack_ip(&ip));
    assert_eq!(detector.hijack_ip_count(), 0);
}

#[test]
fn fresh_ips_survive_eviction() {
    let detector = NxdomainHijackDetector::new(&test_config());
    let ip = "203.0.113.99".parse().unwrap();
    detector.hijack_ips.insert(ip, coarse_now_ns());

    detector.evict_stale_ips();
    assert!(detector.is_hijack_ip(&ip));
    assert_eq!(detector.hijack_ip_count(), 1);
}

#[test]
fn mixed_stale_and_fresh_ips() {
    let detector = NxdomainHijackDetector::new(&test_config());
    let stale_ip = "203.0.113.1".parse().unwrap();
    let fresh_ip = "203.0.113.2".parse().unwrap();

    detector
        .hijack_ips
        .insert(stale_ip, coarse_now_ns() - 10_000_000_000);
    detector.hijack_ips.insert(fresh_ip, coarse_now_ns());

    detector.evict_stale_ips();
    assert!(!detector.is_hijack_ip(&stale_ip));
    assert!(detector.is_hijack_ip(&fresh_ip));
    assert_eq!(detector.hijack_ip_count(), 1);
}

#[test]
fn unbounded_ttl_never_evicts() {
    let detector = NxdomainHijackDetector::new(&NxdomainHijackConfig {
        hijack_ip_ttl_secs: u64::MAX,
        ..test_config()
    });
    let ip = "203.0.113.99".parse().unwrap();
    detector.hijack_ips.insert(ip, 0);

    detector.evict_stale_ips();
    assert!(detector.is_hijack_ip(&ip));
}

#[tokio::test]
async fn zero_probe_interval_does_not_kill_the_probe_loop() {
    let detector = Arc::new(NxdomainHijackDetector::new(&NxdomainHijackConfig {
        probe_interval_secs: 0,
        ..test_config()
    }));

    let probe_loop = tokio::spawn(Arc::clone(&detector).run_probe_loop(Vec::new()));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    assert!(!probe_loop.is_finished(), "probe loop exited (panicked)");
    probe_loop.abort();
}
