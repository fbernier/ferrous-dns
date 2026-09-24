use ferrous_dns_application::ports::{ResponseIpFilterEvictionTarget, ResponseIpFilterStore};
use ferrous_dns_application::use_cases::dns::coarse_timer::coarse_now_ns;
use ferrous_dns_domain::ResponseIpFilterConfig;
use ferrous_dns_infrastructure::dns::ResponseIpFilterDetector;

fn test_config() -> ResponseIpFilterConfig {
    ResponseIpFilterConfig {
        enabled: true,
        ip_ttl_secs: 1,
        ..Default::default()
    }
}

#[test]
fn unknown_ip_is_not_blocked() {
    let detector = ResponseIpFilterDetector::new(&test_config());
    let ip = "1.2.3.4".parse().unwrap();
    assert!(!detector.is_blocked_ip(&ip));
}

#[test]
fn stale_ips_are_evicted() {
    let detector = ResponseIpFilterDetector::new(&test_config());
    let ip = "203.0.113.99".parse().unwrap();
    detector
        .blocked_ips
        .insert(ip, coarse_now_ns() - 10_000_000_000);

    assert!(detector.is_blocked_ip(&ip));
    detector.evict_stale_ips();
    assert!(!detector.is_blocked_ip(&ip));
    assert_eq!(detector.blocked_ip_count(), 0);
}

#[test]
fn fresh_ips_survive_eviction() {
    let detector = ResponseIpFilterDetector::new(&test_config());
    let ip = "203.0.113.99".parse().unwrap();
    detector.blocked_ips.insert(ip, coarse_now_ns());

    detector.evict_stale_ips();
    assert!(detector.is_blocked_ip(&ip));
    assert_eq!(detector.blocked_ip_count(), 1);
}

#[test]
fn mixed_stale_and_fresh_ips() {
    let detector = ResponseIpFilterDetector::new(&test_config());
    let stale_ip = "203.0.113.1".parse().unwrap();
    let fresh_ip = "203.0.113.2".parse().unwrap();

    detector
        .blocked_ips
        .insert(stale_ip, coarse_now_ns() - 10_000_000_000);
    detector.blocked_ips.insert(fresh_ip, coarse_now_ns());

    detector.evict_stale_ips();
    assert!(!detector.is_blocked_ip(&stale_ip));
    assert!(detector.is_blocked_ip(&fresh_ip));
    assert_eq!(detector.blocked_ip_count(), 1);
}

#[test]
fn eviction_with_zero_ttl_removes_all() {
    let config = ResponseIpFilterConfig {
        ip_ttl_secs: 0,
        ..Default::default()
    };
    let detector = ResponseIpFilterDetector::new(&config);
    detector.blocked_ips.insert("10.0.0.1".parse().unwrap(), 0);
    detector.blocked_ips.insert("10.0.0.2".parse().unwrap(), 0);

    detector.evict_stale_ips();
    assert_eq!(detector.blocked_ip_count(), 0);
}

#[test]
fn unbounded_ttl_never_evicts() {
    let detector = ResponseIpFilterDetector::new(&ResponseIpFilterConfig {
        ip_ttl_secs: u64::MAX,
        ..test_config()
    });
    let ip = "203.0.113.99".parse().unwrap();
    detector.blocked_ips.insert(ip, 0);

    detector.evict_stale_ips();
    assert!(detector.is_blocked_ip(&ip));
}
