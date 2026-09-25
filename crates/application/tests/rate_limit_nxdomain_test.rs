mod helpers;

use ferrous_dns_application::ports::DnsResolution;
use ferrous_dns_application::use_cases::dns::DnsRateLimiter;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{DnsRequest, DomainError, RateLimitConfig, RecordType};
use helpers::{MockBlockFilterEngine, MockDnsResolver, MockQueryLogRepository};
use std::net::IpAddr;
use std::sync::Arc;

const CLIENT_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100));
const NX_PER_SECOND: u32 = 2;
/// NXDOMAIN burst capacity is twice the per-second budget.
const NX_BURST: u32 = NX_PER_SECOND * 2;

fn rate_limit(dry_run: bool, slip_ratio: u32) -> RateLimitConfig {
    RateLimitConfig {
        enabled: true,
        queries_per_second: 1,
        burst_size: 1000,
        nxdomain_per_second: NX_PER_SECOND,
        slip_ratio,
        dry_run,
        ..RateLimitConfig::default()
    }
}

/// Upstream-style NXDOMAINs: the resolver reports `Err(NxDomain)`.
async fn use_case(config: RateLimitConfig) -> HandleDnsQueryUseCase {
    let resolver = MockDnsResolver::new();
    resolver
        .set_response_error("nx.example.com", DomainError::NxDomain)
        .await;
    resolver
        .set_response(
            "ok.example.com",
            DnsResolution::new(vec!["192.0.2.1".parse().unwrap()], false),
        )
        .await;
    HandleDnsQueryUseCase::new(
        Arc::new(resolver),
        Arc::new(MockBlockFilterEngine::new()),
        Arc::new(MockQueryLogRepository::new()),
    )
    .with_rate_limiter(Arc::new(DnsRateLimiter::new(&config)))
}

fn request(domain: &str) -> DnsRequest {
    DnsRequest::new(domain, RecordType::A, CLIENT_IP)
}

#[tokio::test]
async fn only_nxdomain_answers_over_budget_are_rate_limited() {
    let use_case = use_case(rate_limit(false, 0)).await;

    for _ in 0..NX_BURST {
        assert!(matches!(
            use_case.execute(&request("nx.example.com")).await,
            Err(DomainError::NxDomain)
        ));
    }

    for _ in 0..3 {
        // The spent budget does not refuse the client's resolving queries...
        assert!(use_case.execute(&request("ok.example.com")).await.is_ok());
        // ...only its next NXDOMAIN answer.
        assert!(matches!(
            use_case.execute(&request("nx.example.com")).await,
            Err(DomainError::DnsRateLimited)
        ));
    }
}

#[tokio::test]
async fn over_budget_nxdomain_answers_follow_the_slip_ratio() {
    let use_case = use_case(rate_limit(false, 2)).await;

    for _ in 0..NX_BURST {
        let _ = use_case.execute(&request("nx.example.com")).await;
    }

    assert!(matches!(
        use_case.execute(&request("nx.example.com")).await,
        Err(DomainError::DnsRateLimitedSlip)
    ));
    assert!(matches!(
        use_case.execute(&request("nx.example.com")).await,
        Err(DomainError::DnsRateLimited)
    ));
    assert!(use_case.execute(&request("ok.example.com")).await.is_ok());
}

#[tokio::test]
async fn dry_run_lets_nxdomain_answers_over_budget_through() {
    let use_case = use_case(rate_limit(true, 0)).await;

    for _ in 0..NX_BURST * 2 {
        assert!(matches!(
            use_case.execute(&request("nx.example.com")).await,
            Err(DomainError::NxDomain)
        ));
    }
}
