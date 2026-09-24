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

fn rate_limit(dry_run: bool) -> RateLimitConfig {
    RateLimitConfig {
        enabled: true,
        queries_per_second: 1,
        burst_size: 1000,
        nxdomain_per_second: NX_PER_SECOND,
        slip_ratio: 0,
        dry_run,
        ..RateLimitConfig::default()
    }
}

async fn use_case(dry_run: bool) -> HandleDnsQueryUseCase {
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
    .with_rate_limiter(Arc::new(DnsRateLimiter::new(&rate_limit(dry_run))))
}

fn request(domain: &str) -> DnsRequest {
    DnsRequest::new(domain, RecordType::A, CLIENT_IP)
}

#[tokio::test]
async fn client_over_its_nxdomain_budget_is_rate_limited() {
    let use_case = use_case(false).await;

    for _ in 0..NX_BURST {
        assert!(matches!(
            use_case.execute(&request("nx.example.com")).await,
            Err(DomainError::NxDomain)
        ));
    }

    // Well inside the general budget, but the NXDOMAIN budget is spent.
    assert!(matches!(
        use_case.execute(&request("ok.example.com")).await,
        Err(DomainError::DnsRateLimited)
    ));
}

#[tokio::test]
async fn resolving_answers_do_not_spend_the_nxdomain_budget() {
    let use_case = use_case(false).await;

    for _ in 0..NX_BURST * 4 {
        assert!(use_case.execute(&request("ok.example.com")).await.is_ok());
    }
}

#[tokio::test]
async fn dry_run_lets_a_client_over_its_nxdomain_budget_through() {
    let use_case = use_case(true).await;

    for _ in 0..NX_BURST {
        let _ = use_case.execute(&request("nx.example.com")).await;
    }

    assert!(use_case.execute(&request("ok.example.com")).await.is_ok());
}
