use ferrous_dns_api::dto::block_filter::{BacktestResponse, FilterTestResponse};
use ferrous_dns_application::use_cases::{BacktestReport, CandidateAction};
use ferrous_dns_domain::{
    AllowMatch, AllowMatchKind, BlockMatch, BlockMatchKind, FilterExplanation, MatchType,
};

#[test]
fn filter_matches_use_their_wire_names() {
    let exp = FilterExplanation {
        domain: "ads.example.com".to_string(),
        group_id: 1,
        blocked: true,
        allow_reasons: vec![AllowMatch {
            kind: AllowMatchKind::Regex,
            source_id: Some(3),
            name: "allow-cdn".to_string(),
            match_type: MatchType::Regex,
        }],
        block_matches: vec![BlockMatch {
            kind: BlockMatchKind::Blocklist,
            source_id: Some(10),
            name: "EasyList".to_string(),
            match_type: MatchType::Exact,
        }],
    };

    let dto = FilterTestResponse::from(exp);
    assert_eq!(dto.block_matches[0].kind, "blocklist");
    assert_eq!(dto.block_matches[0].match_type, "exact");
    assert_eq!(dto.allow_reasons[0].kind, "regex");
    assert_eq!(dto.allow_reasons[0].match_type, "regex");
}

#[test]
fn backtest_action_uses_its_wire_name() {
    let report = BacktestReport {
        group_id: 1,
        action: CandidateAction::Allow,
        window_hours: 24.0,
        corpus_size: 0,
        total_queries: 0,
        currently_blocked_domains: 0,
        currently_blocked_queries: 0,
        matched_domains: 0,
        matched_queries: 0,
        changed_domains: 0,
        changed_queries: 0,
        redundant_domains: 0,
        redundant_queries: 0,
        overridden_domains: 0,
        overridden_queries: 0,
        sample: vec![],
    };

    assert_eq!(BacktestResponse::from(report).action, "allow");
}
