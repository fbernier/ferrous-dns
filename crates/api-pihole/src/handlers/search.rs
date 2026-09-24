use axum::extract::{Path, Query, State};
use axum::Json;
use ferrous_dns_application::ports::FilterDecision;
use ferrous_dns_domain::BlockSource;
use serde::Deserialize;
use std::net::IpAddr;

use crate::{
    dto::search::{SearchResponse, SearchResult},
    errors::PiholeApiError,
    state::PiholeAppState,
};

/// The group of clients no other group claims.
const DEFAULT_GROUP_ID: i64 = 1;

#[derive(Debug, Deserialize)]
pub struct SearchParams {
    pub client: Option<String>,
}

/// Pi-hole v6 GET /api/search/:domain
///
/// Checks whether a domain would be blocked by the current filter configuration.
#[utoipa::path(
    get,
    path = "/search/{domain}",
    tag = "pihole:search",
    params(
        ("domain" = String, Path, description = "Domain to evaluate against the filter index"),
        ("client" = Option<String>, Query, description = "Client IP context for group resolution")
    ),
    responses(
        (status = 200, description = "Filter evaluation result", body = SearchResponse)
    ),
    security(("session_id" = []))
)]
pub async fn search_domain(
    State(state): State<PiholeAppState>,
    Path(mut domain): Path<String>,
    Query(params): Query<SearchParams>,
) -> Result<Json<SearchResponse>, PiholeApiError> {
    // Check the name the DNS path would: no root dot, ASCII-lowercased.
    domain.truncate(domain.trim_end_matches('.').len());
    domain.make_ascii_lowercase();

    let engine = &state.blocking.block_filter_engine;
    let group_id = params
        .client
        .as_deref()
        .and_then(|client| client.parse::<IpAddr>().ok())
        .map_or(DEFAULT_GROUP_ID, |ip| engine.resolve_group(ip));

    let (r#type, kind, source, blocked) = match engine.check(&domain, group_id) {
        FilterDecision::Block(block_source) => {
            let kind = match block_source {
                BlockSource::RegexFilter => "regex",
                BlockSource::Blocklist
                | BlockSource::ManagedDomain
                | BlockSource::CnameCloaking
                | BlockSource::Schedule
                | BlockSource::DnsRebinding
                | BlockSource::RateLimit
                | BlockSource::DnsTunneling
                | BlockSource::NxdomainHijack
                | BlockSource::ResponseIpFilter
                | BlockSource::DgaDetection => "exact",
            };
            ("deny", kind, format!("{block_source:?}"), true)
        }
        FilterDecision::Allow => ("allow", "exact", "allowed".to_string(), false),
        FilterDecision::ExplicitAllow => ("allow", "exact", "allowlist".to_string(), false),
    };

    let results = vec![SearchResult {
        domain,
        r#type,
        kind,
        source,
        blocked,
    }];

    Ok(Json(SearchResponse { results }))
}
