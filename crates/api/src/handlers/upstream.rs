use axum::{extract::State, Json};
use std::collections::HashMap;

use crate::dto::upstream::{upstream_status_str, UpstreamGroupResponse};
use crate::state::AppState;

#[utoipa::path(
    get,
    path = "/upstream/health",
    tag = "system",
    responses(
        (status = 200, description = "Per-upstream health status map", body = HashMap<String, String>),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn get_upstream_health(
    State(state): State<AppState>,
) -> Json<HashMap<String, &'static str>> {
    Json(
        state
            .dns
            .upstream_health
            .get_all_upstream_status()
            .into_iter()
            .map(|(server, status)| (server, upstream_status_str(status)))
            .collect(),
    )
}

#[utoipa::path(
    get,
    path = "/upstream/health/detail",
    tag = "system",
    responses(
        (status = 200, description = "Detailed upstream health grouped per endpoint", body = [UpstreamGroupResponse]),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn get_upstream_health_detail(
    State(state): State<AppState>,
) -> Json<Vec<UpstreamGroupResponse>> {
    Json(
        state
            .dns
            .upstream_health
            .get_grouped_upstream_health()
            .into_iter()
            .map(UpstreamGroupResponse::from)
            .collect(),
    )
}
