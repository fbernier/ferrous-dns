use axum::{
    extract::{Query, Request, State},
    http::{HeaderMap, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
};
use ferrous_dns_domain::DomainError;
use serde::Deserialize;

use crate::{errors::PiholeApiError, state::PiholeAppState};

/// Pi-hole v6 `require_auth`: every route except `/auth` needs a live session.
///
/// With `[auth]` disabled every request passes, as on a Pi-hole with no
/// password set. Otherwise the session id must arrive the way Pi-hole clients
/// send it (see [`extract_sid`]); anything else gets 401 `unauthorized`.
pub async fn require_pihole_auth(
    State(state): State<PiholeAppState>,
    request: Request,
    next: Next,
) -> Response {
    if !state.auth_enabled().await {
        return next.run(request).await;
    }

    if let Some(sid) = extract_sid(request.headers(), request.uri()) {
        if state.auth.validate_session.execute(&sid).await.is_ok() {
            return next.run(request).await;
        }
    }

    PiholeApiError(DomainError::AuthRequired).into_response()
}

#[derive(Deserialize)]
struct SidQuery {
    sid: Option<String>,
}

/// The session id from the `sid` or `X-FTL-SID` header, else the `sid` query
/// parameter — the sources Pi-hole's FTL accepts, in its order. FTL also takes
/// a `sid` cookie (only with a CSRF token) and a `sid` in the request body;
/// neither is supported here, since no session here carries a CSRF token and
/// reading the body would mean buffering it for every route.
pub(crate) fn extract_sid(headers: &HeaderMap, uri: &Uri) -> Option<String> {
    ["sid", "X-FTL-SID"]
        .into_iter()
        .find_map(|name| headers.get(name).and_then(|value| value.to_str().ok()))
        .map(str::to_owned)
        .or_else(|| {
            Query::<SidQuery>::try_from_uri(uri)
                .ok()
                .and_then(|Query(query)| query.sid)
        })
        .filter(|sid| !sid.is_empty())
}
