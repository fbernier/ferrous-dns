use crate::dto::{ClientResponse, ClientStatsResponse, ClientsQuery};
use crate::errors::ApiError;
use crate::state::AppState;
use axum::{
    extract::{Query, State},
    Json,
};
use tracing::{debug, instrument};

#[utoipa::path(
    get,
    path = "/clients",
    tag = "clients",
    params(ClientsQuery),
    responses(
        (status = 200, description = "Client list", body = [ClientResponse]),
        (status = 500, description = "Internal error"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
#[instrument(skip(state), name = "api_get_clients")]
pub async fn get_clients(
    State(state): State<AppState>,
    Query(params): Query<ClientsQuery>,
) -> Result<Json<Vec<ClientResponse>>, ApiError> {
    debug!(
        limit = params.limit,
        offset = params.offset,
        active_days = ?params.active_days,
        "Fetching clients"
    );

    let clients = if let Some(days) = params.active_days {
        state
            .clients
            .get_clients
            .get_active(days, params.limit)
            .await?
    } else {
        state
            .clients
            .get_clients
            .get_all(params.limit, params.offset)
            .await?
    };

    let response: Vec<ClientResponse> = clients.into_iter().map(ClientResponse::from).collect();

    debug!(count = response.len(), "Clients retrieved successfully");
    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/clients/stats",
    tag = "clients",
    responses(
        (status = 200, description = "Aggregated client statistics", body = ClientStatsResponse),
        (status = 500, description = "Internal error"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
#[instrument(skip(state), name = "api_get_client_stats")]
pub async fn get_client_stats(
    State(state): State<AppState>,
) -> Result<Json<ClientStatsResponse>, ApiError> {
    debug!("Fetching client statistics");

    let stats = state.clients.get_clients.get_stats().await?;
    debug!("Client stats retrieved successfully");
    Ok(Json(ClientStatsResponse {
        total_clients: stats.total_clients,
        active_24h: stats.active_24h,
        active_7d: stats.active_7d,
        with_mac: stats.with_mac,
        with_hostname: stats.with_hostname,
    }))
}
