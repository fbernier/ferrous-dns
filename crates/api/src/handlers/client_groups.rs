use axum::{
    extract::{Path, State},
    response::Json,
};

use crate::{
    dto::{AssignGroupRequest, ClientResponse},
    errors::ApiError,
    state::AppState,
};

#[utoipa::path(
    put,
    path = "/clients/{id}/group",
    tag = "clients",
    params(("id" = i64, Path, description = "Client ID")),
    request_body = AssignGroupRequest,
    responses(
        (status = 200, description = "Client assigned to group", body = ClientResponse),
        (status = 404, description = "Client or group not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn assign_client_to_group(
    State(state): State<AppState>,
    Path(client_id): Path<i64>,
    Json(req): Json<AssignGroupRequest>,
) -> Result<Json<ClientResponse>, ApiError> {
    let client = state
        .groups
        .assign_client_group
        .execute(client_id, req.group_id)
        .await?;

    Ok(Json(ClientResponse::from(client)))
}
