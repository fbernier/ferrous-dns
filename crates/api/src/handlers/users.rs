use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use tracing::debug;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::dto::user::{CreateUserRequest, UserResponse};
use crate::errors::ApiError;
use crate::state::AppState;
use ferrous_dns_application::ports::CreateUserInput;
use ferrous_dns_domain::{User, UserRole};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_all_users, create_user))
        .routes(routes!(delete_user))
}

#[utoipa::path(
    get,
    path = "/users",
    tag = "users",
    responses(
        (status = 200, description = "All users", body = [UserResponse]),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_all_users(State(state): State<AppState>) -> Result<Json<Vec<UserResponse>>, ApiError> {
    let users = state.auth.get_users.execute().await?;
    debug!(count = users.len(), "Users retrieved");
    Ok(Json(users.into_iter().map(user_to_response).collect()))
}

#[utoipa::path(
    post,
    path = "/users",
    tag = "users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created", body = UserResponse),
        (status = 409, description = "Username already taken"),
        (status = 400, description = "Invalid input"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_user(
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserResponse>), ApiError> {
    let role: UserRole = req.role.parse()?;
    let input = CreateUserInput {
        username: Arc::from(req.username.as_str()),
        display_name: req.display_name.map(|s| Arc::from(s.as_str())),
        password: req.password,
        role,
    };

    let user = state.auth.create_user.execute(input).await?;
    debug!(username = %user.username, "User created via API");
    Ok((StatusCode::CREATED, Json(user_to_response(user))))
}

#[utoipa::path(
    delete,
    path = "/users/{id}",
    tag = "users",
    params(("id" = i64, Path, description = "User ID")),
    responses(
        (status = 204, description = "User deleted"),
        (status = 404, description = "User not found"),
        (status = 403, description = "Cannot delete protected user"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_user(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.auth.delete_user.execute(id).await?;
    debug!(user_id = id, "User deleted via API");
    Ok(StatusCode::NO_CONTENT)
}

fn user_to_response(user: User) -> UserResponse {
    UserResponse {
        id: user.id,
        username: user.username.to_string(),
        display_name: user.display_name.map(|s| s.to_string()),
        role: user.role.as_str(),
        source: user.source.as_str(),
        enabled: user.enabled,
        created_at: user.created_at,
        updated_at: user.updated_at,
    }
}
