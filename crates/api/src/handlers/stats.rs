use crate::{
    dto::{StatsQuery, StatsResponse},
    errors::ApiError,
    state::AppState,
    utils::period_hours,
};
use axum::{
    extract::{Query, State},
    Json,
};
use tracing::instrument;

#[utoipa::path(
    get,
    path = "/stats",
    tag = "stats",
    params(StatsQuery),
    responses(
        (status = 200, description = "Aggregated query statistics", body = StatsResponse),
        (status = 500, description = "Internal error"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
#[instrument(skip(state), name = "api_get_stats")]
pub async fn get_stats(
    State(state): State<AppState>,
    Query(params): Query<StatsQuery>,
) -> Result<Json<StatsResponse>, ApiError> {
    let stats = state
        .query
        .get_stats
        .execute(period_hours(&params.period))
        .await?;
    Ok(Json(StatsResponse::from(stats)))
}
