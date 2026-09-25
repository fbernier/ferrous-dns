use ferrous_dns_domain::SafeSearchConfig;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SafeSearchConfigResponse {
    pub id: Option<i64>,
    pub group_id: i64,
    #[schema(value_type = String)]
    pub engine: &'static str,
    pub enabled: bool,
    #[schema(value_type = String)]
    pub youtube_mode: &'static str,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl SafeSearchConfigResponse {
    pub fn from_entity(c: SafeSearchConfig) -> Self {
        Self {
            id: c.id,
            group_id: c.group_id,
            engine: c.engine.to_str(),
            enabled: c.enabled,
            youtube_mode: c.youtube_mode.to_str(),
            created_at: c.created_at,
            updated_at: c.updated_at,
        }
    }
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ToggleSafeSearchRequest {
    pub engine: String,
    pub enabled: bool,
    /// `strict` (default when absent) or `moderate`.
    pub youtube_mode: Option<String>,
}
