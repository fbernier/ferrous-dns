use ferrous_dns_domain::BlocklistSource;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct BlocklistSourceResponse {
    pub id: i64,
    pub name: String,
    pub url: Option<String>,
    pub group_ids: Vec<i64>,
    pub comment: Option<String>,
    pub enabled: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub last_synced_at: Option<String>,
}

impl BlocklistSourceResponse {
    pub fn from_source(source: BlocklistSource) -> Self {
        Self {
            id: source.id.unwrap_or(0),
            name: source.name.to_string(),
            url: source.url.as_ref().map(|s| s.to_string()),
            group_ids: source.group_ids,
            comment: source.comment.as_ref().map(|s| s.to_string()),
            enabled: source.enabled,
            created_at: source.created_at,
            updated_at: source.updated_at,
            last_synced_at: source.last_synced_at,
        }
    }
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateBlocklistSourceRequest {
    pub name: String,
    pub url: Option<String>,
    /// Legacy: single group_id. If group_ids is also present, group_ids takes precedence.
    pub group_id: Option<i64>,
    pub group_ids: Option<Vec<i64>>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateBlocklistSourceRequest {
    pub name: Option<String>,
    #[serde(default, deserialize_with = "crate::dto::source_common::double_option")]
    pub url: Option<Option<String>>,
    /// Legacy: single group_id. If group_ids is also present, group_ids takes precedence.
    pub group_id: Option<i64>,
    pub group_ids: Option<Vec<i64>>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}
