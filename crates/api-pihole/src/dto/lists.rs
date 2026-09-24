use ferrous_dns_domain::DomainError;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use utoipa::ToSchema;

/// Pi-hole v6 list type. Blocklist and allowlist sources live in separate
/// tables, so a list is only identified by its address together with its type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ListType {
    Allow,
    Block,
}

impl FromStr for ListType {
    type Err = DomainError;

    /// Case-insensitive, as in Pi-hole FTL.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("allow") {
            Ok(Self::Allow)
        } else if s.eq_ignore_ascii_case("block") {
            Ok(Self::Block)
        } else {
            Err(DomainError::InvalidInput(format!(
                "Invalid list type {s:?} (should be either \"allow\" or \"block\")"
            )))
        }
    }
}

/// `?type=allow|block`. Kept as a string so a bad value gets a Pi-hole error
/// body instead of the extractor's plain-text rejection.
#[derive(Debug, Deserialize)]
pub struct ListTypeQuery {
    pub r#type: Option<String>,
}

/// Pi-hole v6 adlist/list entry.
#[derive(Debug, Serialize, ToSchema)]
pub struct PiholeListEntry {
    pub id: i64,
    pub address: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    pub r#type: ListType,
    pub groups: Vec<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_added: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_modified: Option<String>,
    pub number: u64,
    pub status: u8,
}

/// Pi-hole v6 POST /api/lists request; the type comes from `?type=`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateListRequest {
    pub address: String,
    pub comment: Option<String>,
    pub groups: Option<Vec<i64>>,
    pub enabled: Option<bool>,
}

/// Pi-hole v6 PUT /api/lists/{list} request; the list comes from the path
/// and `?type=`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateListRequest {
    pub comment: Option<String>,
    pub groups: Option<Vec<i64>>,
    pub enabled: Option<bool>,
}

/// One entry of the Pi-hole v6 POST /api/lists:batchDelete body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ListBatchDeleteItem {
    /// List address (or numeric id).
    pub item: String,
    /// `allow` or `block`
    pub r#type: String,
}

/// Pi-hole v6 list response envelope.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListsResponse {
    pub lists: Vec<PiholeListEntry>,
}
