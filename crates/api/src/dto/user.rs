use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateUserRequest {
    pub username: String,
    pub display_name: Option<String>,
    pub password: String,
    #[serde(default = "default_role")]
    pub role: String,
}

fn default_role() -> String {
    "viewer".to_string()
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserResponse {
    pub id: Option<i64>,
    pub username: String,
    pub display_name: Option<String>,
    /// `admin` or `viewer`.
    #[schema(value_type = String)]
    pub role: &'static str,
    /// `toml` or `database`.
    #[schema(value_type = String)]
    pub source: &'static str,
    pub enabled: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}
