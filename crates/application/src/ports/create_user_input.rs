use ferrous_dns_domain::UserRole;
use std::sync::Arc;

/// Input for creating a new database user via use case.
pub struct CreateUserInput {
    pub username: Arc<str>,
    pub display_name: Option<Arc<str>>,
    pub password: String,
    pub role: UserRole,
}
