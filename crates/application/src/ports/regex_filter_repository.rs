use async_trait::async_trait;
use ferrous_dns_domain::{DomainAction, DomainError, RegexFilter};

/// Fields to change on a regex filter; `None` keeps the stored value.
#[derive(Debug, Clone, Default)]
pub struct RegexFilterUpdate {
    pub name: Option<String>,
    pub pattern: Option<String>,
    pub action: Option<DomainAction>,
    pub group_id: Option<i64>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}

#[async_trait]
pub trait RegexFilterRepository: Send + Sync {
    async fn create(
        &self,
        name: String,
        pattern: String,
        action: DomainAction,
        group_id: i64,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<RegexFilter, DomainError>;

    async fn get_by_id(&self, id: i64) -> Result<Option<RegexFilter>, DomainError>;

    async fn get_all(&self) -> Result<Vec<RegexFilter>, DomainError>;

    async fn update(&self, id: i64, update: RegexFilterUpdate) -> Result<RegexFilter, DomainError>;

    async fn delete(&self, id: i64) -> Result<(), DomainError>;

    async fn get_enabled(&self) -> Result<Vec<RegexFilter>, DomainError>;
}
