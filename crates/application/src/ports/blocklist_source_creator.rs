use async_trait::async_trait;
use ferrous_dns_domain::{BlocklistSource, DomainError};

/// Port for creating a blocklist source during backup import.
#[async_trait]
pub trait BlocklistSourceCreator: Send + Sync {
    async fn create_blocklist_source(
        &self,
        name: String,
        url: Option<String>,
        group_ids: Vec<i64>,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<BlocklistSource, DomainError>;
}
