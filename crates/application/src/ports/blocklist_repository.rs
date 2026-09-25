use async_trait::async_trait;
use ferrous_dns_domain::{BlockedDomain, DomainError};

#[async_trait]
pub trait BlocklistRepository: Send + Sync {
    async fn get_all_paged(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<BlockedDomain>, u64), DomainError>;
}
