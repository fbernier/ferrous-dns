use async_trait::async_trait;
use ferrous_dns_domain::{DomainError, WhitelistedDomain};

#[async_trait]
pub trait WhitelistRepository: Send + Sync {
    async fn get_all(&self) -> Result<Vec<WhitelistedDomain>, DomainError>;
}
