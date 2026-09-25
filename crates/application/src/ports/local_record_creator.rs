use async_trait::async_trait;
use ferrous_dns_domain::{DomainError, LocalDnsRecord};

/// Port for creating a local DNS record during backup import.
#[async_trait]
pub trait LocalRecordCreator: Send + Sync {
    async fn create_local_record(&self, record: LocalDnsRecord) -> Result<(), DomainError>;
}
