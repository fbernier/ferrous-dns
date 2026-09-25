use std::sync::Arc;

use async_trait::async_trait;
use ferrous_dns_domain::{Config, DomainError, LocalDnsRecord};
use tokio::sync::RwLock;

use super::{save_failed, validate, LiveRecordSinks};
use crate::ports::{
    ConfigRepository, DnsCachePort, LocalRecordCreator, PtrRecordRegistry, WildcardRecordRegistry,
};

pub struct CreateLocalRecordUseCase {
    config: Arc<RwLock<Config>>,
    config_repo: Arc<dyn ConfigRepository>,
    sinks: LiveRecordSinks,
}

impl CreateLocalRecordUseCase {
    pub fn new(config: Arc<RwLock<Config>>, config_repo: Arc<dyn ConfigRepository>) -> Self {
        Self {
            config,
            config_repo,
            sinks: LiveRecordSinks::default(),
        }
    }

    /// Attaches a live PTR registry so that a successful record creation immediately
    /// registers the new IP → FQDN mapping without requiring a server restart.
    pub fn with_ptr_registry(mut self, registry: Arc<dyn PtrRecordRegistry>) -> Self {
        self.sinks.ptr = Some(registry);
        self
    }

    /// Attaches a live DNS cache so that a successful record creation immediately
    /// inserts the forward record (A/AAAA) into the cache without requiring a server restart.
    pub fn with_dns_cache(mut self, cache: Arc<dyn DnsCachePort>) -> Self {
        self.sinks.cache = Some(cache);
        self
    }

    /// Attaches the live wildcard index so that a newly created wildcard record
    /// answers queries immediately.
    pub fn with_wildcard_registry(mut self, registry: Arc<dyn WildcardRecordRegistry>) -> Self {
        self.sinks.wildcard = Some(registry);
        self
    }

    pub async fn execute(
        &self,
        record: LocalDnsRecord,
    ) -> Result<(LocalDnsRecord, usize), DomainError> {
        let mut config = self.config.write().await;
        validate(&record, config.dns.local_domain.as_deref())?;

        config.dns.local_records.push(record.clone());
        let new_index = config.dns.local_records.len() - 1;

        if let Err(e) = self.config_repo.save_local_records(&config).await {
            config.dns.local_records.pop();
            return Err(save_failed(e));
        }

        let dns = &config.dns;
        self.sinks
            .refresh(&record, &dns.local_records, dns.local_domain.as_deref());
        Ok((record, new_index))
    }
}

#[async_trait]
impl LocalRecordCreator for CreateLocalRecordUseCase {
    async fn create_local_record(&self, record: LocalDnsRecord) -> Result<(), DomainError> {
        self.execute(record).await.map(|_| ())
    }
}
