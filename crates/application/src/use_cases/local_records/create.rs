use std::sync::Arc;

use async_trait::async_trait;
use ferrous_dns_domain::{Config, DomainError, LocalDnsRecord};
use tokio::sync::RwLock;

use super::{ensure_wildcard_anchored, parse_record, save_failed, LiveRecordSinks};
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
    pub fn with_ptr_registry(mut self, registry: Option<Arc<dyn PtrRecordRegistry>>) -> Self {
        self.sinks.ptr = registry;
        self
    }

    /// Attaches a live DNS cache so that a successful record creation immediately
    /// inserts the forward record (A/AAAA) into the cache without requiring a server restart.
    pub fn with_dns_cache(mut self, cache: Option<Arc<dyn DnsCachePort>>) -> Self {
        self.sinks.cache = cache;
        self
    }

    /// Attaches the live wildcard index so that a newly created wildcard record
    /// answers queries immediately.
    pub fn with_wildcard_registry(
        mut self,
        registry: Option<Arc<dyn WildcardRecordRegistry>>,
    ) -> Self {
        self.sinks.wildcard = registry;
        self
    }

    pub async fn execute(
        &self,
        hostname: String,
        domain: Option<String>,
        ip: String,
        record_type: String,
        ttl: Option<u32>,
    ) -> Result<(LocalDnsRecord, usize), DomainError> {
        let parsed = parse_record(hostname, domain, ip, record_type, ttl)?;

        let mut config = self.config.write().await;
        ensure_wildcard_anchored(&parsed.record, &config)?;

        config.dns.local_records.push(parsed.record.clone());
        let new_index = config.dns.local_records.len() - 1;

        if let Err(e) = self.config_repo.save_local_records(&config).await {
            config.dns.local_records.pop();
            return Err(save_failed(e));
        }

        self.sinks.install(&parsed, &config.dns.local_domain);
        Ok((parsed.record, new_index))
    }
}

#[async_trait]
impl LocalRecordCreator for CreateLocalRecordUseCase {
    async fn create_local_record(
        &self,
        hostname: String,
        domain: Option<String>,
        ip: String,
        record_type: String,
        ttl: Option<u32>,
    ) -> Result<LocalDnsRecord, DomainError> {
        self.execute(hostname, domain, ip, record_type, ttl)
            .await
            .map(|(record, _index)| record)
    }
}
