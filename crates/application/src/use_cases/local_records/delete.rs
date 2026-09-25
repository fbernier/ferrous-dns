use std::sync::Arc;

use ferrous_dns_domain::{Config, DomainError, LocalDnsRecord};
use tokio::sync::RwLock;

use super::{record_not_found, save_failed, LiveRecordSinks};
use crate::ports::{ConfigRepository, DnsCachePort, PtrRecordRegistry, WildcardRecordRegistry};

pub struct DeleteLocalRecordUseCase {
    config: Arc<RwLock<Config>>,
    config_repo: Arc<dyn ConfigRepository>,
    sinks: LiveRecordSinks,
}

impl DeleteLocalRecordUseCase {
    pub fn new(config: Arc<RwLock<Config>>, config_repo: Arc<dyn ConfigRepository>) -> Self {
        Self {
            config,
            config_repo,
            sinks: LiveRecordSinks::default(),
        }
    }

    /// Attaches a live PTR registry so that a successful record deletion immediately
    /// removes the IP → FQDN mapping without requiring a server restart.
    pub fn with_ptr_registry(mut self, registry: Arc<dyn PtrRecordRegistry>) -> Self {
        self.sinks.ptr = Some(registry);
        self
    }

    /// Attaches a live DNS cache so that a successful record deletion immediately
    /// removes the forward record (A/AAAA) from the cache without requiring a server restart.
    pub fn with_dns_cache(mut self, cache: Arc<dyn DnsCachePort>) -> Self {
        self.sinks.cache = Some(cache);
        self
    }

    /// Attaches the live wildcard index so that deleting a wildcard record stops
    /// it answering on the next query, without a server restart.
    pub fn with_wildcard_registry(mut self, registry: Arc<dyn WildcardRecordRegistry>) -> Self {
        self.sinks.wildcard = Some(registry);
        self
    }

    pub async fn execute(&self, id: i64) -> Result<LocalDnsRecord, DomainError> {
        let mut config = self.config.write().await;

        let idx = usize::try_from(id)
            .ok()
            .filter(|&idx| idx < config.dns.local_records.len())
            .ok_or_else(|| record_not_found(id))?;

        let removed_record = config.dns.local_records.remove(idx);

        if let Err(e) = self.config_repo.save_local_records(&config).await {
            config.dns.local_records.insert(idx, removed_record.clone());
            return Err(save_failed(e));
        }

        let dns = &config.dns;
        self.sinks.refresh(
            &removed_record,
            &dns.local_records,
            dns.local_domain.as_deref(),
        );
        Ok(removed_record)
    }
}
