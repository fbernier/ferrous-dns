use std::sync::Arc;

use ferrous_dns_domain::{Config, DomainError, LocalDnsRecord};
use tokio::sync::RwLock;

use super::{record_not_found, save_failed, validate, LiveRecordSinks};
use crate::ports::{ConfigRepository, DnsCachePort, PtrRecordRegistry, WildcardRecordRegistry};

pub struct UpdateLocalRecordUseCase {
    config: Arc<RwLock<Config>>,
    config_repo: Arc<dyn ConfigRepository>,
    sinks: LiveRecordSinks,
}

impl UpdateLocalRecordUseCase {
    pub fn new(config: Arc<RwLock<Config>>, config_repo: Arc<dyn ConfigRepository>) -> Self {
        Self {
            config,
            config_repo,
            sinks: LiveRecordSinks::default(),
        }
    }

    /// Attaches a live PTR registry so that a successful record update immediately
    /// swaps the old IP → FQDN mapping for the new one without requiring a server restart.
    pub fn with_ptr_registry(mut self, registry: Arc<dyn PtrRecordRegistry>) -> Self {
        self.sinks.ptr = Some(registry);
        self
    }

    /// Attaches a live DNS cache so that a successful record update immediately
    /// swaps the old forward record (A/AAAA) for the new one without requiring a server restart.
    pub fn with_dns_cache(mut self, cache: Arc<dyn DnsCachePort>) -> Self {
        self.sinks.cache = Some(cache);
        self
    }

    /// Attaches the live wildcard index so that an update moving a record into
    /// or out of wildcard form takes effect without a server restart.
    pub fn with_wildcard_registry(mut self, registry: Arc<dyn WildcardRecordRegistry>) -> Self {
        self.sinks.wildcard = Some(registry);
        self
    }

    /// Replaces the record at `id`, returning the new record and the old one.
    pub async fn execute(
        &self,
        id: i64,
        record: LocalDnsRecord,
    ) -> Result<(LocalDnsRecord, LocalDnsRecord), DomainError> {
        let mut config = self.config.write().await;
        validate(&record, config.dns.local_domain.as_deref())?;

        let idx = usize::try_from(id)
            .ok()
            .filter(|&idx| idx < config.dns.local_records.len())
            .ok_or_else(|| record_not_found(id))?;

        let old_record = std::mem::replace(&mut config.dns.local_records[idx], record.clone());

        if let Err(e) = self.config_repo.save_local_records(&config).await {
            config.dns.local_records[idx] = old_record;
            return Err(save_failed(e));
        }

        let dns = &config.dns;
        let local_domain = dns.local_domain.as_deref();
        self.sinks
            .refresh(&old_record, &dns.local_records, local_domain);
        self.sinks
            .refresh(&record, &dns.local_records, local_domain);

        Ok((record, old_record))
    }
}
