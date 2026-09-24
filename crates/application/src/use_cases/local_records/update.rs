use std::sync::Arc;

use ferrous_dns_domain::{Config, DomainError, LocalDnsRecord};
use tokio::sync::RwLock;

use super::{
    ensure_wildcard_anchored, parse_record, record_not_found, save_failed, LiveRecordSinks,
};
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
    pub fn with_ptr_registry(mut self, registry: Option<Arc<dyn PtrRecordRegistry>>) -> Self {
        self.sinks.ptr = registry;
        self
    }

    /// Attaches a live DNS cache so that a successful record update immediately
    /// swaps the old forward record (A/AAAA) for the new one without requiring a server restart.
    pub fn with_dns_cache(mut self, cache: Option<Arc<dyn DnsCachePort>>) -> Self {
        self.sinks.cache = cache;
        self
    }

    /// Attaches the live wildcard index so that an update moving a record into
    /// or out of wildcard form takes effect without a server restart.
    pub fn with_wildcard_registry(
        mut self,
        registry: Option<Arc<dyn WildcardRecordRegistry>>,
    ) -> Self {
        self.sinks.wildcard = registry;
        self
    }

    pub async fn execute(
        &self,
        id: i64,
        hostname: String,
        domain: Option<String>,
        ip: String,
        record_type: String,
        ttl: Option<u32>,
    ) -> Result<(LocalDnsRecord, LocalDnsRecord), DomainError> {
        let parsed = parse_record(hostname, domain, ip, record_type, ttl)?;

        let mut config = self.config.write().await;

        let idx = usize::try_from(id)
            .ok()
            .filter(|&idx| idx < config.dns.local_records.len())
            .ok_or_else(|| record_not_found(id))?;

        ensure_wildcard_anchored(&parsed.record, &config)?;

        let old_record =
            std::mem::replace(&mut config.dns.local_records[idx], parsed.record.clone());

        if let Err(e) = self.config_repo.save_local_records(&config).await {
            config.dns.local_records[idx] = old_record;
            return Err(save_failed(e));
        }

        self.sinks.retire(&old_record, &config.dns.local_domain);
        self.sinks.install(&parsed, &config.dns.local_domain);

        Ok((parsed.record, old_record))
    }
}
