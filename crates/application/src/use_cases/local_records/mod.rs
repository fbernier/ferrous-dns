pub mod create;
pub mod delete;
pub mod update;

pub use create::CreateLocalRecordUseCase;
pub use delete::DeleteLocalRecordUseCase;
pub use update::UpdateLocalRecordUseCase;

use std::net::IpAddr;
use std::sync::Arc;

use ferrous_dns_domain::{Config, DomainError, LocalDnsRecord, RecordType};
use tracing::warn;

use crate::ports::{DnsCachePort, PtrRecordRegistry, WildcardRecordRegistry};

/// A validated A/AAAA record with its address and type already parsed.
struct ParsedRecord {
    record: LocalDnsRecord,
    ip: IpAddr,
    record_type: RecordType,
}

fn parse_record(
    hostname: String,
    domain: Option<String>,
    ip: String,
    record_type: String,
    ttl: Option<u32>,
) -> Result<ParsedRecord, DomainError> {
    LocalDnsRecord::validate_hostname(&hostname).map_err(DomainError::InvalidDomainName)?;
    if let Some(ref domain) = domain {
        LocalDnsRecord::validate_domain(domain).map_err(DomainError::InvalidDomainName)?;
    }

    let parsed_ip = ip
        .parse::<IpAddr>()
        .map_err(|_| DomainError::InvalidIpAddress("Invalid IP address".to_string()))?;

    let record_type = record_type.to_uppercase();
    let parsed_record_type = record_type
        .parse::<RecordType>()
        .ok()
        .filter(|rt| matches!(rt, RecordType::A | RecordType::AAAA))
        .ok_or_else(|| {
            DomainError::InvalidDomainName("Invalid record type (must be A or AAAA)".to_string())
        })?;

    Ok(ParsedRecord {
        record: LocalDnsRecord {
            hostname,
            domain,
            ip,
            record_type,
            ttl,
        },
        ip: parsed_ip,
        record_type: parsed_record_type,
    })
}

fn ensure_wildcard_anchored(record: &LocalDnsRecord, config: &Config) -> Result<(), DomainError> {
    if record.is_wildcard() && record.wildcard_suffix(&config.dns.local_domain).is_none() {
        return Err(DomainError::InvalidDomainName(
            "A wildcard record needs a domain to anchor it: set the domain field or dns.local_domain".to_string(),
        ));
    }
    Ok(())
}

fn record_not_found(id: i64) -> DomainError {
    DomainError::NotFound(format!("Record with id {} not found", id))
}

fn save_failed(e: DomainError) -> DomainError {
    DomainError::IoError(format!("Failed to save configuration: {}", e))
}

/// Live DNS state mirroring the persisted records, so edits apply without a restart.
///
/// A wildcard lives only in the wildcard index (cache keys match exactly, so a
/// `*.example.com` entry there would be dead weight); an exact record lives in
/// the PTR map and the DNS cache.
#[derive(Default)]
struct LiveRecordSinks {
    ptr: Option<Arc<dyn PtrRecordRegistry>>,
    cache: Option<Arc<dyn DnsCachePort>>,
    wildcard: Option<Arc<dyn WildcardRecordRegistry>>,
}

impl LiveRecordSinks {
    fn install(&self, parsed: &ParsedRecord, local_domain: &Option<String>) {
        let record = &parsed.record;
        let ttl = record.ttl_or_default();
        if let Some(suffix) = record.wildcard_suffix(local_domain) {
            if let Some(ref registry) = self.wildcard {
                registry.register(&suffix, parsed.record_type, parsed.ip, ttl);
            }
            return;
        }

        let fqdn = record.fqdn(local_domain);
        if let Some(ref registry) = self.ptr {
            registry.register(parsed.ip, Arc::from(fqdn.as_str()), ttl);
        }
        if let Some(ref cache) = self.cache {
            cache.insert_permanent_record(&fqdn, parsed.record_type, vec![parsed.ip], ttl);
        }
    }

    /// Stored records were validated on write; unparseable fields are logged and skipped.
    fn retire(&self, record: &LocalDnsRecord, local_domain: &Option<String>) {
        let record_type = record.record_type.parse::<RecordType>();
        if let Some(suffix) = record.wildcard_suffix(local_domain) {
            if let Some(ref registry) = self.wildcard {
                match record_type {
                    Ok(rt) => registry.unregister(&suffix, rt),
                    Err(_) => warn!(
                        record_type = %record.record_type,
                        "Wildcard registry: unrecognised record type, skipping removal"
                    ),
                }
            }
            return;
        }

        if let Some(ref registry) = self.ptr {
            match record.ip.parse() {
                Ok(ip) => registry.unregister(ip),
                Err(_) => warn!(ip = %record.ip, "PTR registry: unparseable IP, skipping removal"),
            }
        }
        if let Some(ref cache) = self.cache {
            match record_type {
                Ok(rt) => {
                    cache.remove_record(&record.fqdn(local_domain), &rt);
                }
                Err(_) => warn!(
                    record_type = %record.record_type,
                    "DNS cache: unrecognised record type, skipping eviction"
                ),
            }
        }
    }
}
