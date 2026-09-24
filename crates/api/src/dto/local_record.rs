use ferrous_dns_domain::{DomainError, LocalDnsRecord};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct LocalRecordDto {
    pub id: i64,
    pub hostname: String,
    pub domain: Option<String>,
    pub fqdn: String,
    pub ip: String,
    pub record_type: String,
    pub ttl: u32,
    pub created_at: Option<String>,
}

impl LocalRecordDto {
    pub fn from_config(record: &LocalDnsRecord, index: i64, default_domain: Option<&str>) -> Self {
        Self {
            id: index,
            hostname: record.hostname.clone(),
            domain: record.domain.clone(),
            fqdn: record.fqdn(default_domain),
            ip: record.ip.to_string(),
            record_type: record.record_type.as_str().to_string(),
            ttl: record.ttl_or_default(),
            created_at: None,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateLocalRecordRequest {
    pub hostname: String,
    pub domain: Option<String>,
    pub ip: String,
    pub record_type: String,
    pub ttl: Option<u32>,
}

impl CreateLocalRecordRequest {
    pub fn into_record(self) -> Result<LocalDnsRecord, DomainError> {
        LocalDnsRecord::parse(
            self.hostname,
            self.domain,
            &self.ip,
            &self.record_type,
            self.ttl,
        )
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateLocalRecordRequest {
    pub hostname: String,
    pub domain: Option<String>,
    pub ip: String,
    pub record_type: String,
    pub ttl: Option<u32>,
}

impl UpdateLocalRecordRequest {
    pub fn into_record(self) -> Result<LocalDnsRecord, DomainError> {
        LocalDnsRecord::parse(
            self.hostname,
            self.domain,
            &self.ip,
            &self.record_type,
            self.ttl,
        )
    }
}
