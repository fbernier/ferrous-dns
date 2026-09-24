use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::dns_record::RecordType;
use crate::errors::domain_error::DomainError;

/// Longest a DNS name may be, in bytes (RFC 1035 §2.3.4).
const MAX_NAME_LEN: usize = 253;

/// Longest a single DNS label may be, in bytes (RFC 1035 §2.3.4).
const MAX_LABEL_LEN: usize = 63;

/// Record types a local record can carry: the address records the permanent
/// cache serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalRecordType {
    A,
    AAAA,
}

impl LocalRecordType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::AAAA => "AAAA",
        }
    }
}

impl From<LocalRecordType> for RecordType {
    fn from(record_type: LocalRecordType) -> Self {
        match record_type {
            LocalRecordType::A => RecordType::A,
            LocalRecordType::AAAA => RecordType::AAAA,
        }
    }
}

impl fmt::Display for LocalRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for LocalRecordType {
    type Err = DomainError;

    /// Case-insensitive, because hand-written configs use `a` as often as `A`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("A") {
            Ok(Self::A)
        } else if s.eq_ignore_ascii_case("AAAA") {
            Ok(Self::AAAA)
        } else {
            Err(DomainError::InvalidInput(format!(
                "Invalid record type '{s}' (must be A or AAAA)"
            )))
        }
    }
}

impl Serialize for LocalRecordType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for LocalRecordType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "LocalDnsRecordFields")]
pub struct LocalDnsRecord {
    pub hostname: String,
    pub domain: Option<String>,
    pub ip: IpAddr,
    pub record_type: LocalRecordType,
    pub ttl: Option<u32>,
}

/// The config-file shape of a record, checked into a [`LocalDnsRecord`] so an
/// address of the wrong family fails the load instead of being served.
#[derive(Deserialize)]
struct LocalDnsRecordFields {
    hostname: String,
    #[serde(default)]
    domain: Option<String>,
    ip: IpAddr,
    record_type: LocalRecordType,
    #[serde(default)]
    ttl: Option<u32>,
}

impl TryFrom<LocalDnsRecordFields> for LocalDnsRecord {
    type Error = String;

    fn try_from(fields: LocalDnsRecordFields) -> Result<Self, Self::Error> {
        Self::validate_address(fields.record_type, fields.ip)
            .map_err(|e| format!("local record '{}': {e}", fields.hostname))?;
        Ok(Self {
            hostname: fields.hostname,
            domain: fields.domain,
            ip: fields.ip,
            record_type: fields.record_type,
            ttl: fields.ttl,
        })
    }
}

impl LocalDnsRecord {
    /// Builds a record from the text fields the API and backups carry.
    pub fn parse(
        hostname: String,
        domain: Option<String>,
        ip: &str,
        record_type: &str,
        ttl: Option<u32>,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            hostname,
            domain,
            ip: ip
                .parse()
                .map_err(|_| DomainError::InvalidIpAddress(ip.to_string()))?,
            record_type: record_type.parse()?,
            ttl,
        })
    }

    pub fn fqdn(&self, default_domain: Option<&str>) -> String {
        match self.domain.as_deref().or(default_domain) {
            Some(domain) => format!("{}.{}", self.hostname, domain),
            None => self.hostname.clone(),
        }
    }

    /// Whether this record is named `fqdn`, compared ASCII case-insensitively
    /// as DNS compares names, without building the record's own name.
    pub fn has_fqdn(&self, fqdn: &str, default_domain: Option<&str>) -> bool {
        let host = self.hostname.as_bytes();
        let fqdn = fqdn.as_bytes();
        match self.domain.as_deref().or(default_domain) {
            Some(domain) => {
                fqdn.get(..host.len())
                    .is_some_and(|head| head.eq_ignore_ascii_case(host))
                    && fqdn.get(host.len()) == Some(&b'.')
                    && fqdn
                        .get(host.len() + 1..)
                        .is_some_and(|tail| tail.eq_ignore_ascii_case(domain.as_bytes()))
            }
            None => fqdn.eq_ignore_ascii_case(host),
        }
    }

    pub fn ttl_or_default(&self) -> u32 {
        self.ttl.unwrap_or(300)
    }

    /// True when the record covers a whole subtree instead of a single name:
    /// `*` on its own, or a `*.`-prefixed hostname such as `*.dev`.
    pub fn is_wildcard(&self) -> bool {
        is_wildcard_hostname(&self.hostname)
    }

    /// Suffix a wildcard record answers for, lowercased for matching:
    /// `*.home.lan` covers `home.lan`.
    ///
    /// `None` for an exact record, and for a wildcard with no domain to anchor
    /// it — a bare `*` would otherwise cover every query in existence.
    pub fn wildcard_suffix(&self, default_domain: Option<&str>) -> Option<String> {
        if !self.is_wildcard() {
            return None;
        }

        self.fqdn(default_domain)
            .strip_prefix("*.")
            .map(str::to_ascii_lowercase)
    }

    /// Rejects an address of the wrong family for its type: an A record with
    /// an IPv6 address would be served as a malformed answer.
    pub fn validate_address(record_type: LocalRecordType, ip: IpAddr) -> Result<(), String> {
        match (record_type, ip) {
            (LocalRecordType::A, IpAddr::V4(_)) | (LocalRecordType::AAAA, IpAddr::V6(_)) => Ok(()),
            (LocalRecordType::A, IpAddr::V6(_)) => {
                Err(format!("an A record needs an IPv4 address, got {ip}"))
            }
            (LocalRecordType::AAAA, IpAddr::V4(_)) => {
                Err(format!("an AAAA record needs an IPv6 address, got {ip}"))
            }
        }
    }

    /// Validates the `hostname` field. A wildcard is accepted only as the
    /// leftmost label, because that is the only position the resolver can
    /// match — anything else would be stored as a record no query can reach.
    pub fn validate_hostname(hostname: &str) -> Result<(), String> {
        if hostname.is_empty() {
            return Err("Hostname cannot be empty".to_string());
        }
        if hostname.len() > MAX_NAME_LEN {
            return Err(format!("Hostname cannot exceed {MAX_NAME_LEN} characters"));
        }
        if hostname.contains('*') && !is_wildcard_hostname(hostname) {
            return Err("Wildcard must be the leftmost label: use '*' or '*.sub'".to_string());
        }

        let remainder = hostname.strip_prefix("*.").unwrap_or(hostname);
        if remainder == "*" {
            return Ok(());
        }

        validate_labels(remainder, "Hostname")
    }

    /// Validates the optional `domain` suffix. Wildcards are rejected here:
    /// the subtree is expressed by the hostname, so a `*` in the suffix would
    /// land in the middle of the composed name.
    pub fn validate_domain(domain: &str) -> Result<(), String> {
        if domain.is_empty() {
            return Err("Domain cannot be empty".to_string());
        }
        if domain.len() > MAX_NAME_LEN {
            return Err(format!("Domain cannot exceed {MAX_NAME_LEN} characters"));
        }
        if domain.contains('*') {
            return Err(
                "Domain cannot contain a wildcard: put the '*' in the hostname".to_string(),
            );
        }

        validate_labels(domain, "Domain")
    }
}

fn is_wildcard_hostname(hostname: &str) -> bool {
    hostname == "*" || hostname.starts_with("*.")
}

fn validate_labels(name: &str, field: &str) -> Result<(), String> {
    for label in name.split('.') {
        if label.is_empty() {
            return Err(format!("{field} cannot contain an empty label"));
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(format!(
                "{field} label cannot exceed {MAX_LABEL_LEN} characters"
            ));
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!(
                "{field} contains invalid characters (only alphanumeric, hyphens and underscores are allowed)"
            ));
        }
    }

    Ok(())
}
