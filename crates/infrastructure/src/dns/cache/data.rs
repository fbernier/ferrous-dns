use bytes::Bytes;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachedDnssecStatus {
    Unknown = 0,
    Secure = 1,
    Insecure = 2,
    Bogus = 3,
    Indeterminate = 4,
}

impl FromStr for CachedDnssecStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "Secure" => Self::Secure,
            "Insecure" => Self::Insecure,
            "Bogus" => Self::Bogus,
            "Indeterminate" => Self::Indeterminate,
            _ => Self::Unknown,
        })
    }
}

impl CachedDnssecStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Secure => "Secure",
            Self::Insecure => "Insecure",
            Self::Bogus => "Bogus",
            Self::Indeterminate => "Indeterminate",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CachedAddresses {
    pub addresses: Arc<Vec<IpAddr>>,
}

#[derive(Clone, Debug)]
pub enum CachedData {
    IpAddresses(CachedAddresses),

    CanonicalName(Arc<str>),

    /// Raw upstream DNS wire bytes for non-A/AAAA record types (HTTPS, MX, TXT, etc.).
    WireData(Bytes),

    NegativeResponse,
}

impl CachedData {
    pub fn is_negative(&self) -> bool {
        matches!(self, CachedData::NegativeResponse)
    }

    pub fn as_ip_addresses(&self) -> Option<&Arc<Vec<IpAddr>>> {
        match self {
            CachedData::IpAddresses(entry) => Some(&entry.addresses),
            CachedData::CanonicalName(_)
            | CachedData::WireData(_)
            | CachedData::NegativeResponse => None,
        }
    }

    pub fn as_canonical_name(&self) -> Option<&Arc<str>> {
        match self {
            CachedData::CanonicalName(name) => Some(name),
            CachedData::IpAddresses(_) | CachedData::WireData(_) | CachedData::NegativeResponse => {
                None
            }
        }
    }
}
