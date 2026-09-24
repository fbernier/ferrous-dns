use crate::dns::wire_response;
use bytes::Bytes;
use ferrous_dns_domain::DnssecStatus;
use std::net::IpAddr;
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

impl From<DnssecStatus> for CachedDnssecStatus {
    fn from(status: DnssecStatus) -> Self {
        match status {
            DnssecStatus::Secure => Self::Secure,
            DnssecStatus::Insecure => Self::Insecure,
            DnssecStatus::Bogus => Self::Bogus,
            DnssecStatus::Indeterminate => Self::Indeterminate,
        }
    }
}

impl CachedDnssecStatus {
    /// `Unknown` is an entry cached without a DNSSEC determination.
    pub fn to_domain(self) -> Option<DnssecStatus> {
        match self {
            Self::Unknown => None,
            Self::Secure => Some(DnssecStatus::Secure),
            Self::Insecure => Some(DnssecStatus::Insecure),
            Self::Bogus => Some(DnssecStatus::Bogus),
            Self::Indeterminate => Some(DnssecStatus::Indeterminate),
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

    /// An upstream DNS response for a non-A/AAAA record type (HTTPS, MX, TXT,
    /// etc.), in [`wire_response::cache_form`].
    WireData(Bytes),

    NegativeResponse,
}

impl CachedData {
    /// The form the cache stores: a wire answer re-sectioned by
    /// [`wire_response::cache_form`], anything else as is. `None` for a wire
    /// answer that does not re-section.
    pub(super) fn into_stored(self) -> Option<Self> {
        match self {
            Self::WireData(wire) => {
                wire_response::cache_form(&wire).map(|wire| Self::WireData(Bytes::from(wire)))
            }
            data @ (Self::IpAddresses(_) | Self::CanonicalName(_) | Self::NegativeResponse) => {
                Some(data)
            }
        }
    }

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
