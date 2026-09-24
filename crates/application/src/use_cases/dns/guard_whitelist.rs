use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Longest presentation-format domain name (RFC 1035 §2.3.4).
const MAX_DOMAIN_LEN: usize = 253;

/// IPv4 CIDR matched in IPv4-mapped IPv6 space (`::ffff:a.b.c.d`).
const V4_MAPPED_PREFIX: u128 = 0xFFFF_0000_0000;
const V4_MAPPED_MASK: u128 = 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0000_0000;

/// Parsed CIDR range for guard client whitelists.
struct CidrRange {
    network: u128,
    mask: u128,
}

impl CidrRange {
    fn parse(cidr: &str) -> Option<Self> {
        let (addr_str, prefix_str) = cidr.split_once('/')?;
        let prefix: u32 = prefix_str.parse().ok()?;

        if let Ok(v4) = addr_str.parse::<Ipv4Addr>() {
            if prefix > 32 {
                return None;
            }
            let v4_mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
            let mask = u128::from(v4_mask) | V4_MAPPED_MASK;
            Some(Self {
                network: (u128::from(u32::from(v4)) | V4_MAPPED_PREFIX) & mask,
                mask,
            })
        } else if let Ok(v6) = addr_str.parse::<Ipv6Addr>() {
            if prefix > 128 {
                return None;
            }
            let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
            Some(Self {
                network: u128::from(v6) & mask,
                mask,
            })
        } else {
            None
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        let bits = match ip {
            IpAddr::V4(v4) => u128::from(u32::from(v4)) | V4_MAPPED_PREFIX,
            IpAddr::V6(v6) => u128::from(v6),
        };
        (bits & self.mask) == self.network
    }
}

/// Domain and client exemptions shared by the tunneling and DGA guards.
pub(super) struct GuardWhitelist {
    domains: HashSet<Box<str>>,
    clients: Vec<CidrRange>,
}

impl GuardWhitelist {
    /// Unparseable CIDRs are skipped; domains are stored lowercased for [`Self::contains_domain`].
    pub(super) fn new(domains: &[String], clients: &[String]) -> Self {
        Self {
            domains: domains
                .iter()
                .map(|s| s.to_lowercase().into_boxed_str())
                .collect(),
            clients: clients.iter().filter_map(|s| CidrRange::parse(s)).collect(),
        }
    }

    pub(super) fn contains_client(&self, ip: IpAddr) -> bool {
        self.clients.iter().any(|cidr| cidr.contains(ip))
    }

    /// Case-insensitive exact match without heap allocation.
    #[inline]
    pub(super) fn contains_domain(&self, domain: &str) -> bool {
        let bytes = domain.as_bytes();
        if bytes.len() > MAX_DOMAIN_LEN {
            return false;
        }
        let mut buf = [0u8; MAX_DOMAIN_LEN];
        let lower = &mut buf[..bytes.len()];
        for (dst, &src) in lower.iter_mut().zip(bytes) {
            *dst = src.to_ascii_lowercase();
        }
        // SAFETY: `lower` copies a UTF-8 `&str` with only ASCII bytes rewritten to other
        // ASCII bytes; multi-byte sequences are untouched, so it is still valid UTF-8.
        let lower = unsafe { std::str::from_utf8_unchecked(lower) };
        self.domains.contains(lower)
    }
}
