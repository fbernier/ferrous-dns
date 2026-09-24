use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::warn;

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
    /// A CIDR, or a bare address as its /32 or /128 — as `rate_limit.whitelist` accepts.
    fn parse(entry: &str) -> Option<Self> {
        let (addr_str, prefix) = match entry.split_once('/') {
            Some((addr_str, prefix_str)) => (addr_str, Some(prefix_str.parse::<u32>().ok()?)),
            None => (entry, None),
        };

        if let Ok(v4) = addr_str.parse::<Ipv4Addr>() {
            let prefix = prefix.unwrap_or(32);
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
            let prefix = prefix.unwrap_or(128);
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
    /// Invalid client entries are skipped with a warning naming `section`;
    /// domains are stored lowercased for [`Self::contains_domain`].
    pub(super) fn new(section: &str, domains: &[String], clients: &[String]) -> Self {
        Self {
            domains: domains
                .iter()
                .map(|s| s.to_lowercase().into_boxed_str())
                .collect(),
            clients: clients
                .iter()
                .filter_map(|entry| {
                    let range = CidrRange::parse(entry);
                    if range.is_none() {
                        warn!(
                            section,
                            entry = %entry,
                            "Ignoring client_whitelist entry: not an IP address or CIDR"
                        );
                    }
                    range
                })
                .collect(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn clients(entries: &[&str]) -> GuardWhitelist {
        let entries: Vec<String> = entries.iter().map(|s| s.to_string()).collect();
        GuardWhitelist::new("test", &[], &entries)
    }

    #[test]
    fn bare_ipv4_is_a_single_host() {
        let whitelist = clients(&["10.0.0.50"]);
        assert!(whitelist.contains_client("10.0.0.50".parse().unwrap()));
        assert!(whitelist.contains_client("::ffff:10.0.0.50".parse().unwrap()));
        assert!(!whitelist.contains_client("10.0.0.51".parse().unwrap()));
    }

    #[test]
    fn bare_ipv6_is_a_single_host() {
        let whitelist = clients(&["2001:db8::1"]);
        assert!(whitelist.contains_client("2001:db8::1".parse().unwrap()));
        assert!(!whitelist.contains_client("2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn invalid_entries_are_skipped_without_dropping_valid_ones() {
        let whitelist = clients(&[
            "not-an-ip",
            "10.0.0.0/33",
            "2001:db8::/129",
            "10.0.0.0/x",
            "192.168.1.0/24",
        ]);
        assert_eq!(whitelist.clients.len(), 1);
        assert!(whitelist.contains_client("192.168.1.7".parse().unwrap()));
    }
}
