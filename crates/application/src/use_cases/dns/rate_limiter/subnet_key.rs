use std::net::IpAddr;

/// Compact register-sized key for subnet-based rate limiting.
///
/// Bit 63 distinguishes IPv4 (0) from IPv6 (1); the low bits hold the right-aligned
/// network prefix. An IPv6 /64 fills all 64 bits, so its top address bit shares the tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SubnetKey(u64);

const V6_TAG: u64 = 1 << 63;

/// Shift/mask pair derived once from the configured prefix lengths, so key
/// derivation is a single shift (plus a mask for IPv6) with no overflow at /0.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SubnetGrouping {
    v4_shift: u32,
    v6_shift: u32,
    v6_mask: u64,
}

impl SubnetGrouping {
    pub(crate) fn new(v4_prefix: u8, v6_prefix: u8) -> Self {
        let v6_prefix = u32::from(v6_prefix.min(64));
        Self {
            v4_shift: 32 - u32::from(v4_prefix.min(32)),
            // A 64-bit shift would overflow, so /0 zeroes the prefix through the mask instead.
            v6_shift: (64 - v6_prefix).min(63),
            v6_mask: if v6_prefix == 0 { 0 } else { u64::MAX },
        }
    }

    #[inline]
    pub(crate) fn key(&self, ip: IpAddr) -> SubnetKey {
        match ip {
            IpAddr::V4(v4) => SubnetKey(u64::from(u32::from(v4)) >> self.v4_shift),
            IpAddr::V6(v6) => {
                let high = (u128::from(v6) >> 64) as u64;
                SubnetKey(((high >> self.v6_shift) & self.v6_mask) | V6_TAG)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn key(ip: IpAddr, v4_prefix: u8, v6_prefix: u8) -> SubnetKey {
        SubnetGrouping::new(v4_prefix, v6_prefix).key(ip)
    }

    #[test]
    fn subnet_key_groups_ipv4_same_slash24() {
        let a = key(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 24, 56);
        let b = key(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)), 24, 56);
        assert_eq!(a, b);
    }

    #[test]
    fn subnet_key_separates_different_subnets() {
        let a = key(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 24, 56);
        let b = key(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 10)), 24, 56);
        assert_ne!(a, b);
    }

    #[test]
    fn subnet_key_ipv6_groups_same_prefix() {
        let a = key(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xab, 0xcd00, 0, 0, 0, 1)),
            24,
            56,
        );
        let b = key(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xab, 0xcdff, 0, 0, 0, 9)),
            24,
            56,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn subnet_key_ipv4_and_ipv6_differ() {
        let v4 = key(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 24, 56);
        let v6 = key(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 24, 56);
        assert_ne!(v4, v6);
    }

    #[test]
    fn zero_prefix_groups_every_address_into_one_bucket() {
        let a = key(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 0, 0);
        let b = key(IpAddr::V4(Ipv4Addr::new(192, 168, 7, 9)), 0, 0);
        assert_eq!(a, b);
        let c = key(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            0,
            0,
        );
        let d = key(IpAddr::V6(Ipv6Addr::new(0xfd00, 1, 2, 3, 0, 0, 0, 1)), 0, 0);
        assert_eq!(c, d);
        assert_ne!(a, c);
    }
}
