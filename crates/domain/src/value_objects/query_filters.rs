use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct PrivateIpFilter;

impl PrivateIpFilter {
    pub fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => Self::is_private_ipv4(ipv4),
            IpAddr::V6(ipv6) => Self::is_private_ipv6(ipv6),
        }
    }

    fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
        ip.is_private() || ip.is_loopback() || ip.is_link_local()
    }

    fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
        // A private IPv4 delivered as `::ffff:a.b.c.d` must not bypass the rebinding check.
        if let Some(ipv4) = ip.to_ipv4_mapped() {
            return Self::is_private_ipv4(&ipv4);
        }
        ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()
    }

    pub fn extract_ip_from_ptr(domain: &str) -> Option<IpAddr> {
        if let Some(labels) = domain.strip_suffix(".in-addr.arpa") {
            return Self::parse_in_addr_arpa(labels).map(IpAddr::V4);
        }
        if let Some(labels) = domain.strip_suffix(".ip6.arpa") {
            return Self::parse_ip6_arpa(labels).map(IpAddr::V6);
        }
        None
    }

    fn parse_in_addr_arpa(labels: &str) -> Option<Ipv4Addr> {
        let mut octets = [0u8; 4];
        let mut labels = labels.rsplit('.');
        for octet in &mut octets {
            *octet = Self::parse_octet(labels.next()?)?;
        }
        labels.next().is_none().then(|| Ipv4Addr::from(octets))
    }

    /// Same octet grammar as `Ipv4Addr::from_str`: decimal digits only, no leading zero.
    fn parse_octet(label: &str) -> Option<u8> {
        let bytes = label.as_bytes();
        if bytes.is_empty() || (bytes.len() > 1 && bytes[0] == b'0') {
            return None;
        }
        if !bytes.iter().all(u8::is_ascii_digit) {
            return None;
        }
        label.parse().ok()
    }

    /// RFC 3596 §2.5: exactly 32 single-hex-digit labels, least significant nibble first.
    fn parse_ip6_arpa(labels: &str) -> Option<Ipv6Addr> {
        let mut value: u128 = 0;
        let mut count = 0u32;
        for label in labels.rsplit('.') {
            let &[digit] = label.as_bytes() else {
                return None;
            };
            let nibble = char::from(digit).to_digit(16)?;
            count += 1;
            if count > 32 {
                return None;
            }
            value = (value << 4) | u128::from(nibble);
        }
        (count == 32).then(|| Ipv6Addr::from(value))
    }

    pub fn is_private_ptr_query(domain: &str) -> bool {
        Self::extract_ip_from_ptr(domain).is_some_and(|ip| Self::is_private_ip(&ip))
    }
}

pub struct FqdnFilter;

impl FqdnFilter {
    pub fn is_fqdn(domain: &str) -> bool {
        // A dot anywhere but the end already implies at least two labels.
        domain.contains('.') && !domain.ends_with('.')
    }

    pub fn is_local_hostname(domain: &str) -> bool {
        !Self::is_fqdn(domain)
    }
}
