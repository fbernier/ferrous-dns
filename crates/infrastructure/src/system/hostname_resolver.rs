use async_trait::async_trait;
use ferrous_dns_application::ports::HostnameResolver;
use ferrous_dns_domain::{DomainError, RecordType};
use hickory_proto::rr::{RData, Record};
use std::net::IpAddr;
use std::sync::Arc;
use tracing::debug;

use crate::dns::forwarding::DnsForwarder;
use crate::dns::load_balancer::PoolManager;

pub struct PtrHostnameResolver {
    pool_manager: Arc<PoolManager>,
    timeout_secs: u64,
    local_dns_server: Option<String>,
}

impl PtrHostnameResolver {
    pub fn new(pool_manager: Arc<PoolManager>, timeout_secs: u64) -> Self {
        Self {
            pool_manager,
            timeout_secs,
            local_dns_server: None,
        }
    }

    pub fn with_local_dns_server(mut self, server: Option<String>) -> Self {
        self.local_dns_server = server;
        self
    }

    pub fn ip_to_reverse_domain(ip: &IpAddr) -> String {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                format!(
                    "{}.{}.{}.{}.in-addr.arpa",
                    octets[3], octets[2], octets[1], octets[0]
                )
            }
            IpAddr::V6(ipv6) => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                // 32 nibbles, each followed by a dot, then "ip6.arpa".
                let mut name = String::with_capacity(72);
                for byte in ipv6.octets().iter().rev() {
                    name.push(char::from(HEX[usize::from(byte & 0x0f)]));
                    name.push('.');
                    name.push(char::from(HEX[usize::from(byte >> 4)]));
                    name.push('.');
                }
                name.push_str("ip6.arpa");
                name
            }
        }
    }

    fn is_private_or_local(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
            IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local()
            }
        }
    }
}

/// First PTR target as a display hostname, without the root label's trailing dot.
fn first_ptr(records: &[Record]) -> Option<String> {
    records.iter().find_map(|record| match &record.data {
        RData::PTR(ptr) => {
            let mut name = ptr.to_utf8();
            if name.len() > 1 && name.ends_with('.') {
                name.pop();
            }
            Some(name)
        }
        _ => None,
    })
}

#[async_trait]
impl HostnameResolver for PtrHostnameResolver {
    async fn resolve_hostname(&self, ip: IpAddr) -> Result<Option<String>, DomainError> {
        let reverse_domain = Self::ip_to_reverse_domain(&ip);
        let timeout_ms = self.timeout_secs * 1000;

        debug!(
            ip = %ip,
            reverse_domain = %reverse_domain,
            "Performing PTR lookup"
        );

        if let Some(ref server) = self.local_dns_server {
            if Self::is_private_or_local(&ip) {
                let forwarder = DnsForwarder::new().with_hardening(self.pool_manager.hardening());
                match forwarder
                    .query(server, &reverse_domain, &RecordType::PTR, timeout_ms)
                    .await
                {
                    Ok(result) => {
                        let hostname = first_ptr(&result.raw_answers);
                        match &hostname {
                            Some(h) => {
                                debug!(ip = %ip, hostname = %h, server = %server, "PTR lookup via local DNS server successful")
                            }
                            None => {
                                debug!(ip = %ip, server = %server, "PTR lookup via local DNS server returned no records")
                            }
                        }
                        return Ok(hostname);
                    }
                    Err(e) => {
                        debug!(ip = %ip, server = %server, error = %e, "PTR lookup via local DNS server failed, falling back to upstream");
                    }
                }
            }
        }

        let domain_arc: Arc<str> = Arc::from(reverse_domain.as_str());
        match self
            .pool_manager
            .query(&domain_arc, &RecordType::PTR, timeout_ms, false)
            .await
        {
            Ok(result) => {
                let hostname = first_ptr(&result.response.raw_answers);
                match &hostname {
                    Some(h) => debug!(ip = %ip, hostname = %h, "PTR lookup successful"),
                    None => debug!(ip = %ip, "PTR lookup returned no records"),
                }
                Ok(hostname)
            }
            Err(e) => {
                debug!(ip = %ip, error = %e, reverse_domain = %reverse_domain, "PTR lookup failed");
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::first_ptr;
    use hickory_proto::rr::rdata::{A, PTR};
    use hickory_proto::rr::{Name, RData, Record};
    use std::str::FromStr;

    fn record(rdata: RData) -> Record {
        let owner = Name::from_str("10.1.168.192.in-addr.arpa.").expect("owner");
        Record::from_rdata(owner, 60, rdata)
    }

    #[test]
    fn test_first_ptr_strips_root_dot_and_skips_non_ptr_records() {
        let target = Name::from_str("printer.lan.").expect("target");
        let records = [
            record(RData::A(A::new(192, 168, 1, 10))),
            record(RData::PTR(PTR(target))),
        ];
        assert_eq!(first_ptr(&records).as_deref(), Some("printer.lan"));
    }

    #[test]
    fn test_first_ptr_without_ptr_records_is_none() {
        assert_eq!(
            first_ptr(&[record(RData::A(A::new(192, 168, 1, 10)))]),
            None
        );
    }
}
