use std::cmp::Reverse;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ClientSubnet {
    pub id: Option<i64>,
    pub subnet_cidr: Arc<str>,
    pub group_id: i64,
    pub comment: Option<Arc<str>>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl ClientSubnet {
    pub fn new(subnet_cidr: String, group_id: i64, comment: Option<String>) -> Self {
        Self {
            id: None,
            subnet_cidr: Arc::from(subnet_cidr.as_str()),
            group_id,
            comment: comment.map(|s| Arc::from(s.as_str())),
            created_at: None,
            updated_at: None,
        }
    }

    pub fn validate_cidr(cidr: &str) -> Result<(), String> {
        if cidr.is_empty() {
            return Err("CIDR cannot be empty".to_string());
        }

        if !cidr.contains('/') {
            return Err("CIDR must include prefix (e.g., 192.168.1.0/24)".to_string());
        }

        Ok(())
    }
}

pub struct SubnetMatcher {
    subnets: Vec<(ipnetwork::IpNetwork, i64)>,
}

impl SubnetMatcher {
    pub fn new(subnets: Vec<ClientSubnet>) -> Result<Self, String> {
        let mut networks = Vec::new();

        for subnet in subnets {
            let network: ipnetwork::IpNetwork = subnet
                .subnet_cidr
                .parse()
                .map_err(|e| format!("Invalid CIDR {}: {}", subnet.subnet_cidr, e))?;
            networks.push((network, subnet.group_id));
        }

        Ok(Self { subnets: networks })
    }

    /// Longest prefix wins; among equal prefixes the first subnet wins.
    pub fn find_group_for_ip(&self, ip: IpAddr) -> Option<i64> {
        self.subnets
            .iter()
            .filter(|(network, _)| network.contains(ip))
            .min_by_key(|(network, _)| Reverse(network.prefix()))
            .map(|(_, group_id)| *group_id)
    }
}
