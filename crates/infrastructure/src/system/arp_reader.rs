use async_trait::async_trait;
use ferrous_dns_application::ports::{ArpReader, ArpTable};
use ferrous_dns_domain::DomainError;
use std::net::IpAddr;
use std::str::FromStr;
use tokio::fs;
use tracing::{debug, warn};

/// `ATF_COM` from `<linux/if_arp.h>`: the entry has a resolved hardware address.
/// Other bits (e.g. `ATF_PERM` for static entries) may be set alongside it.
const ATF_COM: u32 = 0x2;

fn is_complete(flags: &str) -> bool {
    flags
        .strip_prefix("0x")
        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        .is_some_and(|f| f & ATF_COM != 0)
}

fn is_valid_mac(mac: &str) -> bool {
    if mac.len() != 17 {
        return false;
    }

    let separator = if mac.contains(':') {
        ':'
    } else if mac.contains('-') {
        '-'
    } else {
        return false;
    };

    let parts: Vec<&str> = mac.split(separator).collect();
    if parts.len() != 6 {
        return false;
    }

    parts
        .iter()
        .all(|part| part.len() == 2 && part.chars().all(|c| c.is_ascii_hexdigit()))
}

pub struct LinuxArpReader {
    arp_path: String,
}

impl LinuxArpReader {
    pub fn new() -> Self {
        Self {
            arp_path: "/proc/net/arp".to_string(),
        }
    }

    pub fn with_path(path: String) -> Self {
        Self { arp_path: path }
    }
}

impl Default for LinuxArpReader {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ArpReader for LinuxArpReader {
    async fn read_arp_table(&self) -> Result<ArpTable, DomainError> {
        let content = fs::read_to_string(&self.arp_path)
            .await
            .map_err(|e| DomainError::IoError(format!("Failed to read ARP cache: {}", e)))?;

        let mut arp_table = ArpTable::new();

        for line in content.lines().skip(1) {
            let mut fields = line.split_whitespace();
            let (Some(ip_str), Some(_hw_type), Some(flags), Some(mac)) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                continue;
            };

            if !is_complete(flags) || mac == "00:00:00:00:00:00" {
                continue;
            }

            if !is_valid_mac(mac) {
                warn!(
                    ip = ip_str,
                    mac = mac,
                    "Invalid MAC address format in ARP table"
                );
                continue;
            }

            match IpAddr::from_str(ip_str) {
                Ok(ip) => {
                    arp_table.insert(ip, mac.to_string());
                }
                Err(e) => {
                    warn!(error = %e, ip = ip_str, "Invalid IP in ARP table");
                }
            }
        }

        debug!(entries = arp_table.len(), "ARP table parsed");
        Ok(arp_table)
    }
}
