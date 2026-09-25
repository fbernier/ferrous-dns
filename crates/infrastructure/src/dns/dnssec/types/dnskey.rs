use super::algorithm_name;
use ferrous_dns_domain::DomainError;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnskeyRecord {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
}

impl DnskeyRecord {
    pub fn parse(data: &[u8]) -> Result<Self, DomainError> {
        if data.len() < 4 {
            return Err(DomainError::InvalidDnsResponse(
                "DNSKEY record too short".into(),
            ));
        }

        let flags = u16::from_be_bytes([data[0], data[1]]);
        let protocol = data[2];
        let algorithm = data[3];
        let public_key = data[4..].to_vec();

        if protocol != 3 {
            return Err(DomainError::InvalidDnsResponse(format!(
                "Invalid DNSKEY protocol: {} (expected 3)",
                protocol
            )));
        }

        if flags & 0x0100 == 0 {
            return Err(DomainError::InvalidDnsResponse(
                "DNSKEY Zone Key flag not set".into(),
            ));
        }

        Ok(Self {
            flags,
            protocol,
            algorithm,
            public_key,
        })
    }

    pub fn is_ksk(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    /// RFC 4034 Appendix B key tag.
    pub fn calculate_key_tag(&self) -> u16 {
        // u64 so an oversized key (trust anchor files are not RDLENGTH-bounded)
        // cannot overflow the running sum; identical to the RFC's u32 for real keys.
        let mut accumulator: u64 = u64::from(self.flags);
        accumulator += u64::from(u16::from_be_bytes([self.protocol, self.algorithm]));

        for chunk in self.public_key.chunks(2) {
            accumulator += match *chunk {
                [hi, lo] => u64::from(u16::from_be_bytes([hi, lo])),
                [hi] => u64::from(hi) << 8,
                _ => 0,
            };
        }

        accumulator += accumulator >> 16;
        (accumulator & 0xFFFF) as u16
    }
}

impl fmt::Display for DnskeyRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DNSKEY(flags={}, algo={}, tag={}, {})",
            self.flags,
            algorithm_name(self.algorithm),
            self.calculate_key_tag(),
            if self.is_ksk() { "KSK" } else { "ZSK" }
        )
    }
}
