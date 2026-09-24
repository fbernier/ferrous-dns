use crate::errors::domain_error::DomainError;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    PTR,

    SRV,
    SOA,
    NS,
    NAPTR,
    DS,
    DNSKEY,
    SVCB,
    HTTPS,

    CAA,
    TLSA,
    SSHFP,
    DNAME,

    RRSIG,
    NSEC,
    NSEC3,
    NSEC3PARAM,

    CDS,
    CDNSKEY,

    OPT,

    NULL,
    HINFO,
    WKS,

    IPSECKEY,
    OPENPGPKEY,

    ZONEMD,

    ANAME,
}

macro_rules! impl_record_type_conversions {
    ( $( ($variant:ident, $str:literal, $code:literal) ),* $(,)? ) => {
        impl RecordType {
            pub fn as_str(&self) -> &'static str {
                match self {
                    $( RecordType::$variant => $str, )*
                }
            }

            pub fn to_u16(&self) -> u16 {
                match self {
                    $( RecordType::$variant => $code, )*
                }
            }

            pub fn from_u16(code: u16) -> Option<Self> {
                match code {
                    $( $code => Some(RecordType::$variant), )*
                    _ => None,
                }
            }
        }

        impl FromStr for RecordType {
            type Err = DomainError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $( if s.eq_ignore_ascii_case($str) {
                    return Ok(RecordType::$variant);
                } )*
                Err(DomainError::InvalidInput(format!("unknown record type: {s}")))
            }
        }
    };
}

impl_record_type_conversions! {
    (A,          "A",          1),
    (NS,         "NS",         2),
    (CNAME,      "CNAME",      5),
    (SOA,        "SOA",        6),
    (NULL,       "NULL",       10),
    (WKS,        "WKS",        11),
    (PTR,        "PTR",        12),
    (HINFO,      "HINFO",      13),
    (MX,         "MX",         15),
    (TXT,        "TXT",        16),
    (AAAA,       "AAAA",       28),
    (SRV,        "SRV",        33),
    (NAPTR,      "NAPTR",      35),
    (DNAME,      "DNAME",      39),
    (OPT,        "OPT",        41),
    (DS,         "DS",         43),
    (SSHFP,      "SSHFP",      44),
    (IPSECKEY,   "IPSECKEY",   45),
    (RRSIG,      "RRSIG",      46),
    (NSEC,       "NSEC",       47),
    (DNSKEY,     "DNSKEY",     48),
    (NSEC3,      "NSEC3",      50),
    (NSEC3PARAM, "NSEC3PARAM", 51),
    (TLSA,       "TLSA",       52),
    (CDS,        "CDS",        59),
    (CDNSKEY,    "CDNSKEY",    60),
    (OPENPGPKEY, "OPENPGPKEY", 61),
    (ZONEMD,     "ZONEMD",     63),
    (SVCB,       "SVCB",       64),
    (HTTPS,      "HTTPS",      65),
    (CAA,        "CAA",        257),
    (ANAME,      "ANAME",      65305),
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
