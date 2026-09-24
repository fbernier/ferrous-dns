use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

/// Represents an upstream server address that may or may not be resolved to an IP.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UpstreamAddr {
    Resolved(SocketAddr),
    Unresolved { hostname: Arc<str>, port: u16 },
}

impl UpstreamAddr {
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            UpstreamAddr::Resolved(addr) => Some(*addr),
            UpstreamAddr::Unresolved { .. } => None,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            UpstreamAddr::Resolved(addr) => addr.port(),
            UpstreamAddr::Unresolved { port, .. } => *port,
        }
    }

    pub fn is_unresolved(&self) -> bool {
        matches!(self, UpstreamAddr::Unresolved { .. })
    }

    /// Returns (hostname, port) if this address is unresolved.
    pub fn unresolved_parts(&self) -> Option<(&str, u16)> {
        match self {
            UpstreamAddr::Unresolved { hostname, port } => Some((hostname, *port)),
            UpstreamAddr::Resolved(_) => None,
        }
    }
}

impl fmt::Display for UpstreamAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpstreamAddr::Resolved(addr) => write!(f, "{}", addr),
            UpstreamAddr::Unresolved { hostname, port } => write!(f, "{}:{}", hostname, port),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DnsProtocol {
    Udp {
        addr: UpstreamAddr,
    },
    Tcp {
        addr: UpstreamAddr,
    },
    Tls {
        addr: UpstreamAddr,
        hostname: Arc<str>,
    },
    Https {
        url: Arc<str>,
        /// URL host without brackets or port: the name the certificate is checked against.
        hostname: Arc<str>,
        port: u16,
        resolved_addrs: Vec<SocketAddr>,
    },
    Quic {
        addr: UpstreamAddr,
        hostname: Arc<str>,
    },
    H3 {
        url: Arc<str>,
        /// URL host without brackets or port: the name the certificate is checked against.
        hostname: Arc<str>,
        port: u16,
        resolved_addrs: Vec<SocketAddr>,
    },
}

impl DnsProtocol {
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            DnsProtocol::Udp { addr }
            | DnsProtocol::Tcp { addr }
            | DnsProtocol::Tls { addr, .. }
            | DnsProtocol::Quic { addr, .. } => addr.socket_addr(),
            DnsProtocol::Https { .. } | DnsProtocol::H3 { .. } => None,
        }
    }

    pub fn hostname(&self) -> Option<&str> {
        match self {
            DnsProtocol::Tls { hostname, .. }
            | DnsProtocol::Https { hostname, .. }
            | DnsProtocol::Quic { hostname, .. }
            | DnsProtocol::H3 { hostname, .. } => Some(hostname),
            DnsProtocol::Udp { .. } | DnsProtocol::Tcp { .. } => None,
        }
    }

    /// Returns `true` if this protocol has an unresolved hostname that needs DNS resolution.
    pub fn needs_resolution(&self) -> bool {
        match self {
            DnsProtocol::Udp { addr }
            | DnsProtocol::Tcp { addr }
            | DnsProtocol::Tls { addr, .. }
            | DnsProtocol::Quic { addr, .. } => addr.is_unresolved(),
            DnsProtocol::Https {
                hostname,
                resolved_addrs,
                ..
            }
            | DnsProtocol::H3 {
                hostname,
                resolved_addrs,
                ..
            } => hostname.parse::<IpAddr>().is_err() && resolved_addrs.is_empty(),
        }
    }

    /// Creates a copy of this protocol with the given resolved `SocketAddr`.
    /// Used by PoolManager to expand hostnames into concrete IP addresses.
    pub fn with_resolved_addr(&self, resolved: SocketAddr) -> Self {
        match self {
            DnsProtocol::Udp { .. } => DnsProtocol::Udp {
                addr: UpstreamAddr::Resolved(resolved),
            },
            DnsProtocol::Tcp { .. } => DnsProtocol::Tcp {
                addr: UpstreamAddr::Resolved(resolved),
            },
            DnsProtocol::Tls { hostname, .. } => DnsProtocol::Tls {
                addr: UpstreamAddr::Resolved(resolved),
                hostname: hostname.clone(),
            },
            DnsProtocol::Quic { hostname, .. } => DnsProtocol::Quic {
                addr: UpstreamAddr::Resolved(resolved),
                hostname: hostname.clone(),
            },
            DnsProtocol::Https { .. } | DnsProtocol::H3 { .. } => self.clone(),
        }
    }

    pub fn with_resolved_addrs(&self, addrs: Vec<SocketAddr>) -> Self {
        match self {
            DnsProtocol::Https {
                url,
                hostname,
                port,
                ..
            } => DnsProtocol::Https {
                url: url.clone(),
                hostname: hostname.clone(),
                port: *port,
                resolved_addrs: addrs,
            },
            DnsProtocol::H3 {
                url,
                hostname,
                port,
                ..
            } => DnsProtocol::H3 {
                url: url.clone(),
                hostname: hostname.clone(),
                port: *port,
                resolved_addrs: addrs,
            },
            DnsProtocol::Udp { .. }
            | DnsProtocol::Tcp { .. }
            | DnsProtocol::Tls { .. }
            | DnsProtocol::Quic { .. } => self.clone(),
        }
    }
}

fn parse_host_port(s: &str) -> Option<(&str, u16)> {
    if s.starts_with('[') {
        let end = s.find(']')?;
        let host = &s[1..end];
        let rest = &s[end + 1..];
        let port_str = rest.strip_prefix(':')?;
        let port = port_str.parse::<u16>().ok()?;
        Some((host, port))
    } else {
        let (host, port_str) = s.rsplit_once(':')?;
        let port = port_str.parse::<u16>().ok()?;
        Some((host, port))
    }
}

/// The returned name is what the peer certificate is checked against; IPs stay unbracketed.
fn parse_named_addr(rest: &str) -> Result<(UpstreamAddr, Arc<str>), String> {
    if let Ok(addr) = rest.parse::<SocketAddr>() {
        return Ok((UpstreamAddr::Resolved(addr), addr.ip().to_string().into()));
    }
    let (host, port_str) = rest.rsplit_once(':').ok_or("missing port")?;
    let port = port_str
        .parse::<u16>()
        .map_err(|e| format!("invalid port: {e}"))?;
    let hostname: Arc<str> = host.into();
    Ok((
        UpstreamAddr::Unresolved {
            hostname: hostname.clone(),
            port,
        },
        hostname,
    ))
}

/// Splits the authority of `rest` (a URL after its scheme) into the bare host,
/// IPv6 unbracketed, and the port, 443 when absent.
fn parse_url_authority(rest: &str) -> Result<(Arc<str>, u16), String> {
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let (host, port) = match authority.strip_prefix('[') {
        Some(bracketed) => {
            let (host, after) = bracketed
                .split_once(']')
                .ok_or("unterminated IPv6 literal")?;
            host.parse::<Ipv6Addr>()
                .map_err(|e| format!("invalid IPv6 literal '{host}': {e}"))?;
            let port = match after {
                "" => None,
                _ => Some(
                    after
                        .strip_prefix(':')
                        .ok_or("unexpected characters after IPv6 literal")?,
                ),
            };
            (host, port)
        }
        // An unbracketed IPv6 address lands here and fails the port parse.
        None => match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    if host.is_empty() {
        return Err("missing host".into());
    }
    let port = match port {
        Some(port) => port
            .parse::<u16>()
            .map_err(|e| format!("invalid port '{port}': {e}"))?,
        None => 443,
    };
    Ok((host.into(), port))
}

fn parse_upstream_addr(addr_str: &str) -> Result<UpstreamAddr, String> {
    if let Ok(addr) = addr_str.parse::<SocketAddr>() {
        return Ok(UpstreamAddr::Resolved(addr));
    }
    if let Some((host, port)) = parse_host_port(addr_str) {
        return Ok(UpstreamAddr::Unresolved {
            hostname: host.into(),
            port,
        });
    }
    Err(format!("Invalid address '{}'", addr_str))
}

impl FromStr for DnsProtocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(addr_str) = s.strip_prefix("udp://") {
            let addr = parse_upstream_addr(addr_str)
                .map_err(|_| format!("Invalid UDP address '{}'", addr_str))?;
            return Ok(DnsProtocol::Udp { addr });
        }
        if let Some(addr_str) = s.strip_prefix("tcp://") {
            let addr = parse_upstream_addr(addr_str)
                .map_err(|_| format!("Invalid TCP address '{}'", addr_str))?;
            return Ok(DnsProtocol::Tcp { addr });
        }
        if let Some(rest) = s.strip_prefix("tls://") {
            let (addr, hostname) = parse_named_addr(rest)
                .map_err(|e| format!("Invalid TLS address '{s}': {e}. Expected 'tls://IP:PORT' or 'tls://HOSTNAME:PORT'"))?;
            return Ok(DnsProtocol::Tls { addr, hostname });
        }
        if let Some(rest) = s.strip_prefix("doq://") {
            let (addr, hostname) = parse_named_addr(rest)
                .map_err(|e| format!("Invalid QUIC address '{s}': {e}. Expected 'doq://IP:PORT' or 'doq://HOSTNAME:PORT'"))?;
            return Ok(DnsProtocol::Quic { addr, hostname });
        }
        if let Some(rest) = s.strip_prefix("h3://") {
            let (hostname, port) =
                parse_url_authority(rest).map_err(|e| format!("Invalid H3 URL '{s}': {e}"))?;
            return Ok(DnsProtocol::H3 {
                url: s.into(),
                hostname,
                port,
                resolved_addrs: vec![],
            });
        }
        if let Some(rest) = s.strip_prefix("https://") {
            let (hostname, port) =
                parse_url_authority(rest).map_err(|e| format!("Invalid HTTPS URL '{s}': {e}"))?;
            return Ok(DnsProtocol::Https {
                url: s.into(),
                hostname,
                port,
                resolved_addrs: vec![],
            });
        }
        if let Ok(addr) = s.parse::<SocketAddr>() {
            return Ok(DnsProtocol::Udp {
                addr: UpstreamAddr::Resolved(addr),
            });
        }
        Err(format!("Invalid DNS endpoint format: '{}'. Expected: udp://IP:PORT, tcp://IP:PORT, tls://HOST:PORT, https://URL, h3://URL, doq://HOST:PORT, or IP:PORT", s))
    }
}

impl fmt::Display for DnsProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsProtocol::Udp { addr } => write!(f, "udp://{}", addr),
            DnsProtocol::Tcp { addr } => write!(f, "tcp://{}", addr),
            DnsProtocol::Tls { addr, hostname } => {
                write!(f, "tls://")?;
                write_host_port(f, hostname, addr.port())
            }
            DnsProtocol::Https { url, .. } => write!(f, "{}", url),
            DnsProtocol::H3 { url, .. } => write!(f, "{}", url),
            DnsProtocol::Quic { addr, hostname } => {
                write!(f, "doq://")?;
                write_host_port(f, hostname, addr.port())
            }
        }
    }
}

fn write_host_port(f: &mut fmt::Formatter<'_>, host: &str, port: u16) -> fmt::Result {
    if host.contains(':') {
        write!(f, "[{host}]:{port}")
    } else {
        write!(f, "{host}:{port}")
    }
}
