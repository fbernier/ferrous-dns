use ferrous_dns_domain::DomainError;
use std::io;
use std::net::{IpAddr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt};

const PROXY_V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
const FIXED_HEADER_LEN: usize = 16;
const MAX_ADDITIONAL_LEN: usize = 536;

const COMMAND_LOCAL: u8 = 0x00;
const COMMAND_PROXY: u8 = 0x01;

const FAMILY_TCP4: u8 = 0x11;
const FAMILY_TCP6: u8 = 0x21;

fn read_error(e: io::Error) -> DomainError {
    DomainError::IoError(format!("reading PROXY Protocol v2 header: {e}"))
}

fn invalid_header(reason: &str) -> DomainError {
    DomainError::InvalidInput(format!("PROXY Protocol v2 header: {reason}"))
}

/// The client address behind a PROXY Protocol v2 header. Read failures are
/// `IoError`; a malformed header is `InvalidInput`.
pub async fn read_proxy_v2_client_ip<R: AsyncRead + Unpin>(
    stream: &mut R,
    peer_addr: IpAddr,
) -> Result<IpAddr, DomainError> {
    let mut header = [0u8; FIXED_HEADER_LEN];
    stream.read_exact(&mut header).await.map_err(read_error)?;

    if header[0..12] != PROXY_V2_SIGNATURE {
        return Err(invalid_header("invalid signature"));
    }

    let version = header[12] >> 4;
    if version != 2 {
        return Err(invalid_header("unsupported version (expected 2)"));
    }

    let command = header[12] & 0x0F;
    let family = header[13];
    let additional_len = u16::from_be_bytes([header[14], header[15]]) as usize;

    if additional_len > MAX_ADDITIONAL_LEN {
        return Err(DomainError::InvalidInput(format!(
            "PROXY Protocol v2 header: additional length exceeds {MAX_ADDITIONAL_LEN} bytes"
        )));
    }

    let mut additional = [0u8; MAX_ADDITIONAL_LEN];
    if additional_len > 0 {
        stream
            .read_exact(&mut additional[..additional_len])
            .await
            .map_err(read_error)?;
    }

    match command {
        COMMAND_LOCAL => Ok(peer_addr),
        COMMAND_PROXY => Ok(extract_source_ip(
            family,
            &additional[..additional_len],
            peer_addr,
        )),
        _ => Err(invalid_header("unknown command")),
    }
}

/// The client address a `PROXY` header carries. Any other family (`UNSPEC`,
/// datagram or UNIX) or a truncated address block keeps the peer address.
fn extract_source_ip(family: u8, additional: &[u8], peer_addr: IpAddr) -> IpAddr {
    match family {
        FAMILY_TCP4 => additional
            .first_chunk::<4>()
            .map_or(peer_addr, |octets| IpAddr::from(*octets)),
        FAMILY_TCP6 => additional.first_chunk::<16>().map_or(peer_addr, |octets| {
            // A dual-stack frontend encodes an IPv4 client as TCP6 with a
            // v4-mapped address. Normalise it, so a client keyed as
            // `10.0.0.1` on the direct path is not keyed as
            // `::ffff:10.0.0.1` behind the proxy.
            let v6 = Ipv6Addr::from(*octets);
            match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            }
        }),
        _ => peer_addr,
    }
}
