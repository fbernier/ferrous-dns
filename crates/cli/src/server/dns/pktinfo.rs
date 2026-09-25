use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;

#[cfg(target_os = "linux")]
use ferrous_dns_infrastructure::dns::wire_response;
use socket2::Socket;

#[cfg(target_os = "linux")]
pub(super) const BATCH_SIZE: usize = 64;
#[cfg(target_os = "linux")]
const RECV_BUF_SIZE: usize = 512;
/// Receive-side control buffer, with room beyond IPV6_PKTINFO so other
/// ancillary data cannot truncate it away (MSG_CTRUNC).
const RECV_CMSG_BUF_SIZE: usize = 128;

/// Offset of a control message's payload from its header.
// SAFETY: CMSG_LEN is pure size arithmetic.
const CMSG_HDR_LEN: usize = unsafe { libc::CMSG_LEN(0) } as usize;
/// `msg_controllen` for a lone IPV6_PKTINFO: `CMSG_LEN`, not `CMSG_SPACE`.
/// Linux copies control data up to 36 bytes into an on-stack buffer and
/// kmallocs anything larger; CMSG_SPACE's 4 bytes of tail padding (40) would
/// cost an allocation and free on every send.
// SAFETY: CMSG_LEN is pure size arithmetic.
const PKTINFO_CMSG_LEN: usize =
    unsafe { libc::CMSG_LEN(size_of::<libc::in6_pktinfo>() as u32) } as usize;
// SAFETY: CMSG_SPACE is pure size arithmetic.
const PKTINFO_CMSG_SPACE: usize =
    unsafe { libc::CMSG_SPACE(size_of::<libc::in6_pktinfo>() as u32) } as usize;

/// Asks the kernel to report each datagram's destination (IPV6_PKTINFO), so
/// replies leave from the address the query reached. The listeners are
/// AF_INET6 dual-stack sockets on which IPv4 destinations arrive v4-mapped,
/// so the IPv6 option alone covers both families.
pub(super) fn enable_pktinfo(socket: &Socket) -> io::Result<()> {
    let on: libc::c_int = 1;
    // SAFETY: the fd stays open for the lifetime of `socket`; `on` outlives
    // the call and the length passed is its size.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVPKTINFO,
            (&raw const on).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Ancillary-data storage aligned for `cmsghdr`, so a header can be written
/// in place; a bare `[u8; N]` only guarantees alignment 1.
#[repr(C)]
struct CmsgBuf<const N: usize> {
    _align: [libc::cmsghdr; 0],
    bytes: [u8; N],
}

impl<const N: usize> CmsgBuf<N> {
    const fn zeroed() -> Self {
        Self {
            _align: [],
            bytes: [0; N],
        }
    }

    /// The first `len` bytes, as reported filled by the kernel, clamped to
    /// the buffer.
    fn filled(&self, len: usize) -> &[u8] {
        &self.bytes[..len.min(N)]
    }

    /// Writes a lone IPV6_PKTINFO message that sends from `src` on interface
    /// `ifindex`; it occupies the first `PKTINFO_CMSG_LEN` bytes.
    fn write_pktinfo(&mut self, src: IpAddr, ifindex: u32) {
        const { assert!(N >= PKTINFO_CMSG_LEN) };
        // Also clears the padding musl's 64-bit `cmsghdr` keeps inside the
        // kernel's `cmsg_len` word.
        self.bytes.fill(0);
        let cmsg = self.bytes.as_mut_ptr().cast::<libc::cmsghdr>();
        // SAFETY: `bytes` sits at offset 0 of this cmsghdr-aligned struct and
        // holds at least PKTINFO_CMSG_LEN bytes (asserted above), which covers
        // the header and the in6_pktinfo at CMSG_HDR_LEN; the payload write is
        // unaligned, so its own alignment is irrelevant.
        unsafe {
            (*cmsg).cmsg_len = PKTINFO_CMSG_LEN as _;
            (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
            (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
            cmsg.cast::<u8>()
                .add(CMSG_HDR_LEN)
                .cast::<libc::in6_pktinfo>()
                .write_unaligned(libc::in6_pktinfo {
                    ipi6_addr: ip_to_in6_addr(src),
                    ipi6_ifindex: ifindex,
                });
        }
    }
}

/// Heap-allocates a zero-filled `T` without building it on the stack first.
///
/// # Safety
/// The all-zero bit pattern must be a valid `T`.
#[cfg(target_os = "linux")]
unsafe fn zeroed_box<T>() -> Box<T> {
    Box::<T>::new_zeroed().assume_init()
}

/// Storage and headers for one `recvmmsg` call.
///
/// `hdrs` and `iovecs` hold raw pointers into the other boxed arrays, wired
/// once in `new`. The boxes are never replaced, and moving the batch moves
/// only the box pointers, so the wiring stays valid for the batch's lifetime.
#[cfg(target_os = "linux")]
pub(super) struct RecvBatch {
    recv_bufs: Box<[[u8; RECV_BUF_SIZE]; BATCH_SIZE]>,
    cmsg_bufs: Box<[CmsgBuf<RECV_CMSG_BUF_SIZE>; BATCH_SIZE]>,
    src_addrs: Box<[libc::sockaddr_in6; BATCH_SIZE]>,
    iovecs: Box<[libc::iovec; BATCH_SIZE]>,
    hdrs: Box<[libc::mmsghdr; BATCH_SIZE]>,
    /// Headers the last `recv` wrote; only those need their
    /// `msg_controllen` restored.
    written: usize,
}

// SAFETY: the raw pointers inside `hdrs` and `iovecs` point only into heap
// arrays this batch owns, which a move does not relocate. The batch is not
// Clone, so the worker that owns it has exclusive access.
#[cfg(target_os = "linux")]
unsafe impl Send for RecvBatch {}

#[cfg(target_os = "linux")]
impl RecvBatch {
    pub(super) fn new() -> Self {
        // SAFETY: byte arrays, `CmsgBuf`, and the libc C structs (integers and
        // raw pointers only) are all valid when zeroed.
        let mut batch = unsafe {
            Self {
                recv_bufs: zeroed_box(),
                cmsg_bufs: zeroed_box(),
                src_addrs: zeroed_box(),
                iovecs: zeroed_box(),
                hdrs: zeroed_box(),
                written: 0,
            }
        };
        for i in 0..BATCH_SIZE {
            batch.iovecs[i] = libc::iovec {
                iov_base: batch.recv_bufs[i].as_mut_ptr().cast(),
                iov_len: RECV_BUF_SIZE,
            };
            let hdr = &mut batch.hdrs[i].msg_hdr;
            hdr.msg_name = (&raw mut batch.src_addrs[i]).cast();
            hdr.msg_namelen = size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            hdr.msg_iov = &raw mut batch.iovecs[i];
            hdr.msg_iovlen = 1;
            hdr.msg_control = batch.cmsg_bufs[i].bytes.as_mut_ptr().cast();
            hdr.msg_controllen = RECV_CMSG_BUF_SIZE as _;
        }
        batch
    }

    /// Restores `msg_controllen` to its original size before each `recvmmsg`
    /// call. The kernel shrinks `msg_controllen` to the actual ancillary data
    /// length; without this reset, subsequent calls may fail to deliver pktinfo.
    /// Only the headers it filled last time were touched, so a sparse socket
    /// resets one header, not the whole batch.
    fn reset_controllen(&mut self) {
        for hdr in &mut self.hdrs[..self.written] {
            hdr.msg_hdr.msg_controllen = RECV_CMSG_BUF_SIZE as _;
        }
        self.written = 0;
    }

    /// Receives up to `BATCH_SIZE` datagrams in one syscall and returns how
    /// many arrived; `Err(WouldBlock)` when none are pending.
    pub(super) fn recv(&mut self, fd: RawFd) -> io::Result<usize> {
        self.reset_controllen();

        // SAFETY: `hdrs` holds exactly BATCH_SIZE headers, each wired in `new`
        // to buffers this batch owns, so the kernel writes only into our
        // memory. MSG_DONTWAIT and the null timeout make the call non-blocking.
        let n = unsafe {
            libc::recvmmsg(
                fd,
                self.hdrs.as_mut_ptr(),
                BATCH_SIZE as libc::c_uint,
                libc::MSG_DONTWAIT as _,
                std::ptr::null_mut(),
            )
        };

        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        self.written = n as usize;
        Ok(self.written)
    }

    /// Payload and addressing of slot `i`, for `i` below the count the last
    /// `recv` returned.
    pub(super) fn get_msg(&self, i: usize) -> ReceivedMsg<'_> {
        let hdr = &self.hdrs[i];
        let control = self.cmsg_bufs[i].filled(hdr.msg_hdr.msg_controllen as _);
        ReceivedMsg {
            data: &self.recv_bufs[i][..hdr.msg_len as usize],
            src: sockaddr_in6_to_socket_addr(&self.src_addrs[i]),
            dst_ip: extract_pktinfo_dst(control),
        }
    }
}

/// Payload and addressing metadata for one received UDP datagram.
#[cfg(target_os = "linux")]
pub(super) struct ReceivedMsg<'a> {
    /// Raw wire bytes of the DNS query.
    pub data: &'a [u8],
    /// Source address of the client (v4-mapped clients normalised to `IpAddr::V4`).
    pub src: SocketAddr,
    /// Destination IP (our interface) extracted from IPV6_PKTINFO.
    pub dst_ip: IpAddr,
}

/// Capacity of one inline cache-hit response; see `wire_response`.
#[cfg(target_os = "linux")]
pub(super) type ResponseBuf = [u8; wire_response::RESPONSE_BUF_LEN];

/// A fast-path WireData response (MX, TXT, NS, CNAME, SOA, PTR) queued for
/// individual sendmsg. Heap-allocated because WireData can exceed 523 bytes.
#[cfg(target_os = "linux")]
pub(super) struct PendingWireResponse {
    pub data: Vec<u8>,
    pub to: SocketAddr,
    pub src_ip: IpAddr,
}

/// Storage and headers for one `sendmmsg` call, including the response
/// bytes, so a cache hit is encoded straight into the buffer the kernel
/// reads. Wired once in `new` like [`RecvBatch`]; slots `[..staged]` hold the
/// responses of the next flush.
#[cfg(target_os = "linux")]
pub(super) struct SendBatch {
    wires: Box<[ResponseBuf; BATCH_SIZE]>,
    cmsg_bufs: Box<[CmsgBuf<PKTINFO_CMSG_SPACE>; BATCH_SIZE]>,
    dst_addrs: Box<[libc::sockaddr_in6; BATCH_SIZE]>,
    iovecs: Box<[libc::iovec; BATCH_SIZE]>,
    hdrs: Box<[libc::mmsghdr; BATCH_SIZE]>,
    staged: usize,
}

// SAFETY: as for `RecvBatch`, the wired raw pointers target only heap arrays
// this batch owns, and the owning worker has exclusive access.
#[cfg(target_os = "linux")]
unsafe impl Send for SendBatch {}

#[cfg(target_os = "linux")]
impl SendBatch {
    pub(super) fn new() -> Self {
        // SAFETY: as in `RecvBatch::new`, every field is valid when zeroed.
        let mut batch = unsafe {
            Self {
                wires: zeroed_box(),
                cmsg_bufs: zeroed_box(),
                dst_addrs: zeroed_box(),
                iovecs: zeroed_box(),
                hdrs: zeroed_box(),
                staged: 0,
            }
        };
        for i in 0..BATCH_SIZE {
            batch.iovecs[i].iov_base = batch.wires[i].as_mut_ptr().cast();
            let hdr = &mut batch.hdrs[i].msg_hdr;
            hdr.msg_name = (&raw mut batch.dst_addrs[i]).cast();
            hdr.msg_namelen = size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            hdr.msg_iov = &raw mut batch.iovecs[i];
            hdr.msg_iovlen = 1;
            hdr.msg_control = batch.cmsg_bufs[i].bytes.as_mut_ptr().cast();
        }
        batch
    }

    /// Encodes a response into the next free slot with `encode`, which returns
    /// its length or `None` to decline, and queues it for `to` from `src_ip`.
    /// Returns whether it was queued; `false` also when the batch is full.
    pub(super) fn stage(
        &mut self,
        to: SocketAddr,
        src_ip: IpAddr,
        encode: impl FnOnce(&mut ResponseBuf) -> Option<usize>,
    ) -> bool {
        let i = self.staged;
        let Some(wire) = self.wires.get_mut(i) else {
            return false;
        };
        let Some(len) = encode(wire) else {
            return false;
        };

        self.dst_addrs[i] = socket_addr_to_sockaddr_in6(to);
        self.iovecs[i].iov_len = len;

        let hdr = &mut self.hdrs[i].msg_hdr;
        if is_unspecified(src_ip) {
            // No captured destination: let the kernel pick the source address.
            hdr.msg_controllen = 0;
        } else {
            self.cmsg_bufs[i].write_pktinfo(src_ip, dest_scope_id(to));
            hdr.msg_controllen = PKTINFO_CMSG_LEN as _;
        }
        self.staged += 1;
        true
    }

    /// Sends every staged response with one `sendmmsg` and empties the batch.
    /// Returns `Ok(())` on success or partial send.
    pub(super) fn flush(&mut self, fd: RawFd) -> io::Result<()> {
        let count = std::mem::take(&mut self.staged);
        if count == 0 {
            return Ok(());
        }

        // SAFETY: `count <= BATCH_SIZE`, and `stage` filled hdrs[..count],
        // whose pointers target buffers this batch owns. MSG_DONTWAIT avoids
        // blocking when the send buffer is full.
        let n = unsafe {
            libc::sendmmsg(
                fd,
                self.hdrs.as_mut_ptr(),
                count as libc::c_uint,
                libc::MSG_DONTWAIT as _,
            )
        };

        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn try_recv_with_pktinfo(
    socket: &std::net::UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, IpAddr)> {
    let fd = socket.as_raw_fd();
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // SAFETY: sockaddr_in6 and msghdr are C structs; zeroing is the correct way to initialize them.
    let mut src_addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let mut control = CmsgBuf::<RECV_CMSG_BUF_SIZE>::zeroed();
    // SAFETY: as above.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&raw mut src_addr).cast();
    msg.msg_namelen = size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.bytes.as_mut_ptr().cast();
    msg.msg_controllen = RECV_CMSG_BUF_SIZE as _;

    // SAFETY: fd is valid; msg points to iov, src_addr and control, all live on the stack.
    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let from = sockaddr_in6_to_socket_addr(&src_addr);
    let dst = extract_pktinfo_dst(control.filled(msg.msg_controllen as _));

    Ok((n as usize, from, dst))
}

/// Sends `buf` to `to` from source address `src`, or from whatever address
/// the kernel picks when `src` is unspecified (no destination was captured).
pub(super) fn try_send_with_src_ip(
    socket: &std::net::UdpSocket,
    buf: &[u8],
    to: SocketAddr,
    src: IpAddr,
) -> io::Result<()> {
    let dst_addr = socket_addr_to_sockaddr_in6(to);
    let iov = libc::iovec {
        iov_base: buf.as_ptr().cast_mut().cast(),
        iov_len: buf.len(),
    };
    let mut control = CmsgBuf::<PKTINFO_CMSG_SPACE>::zeroed();
    // SAFETY: msghdr is a C struct; zeroing is the correct initialization before setting fields.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&raw const dst_addr).cast_mut().cast();
    msg.msg_namelen = size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    msg.msg_iov = (&raw const iov).cast_mut();
    msg.msg_iovlen = 1;
    if !is_unspecified(src) {
        control.write_pktinfo(src, dest_scope_id(to));
        msg.msg_control = control.bytes.as_mut_ptr().cast();
        msg.msg_controllen = PKTINFO_CMSG_LEN as _;
    }

    // SAFETY: fd is valid; msg points to dst_addr, iov and control, all live on
    // the stack, and the kernel only reads through them.
    let n = unsafe { libc::sendmsg(socket.as_raw_fd(), &msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Destination address carried by an IPV6_PKTINFO message in `control`, or
/// `::` when there is none. Every read is bounds-checked against `control`,
/// so arbitrary bytes are handled soundly.
fn extract_pktinfo_dst(mut control: &[u8]) -> IpAddr {
    while control.len() >= PKTINFO_CMSG_LEN {
        // SAFETY: `control` holds at least a `cmsghdr`; the read is unaligned.
        let hdr = unsafe { control.as_ptr().cast::<libc::cmsghdr>().read_unaligned() };
        if hdr.cmsg_level == libc::IPPROTO_IPV6 && hdr.cmsg_type == libc::IPV6_PKTINFO {
            // SAFETY: `control.len() >= PKTINFO_CMSG_LEN` covers the
            // in6_pktinfo at CMSG_HDR_LEN; the read is unaligned.
            let pktinfo = unsafe {
                control
                    .as_ptr()
                    .add(CMSG_HDR_LEN)
                    .cast::<libc::in6_pktinfo>()
                    .read_unaligned()
            };
            return unmap_v4(Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr));
        }
        let cmsg_len: usize = hdr.cmsg_len as _;
        let Some(payload) = cmsg_len.checked_sub(CMSG_HDR_LEN) else {
            break;
        };
        // CMSG_SPACE(payload) is the aligned stride to the next header; the
        // clamp keeps the arithmetic in range, as no stride past the end matters.
        // SAFETY: CMSG_SPACE is pure size arithmetic.
        let stride = unsafe { libc::CMSG_SPACE(payload.min(control.len()) as u32) } as usize;
        control = control.get(stride..).unwrap_or_default();
    }

    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
}

/// Normalises a (possibly v4-mapped) IPv6 address back to a real `IpAddr::V4`
/// so the application's client-IP / blocking logic still sees genuine IPv4.
fn unmap_v4(v6: Ipv6Addr) -> IpAddr {
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

/// Converts an `IpAddr` to an `in6_addr`, mapping IPv4 to `::ffff:a.b.c.d` so it
/// can be used with the dual-stack AF_INET6 socket.
fn ip_to_in6_addr(ip: IpAddr) -> libc::in6_addr {
    let v6 = match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    libc::in6_addr {
        s6_addr: v6.octets(),
    }
}

fn is_unspecified(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_unspecified(),
    }
}

/// Scope id of a destination address, used as the reply's outgoing interface
/// so link-local clients are answered on the link the query came from.
fn dest_scope_id(addr: SocketAddr) -> u32 {
    match addr {
        SocketAddr::V6(v6) => v6.scope_id(),
        SocketAddr::V4(_) => 0,
    }
}

/// Normalises a v4-mapped socket address (`::ffff:a.b.c.d`) back to plain IPv4.
/// The dual-stack listeners report IPv4 peers in mapped form; client-facing
/// logic (groups, limits, logs) expects real IPv4.
pub(super) fn unmap_socket_addr(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), addr.port()),
            None => addr,
        },
        IpAddr::V4(_) => addr,
    }
}

/// Rewrites an IPv4 bind address into its v4-mapped form (`::ffff:a.b.c.d`) so
/// every listener can be created on an AF_INET6 socket. An IPv6 bind is left
/// alone: combined with `set_only_v6(false)`, a `[::]` bind then serves both
/// families on a single socket, while a mapped IPv4 bind stays v4-only.
pub(super) fn v6_mapped_bind_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()),
        SocketAddr::V6(_) => addr,
    }
}

pub(super) fn sockaddr_in6_to_socket_addr(addr: &libc::sockaddr_in6) -> SocketAddr {
    let v6 = Ipv6Addr::from(addr.sin6_addr.s6_addr);
    let port = u16::from_be(addr.sin6_port);
    match unmap_v4(v6) {
        IpAddr::V4(v4) => SocketAddr::new(IpAddr::V4(v4), port),
        // Keep the scope id: replies to link-local clients need it.
        IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, addr.sin6_scope_id)),
    }
}

pub(super) fn socket_addr_to_sockaddr_in6(addr: SocketAddr) -> libc::sockaddr_in6 {
    // SAFETY: sockaddr_in6 is a C struct; zeroing is the correct initialization before setting fields.
    let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    sa.sin6_addr = ip_to_in6_addr(addr.ip());
    sa.sin6_port = addr.port().to_be();
    if let SocketAddr::V6(v6) = addr {
        sa.sin6_scope_id = v6.scope_id();
    }
    sa
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn unmap_v4_returns_real_v4_for_mapped_address() {
        let mapped: Ipv6Addr = "::ffff:192.0.2.1".parse().unwrap();
        assert_eq!(unmap_v4(mapped), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn unmap_v4_keeps_native_v6() {
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(unmap_v4(v6), IpAddr::V6(v6));
    }

    #[test]
    fn ip_to_in6_addr_maps_v4() {
        let addr = ip_to_in6_addr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        let expected: Ipv6Addr = "::ffff:192.0.2.1".parse().unwrap();
        assert_eq!(addr.s6_addr, expected.octets());
    }

    #[test]
    fn ip_to_in6_addr_passes_v6_through() {
        let v6: Ipv6Addr = "2001:db8::2".parse().unwrap();
        assert_eq!(ip_to_in6_addr(IpAddr::V6(v6)).s6_addr, v6.octets());
    }

    #[test]
    fn is_unspecified_detects_both_families() {
        assert!(is_unspecified("0.0.0.0".parse().unwrap()));
        assert!(is_unspecified("::".parse().unwrap()));
        assert!(!is_unspecified("192.0.2.1".parse().unwrap()));
        assert!(!is_unspecified("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn sockaddr_round_trip_v4() {
        let addr: SocketAddr = "192.0.2.1:5353".parse().unwrap();
        let sa = socket_addr_to_sockaddr_in6(addr);
        assert_eq!(sa.sin6_family, libc::AF_INET6 as libc::sa_family_t);
        assert_eq!(sockaddr_in6_to_socket_addr(&sa), addr);
    }

    #[test]
    fn sockaddr_round_trip_v6() {
        let addr: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        let sa = socket_addr_to_sockaddr_in6(addr);
        assert_eq!(sockaddr_in6_to_socket_addr(&sa), addr);
    }

    #[test]
    fn sockaddr_round_trip_keeps_link_local_scope_id() {
        let addr = SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 53, 0, 7));
        let sa = socket_addr_to_sockaddr_in6(addr);
        assert_eq!(sa.sin6_scope_id, 7);
        assert_eq!(sockaddr_in6_to_socket_addr(&sa), addr);
        assert_eq!(dest_scope_id(addr), 7);
    }

    #[test]
    fn unmap_socket_addr_normalises_mapped_peers() {
        let mapped: SocketAddr = "[::ffff:192.0.2.1]:4242".parse().unwrap();
        assert_eq!(
            unmap_socket_addr(mapped),
            "192.0.2.1:4242".parse::<SocketAddr>().unwrap()
        );
        let v6: SocketAddr = "[2001:db8::1]:4242".parse().unwrap();
        assert_eq!(unmap_socket_addr(v6), v6);
    }

    #[test]
    fn v6_mapped_bind_addr_maps_ipv4_binds() {
        let v4: SocketAddr = "192.0.2.1:853".parse().unwrap();
        assert_eq!(
            v6_mapped_bind_addr(v4),
            "[::ffff:192.0.2.1]:853".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn v6_mapped_bind_addr_keeps_ipv6_binds() {
        let wildcard: SocketAddr = "[::]:853".parse().unwrap();
        assert_eq!(v6_mapped_bind_addr(wildcard), wildcard);
    }

    fn put_cmsg_header(buf: &mut [u8], level: libc::c_int, ty: libc::c_int, len: usize) {
        assert!(buf.len() >= size_of::<libc::cmsghdr>());
        // SAFETY: cmsghdr is a C struct; zeroing is a valid initialization.
        let mut hdr: libc::cmsghdr = unsafe { std::mem::zeroed() };
        hdr.cmsg_len = len as _;
        hdr.cmsg_level = level;
        hdr.cmsg_type = ty;
        // SAFETY: bounds asserted above; the write is unaligned.
        unsafe {
            buf.as_mut_ptr()
                .cast::<libc::cmsghdr>()
                .write_unaligned(hdr)
        };
    }

    #[test]
    fn written_pktinfo_is_read_back() {
        let mut control = CmsgBuf::<PKTINFO_CMSG_SPACE>::zeroed();
        control.write_pktinfo(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 3);
        assert_eq!(
            extract_pktinfo_dst(control.filled(PKTINFO_CMSG_LEN)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))
        );
    }

    #[test]
    fn pktinfo_after_another_control_message_is_found() {
        // SAFETY: CMSG_LEN / CMSG_SPACE are pure size arithmetic.
        let (other_len, other_space) = unsafe { (libc::CMSG_LEN(8), libc::CMSG_SPACE(8)) };
        let offset = other_space as usize;
        let mut control = [0u8; RECV_CMSG_BUF_SIZE];
        put_cmsg_header(&mut control, libc::SOL_SOCKET, 99, other_len as usize);
        let mut pktinfo = CmsgBuf::<PKTINFO_CMSG_SPACE>::zeroed();
        pktinfo.write_pktinfo("2001:db8::53".parse().unwrap(), 0);
        control[offset..offset + PKTINFO_CMSG_LEN]
            .copy_from_slice(&pktinfo.bytes[..PKTINFO_CMSG_LEN]);

        assert_eq!(
            extract_pktinfo_dst(&control[..offset + PKTINFO_CMSG_LEN]),
            "2001:db8::53".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn malformed_control_messages_yield_unspecified() {
        let unspecified = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        let mut control = [0u8; RECV_CMSG_BUF_SIZE];

        // A length shorter than the header itself must stop the walk.
        put_cmsg_header(&mut control, libc::SOL_SOCKET, 99, 0);
        assert_eq!(extract_pktinfo_dst(&control), unspecified);

        // A length reaching past the buffer must not step out of it.
        put_cmsg_header(&mut control, libc::SOL_SOCKET, 99, usize::MAX >> 1);
        assert_eq!(extract_pktinfo_dst(&control), unspecified);

        // A pktinfo header whose payload was cut off is not read.
        let mut pktinfo = CmsgBuf::<PKTINFO_CMSG_SPACE>::zeroed();
        pktinfo.write_pktinfo(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 0);
        assert_eq!(
            extract_pktinfo_dst(&pktinfo.bytes[..PKTINFO_CMSG_LEN - 1]),
            unspecified
        );
    }

    #[test]
    fn enable_pktinfo_reports_setsockopt_failure() {
        let v4_only = Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        assert!(enable_pktinfo(&v4_only).is_err());
    }
}
