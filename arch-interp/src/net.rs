//! Native socket server for the hosted backend — the "punch-through" that
//! proxies the kernel's Linux socket syscalls to the host's `std::net`.
//!
//! The kernel runs native in this process, so a guest `socket`/`connect`/
//! `send`/`recv` becomes a real host TCP connection with no in-guest TCP/IP
//! stack. State is thread-local (set on the CPU/kernel thread before startup),
//! matching the native host-fs server. Raw `sockaddr_in` bytes cross the seam
//! and are parsed here, so no kernel type appears in this crate.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};

// Linux errnos we hand back (negated by the caller side already expects <0).
const EBADF: i32 = -9;
const EINVAL: i32 = -22;
const EAFNOSUPPORT: i32 = -97;
const ECONNREFUSED: i32 = -111;
const ENOTCONN: i32 = -107;
const EIO: i32 = -5;

enum HostSocket {
    /// Created but not yet connected/bound.
    Fresh { bind_addr: Option<SocketAddrV4> },
    Stream(TcpStream),
    Listener(TcpListener),
}

struct Sockets {
    map: HashMap<i32, HostSocket>,
    next: i32,
}

impl Sockets {
    fn insert(&mut self, s: HostSocket) -> i32 {
        let h = self.next;
        self.next += 1;
        self.map.insert(h, s);
        h
    }
}

thread_local! {
    /// The native socket table for the injected backend. Set by
    /// `install_native_sockets` on the CPU/kernel thread before startup.
    static NATIVE_SOCKETS: RefCell<Option<Sockets>> = const { RefCell::new(None) };
}

/// Enable the native socket backend on this (CPU/kernel) thread.
pub fn install_native_sockets() {
    NATIVE_SOCKETS.with(|s| *s.borrow_mut() = Some(Sockets { map: HashMap::new(), next: 1 }));
}

fn with<R>(f: impl FnOnce(&mut Sockets) -> R, miss: R) -> R {
    NATIVE_SOCKETS.with(|s| match s.borrow_mut().as_mut() {
        Some(sk) => f(sk),
        None => miss,
    })
}

/// Decode a guest `sockaddr_in` (native-endian family, big-endian port).
fn decode_sockaddr(a: &[u8]) -> Option<SocketAddrV4> {
    if a.len() < 8 {
        return None;
    }
    if u16::from_ne_bytes([a[0], a[1]]) != 2 {
        return None; // not AF_INET
    }
    let port = u16::from_be_bytes([a[2], a[3]]);
    Some(SocketAddrV4::new(Ipv4Addr::new(a[4], a[5], a[6], a[7]), port))
}

/// Encode a `sockaddr_in` (16 bytes) into `out` (capped); returns the full
/// structure length (16), the value `getsockname`/`accept` report.
fn encode_sockaddr(sa: SocketAddrV4, out: &mut [u8]) -> i32 {
    let mut buf = [0u8; 16];
    buf[0..2].copy_from_slice(&2u16.to_ne_bytes());
    buf[2..4].copy_from_slice(&sa.port().to_be_bytes());
    buf[4..8].copy_from_slice(&sa.ip().octets());
    let n = out.len().min(16);
    out[..n].copy_from_slice(&buf[..n]);
    16
}

// ── The primitive free functions the kernel's `SocketHooks` point at ──────

pub fn host_sock_socket(domain: i32, _ty: i32, _proto: i32) -> i32 {
    if domain != 2 {
        return EAFNOSUPPORT; // AF_INET only for now
    }
    with(|s| s.insert(HostSocket::Fresh { bind_addr: None }), EBADF)
}

pub fn host_sock_connect(h: i32, addr: &[u8]) -> i32 {
    let Some(sa) = decode_sockaddr(addr) else { return EINVAL };
    with(
        |s| {
            if !matches!(s.map.get(&h), Some(HostSocket::Fresh { .. })) {
                return EBADF;
            }
            match TcpStream::connect(sa) {
                Ok(stream) => {
                    s.map.insert(h, HostSocket::Stream(stream));
                    0
                }
                Err(_) => ECONNREFUSED,
            }
        },
        EBADF,
    )
}

pub fn host_sock_bind(h: i32, addr: &[u8]) -> i32 {
    let Some(sa) = decode_sockaddr(addr) else { return EINVAL };
    with(
        |s| match s.map.get_mut(&h) {
            Some(HostSocket::Fresh { bind_addr }) => {
                *bind_addr = Some(sa);
                0
            }
            _ => EBADF,
        },
        EBADF,
    )
}

pub fn host_sock_listen(h: i32, _backlog: i32) -> i32 {
    with(
        |s| {
            let addr = match s.map.get(&h) {
                Some(HostSocket::Fresh { bind_addr: Some(a) }) => *a,
                Some(HostSocket::Fresh { bind_addr: None }) => {
                    SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)
                }
                _ => return EBADF,
            };
            match TcpListener::bind(addr) {
                Ok(l) => {
                    s.map.insert(h, HostSocket::Listener(l));
                    0
                }
                Err(_) => EIO,
            }
        },
        EBADF,
    )
}

pub fn host_sock_accept(h: i32, addr_out: &mut [u8]) -> i32 {
    // NB: blocking accept holds the table borrow — acceptable for the slice.
    with(
        |s| match s.map.get(&h) {
            Some(HostSocket::Listener(l)) => match l.accept() {
                Ok((stream, peer)) => {
                    if let std::net::SocketAddr::V4(p) = peer {
                        encode_sockaddr(p, addr_out);
                    }
                    s.insert(HostSocket::Stream(stream))
                }
                Err(_) => EIO,
            },
            _ => EBADF,
        },
        EBADF,
    )
}

pub fn host_sock_sendto(h: i32, buf: &[u8], _flags: i32, _addr: &[u8]) -> i32 {
    with(
        |s| match s.map.get_mut(&h) {
            Some(HostSocket::Stream(stream)) => match stream.write(buf) {
                Ok(n) => n as i32,
                Err(_) => EIO,
            },
            Some(_) => ENOTCONN,
            None => EBADF,
        },
        EBADF,
    )
}

pub fn host_sock_recvfrom(h: i32, buf: &mut [u8], _flags: i32, _addr_out: &mut [u8]) -> i32 {
    with(
        |s| match s.map.get_mut(&h) {
            Some(HostSocket::Stream(stream)) => match stream.read(buf) {
                Ok(n) => n as i32,
                Err(_) => EIO,
            },
            Some(_) => ENOTCONN,
            None => EBADF,
        },
        EBADF,
    )
}

pub fn host_sock_setsockopt(_h: i32, _level: i32, _optname: i32, _opt: &[u8]) -> i32 {
    0 // best-effort no-op (SO_REUSEADDR, TCP_NODELAY, …)
}

pub fn host_sock_getsockname(h: i32, addr_out: &mut [u8]) -> i32 {
    with(
        |s| match s.map.get(&h) {
            Some(HostSocket::Stream(stream)) => match stream.local_addr() {
                Ok(std::net::SocketAddr::V4(a)) => { encode_sockaddr(a, addr_out); 0 }
                _ => EIO,
            },
            Some(HostSocket::Listener(l)) => match l.local_addr() {
                Ok(std::net::SocketAddr::V4(a)) => { encode_sockaddr(a, addr_out); 0 }
                _ => EIO,
            },
            _ => EBADF,
        },
        EBADF,
    )
}

pub fn host_sock_getpeername(h: i32, addr_out: &mut [u8]) -> i32 {
    with(
        |s| match s.map.get(&h) {
            Some(HostSocket::Stream(stream)) => match stream.peer_addr() {
                Ok(std::net::SocketAddr::V4(a)) => { encode_sockaddr(a, addr_out); 0 }
                _ => EIO,
            },
            _ => ENOTCONN,
        },
        EBADF,
    )
}

pub fn host_sock_shutdown(h: i32, how: i32) -> i32 {
    let how = match how {
        0 => Shutdown::Read,
        1 => Shutdown::Write,
        _ => Shutdown::Both,
    };
    with(
        |s| match s.map.get(&h) {
            Some(HostSocket::Stream(stream)) => {
                let _ = stream.shutdown(how);
                0
            }
            _ => EBADF,
        },
        EBADF,
    )
}

pub fn host_sock_close(h: i32) {
    with(|s| { s.map.remove(&h); }, ());
}
