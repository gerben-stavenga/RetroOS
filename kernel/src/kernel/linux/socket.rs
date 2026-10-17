//! Linux socket ABI translation. Socket ownership and protocol processing live
//! in kernel::net so OS/2 sockets and Winsock can use that same implementation.
use crate::kernel::net::{self, Endpoint, Error, Shutdown, SocketKind, SocketOption};
pub use crate::kernel::net::{add_ref, close, native_backend, nonblocking, set_nonblocking};

pub fn errno(e: Error) -> i32 {
    match e {
        Error::Unavailable => 38,
        Error::InvalidHandle => 9,
        Error::InvalidArgument => 22,
        Error::WouldBlock => 11,
        Error::TooManySockets => 24,
        Error::AddressInUse => 98,
        Error::AddressUnavailable => 99,
        Error::NotConnected => 107,
        Error::AlreadyConnected => 106,
        Error::ConnectionRefused => 111,
        Error::AlreadyConnecting => 114,
        Error::InProgress => 115,
        Error::NetworkUnreachable => 101,
        Error::BrokenPipe => 32,
        Error::MessageTooLarge => 90,
        Error::DestinationRequired => 89,
        Error::Unsupported => 95,
        Error::UnsupportedOption => 92,
        Error::Io => 5,
    }
}
fn result(r: net::Result<i32>) -> i32 {
    r.unwrap_or_else(|e| -errno(e))
}
fn decode(a: &[u8]) -> Result<Endpoint, i32> {
    if a.len() < 16 {
        return Err(-22);
    }
    if a[..2] != [2, 0] {
        return Err(-97);
    }
    Ok(Endpoint {
        address: [a[4], a[5], a[6], a[7]],
        port: u16::from_be_bytes([a[2], a[3]]),
    })
}
fn encode(e: Option<Endpoint>, out: &mut [u8]) {
    let Some(e) = e else { return };
    let mut a = [0; 16];
    a[0] = 2;
    a[2..4].copy_from_slice(&e.port.to_be_bytes());
    a[4..8].copy_from_slice(&e.address);
    let count = out.len().min(a.len());
    out[..count].copy_from_slice(&a[..count]);
}
pub fn socket(domain: i32, ty: i32, protocol: i32) -> i32 {
    // Preserve socket()'s existing no-device failure.
    if !net::socket_backend_installed() {
        return -38;
    }
    if domain != 2 {
        return -97;
    }
    let kind = match ty & 0xf {
        1 => SocketKind::Tcp,
        2 => SocketKind::Udp,
        _ => return -94,
    };
    if protocol != 0 && protocol != if kind == SocketKind::Tcp { 6 } else { 17 } {
        return -93;
    }
    if ty & !(0xf | 0x800 | 0x80000) != 0 {
        return -22;
    }
    result(net::socket(kind, ty & 0x800 != 0))
}
pub fn connect(h: i32, addr: &[u8]) -> i32 {
    match decode(addr) {
        Ok(e) => result(net::connect(h, e)),
        Err(e) => e,
    }
}
pub fn bind(h: i32, addr: &[u8]) -> i32 {
    match decode(addr) {
        Ok(e) => result(net::bind(h, e)),
        Err(e) => e,
    }
}
pub fn listen(h: i32, backlog: i32) -> i32 {
    result(net::listen(h, backlog))
}
pub fn accept(h: i32, addr: &mut [u8]) -> i32 {
    let mut peer = None;
    let r = result(net::accept(h, &mut peer));
    if r >= 0 {
        encode(peer, addr);
    }
    r
}
pub fn sendto(h: i32, buf: &[u8], flags: i32, addr: &[u8]) -> i32 {
    if flags & !(0x40 | 0x4000) != 0 {
        return -95;
    }
    let peer = if addr.is_empty() {
        None
    } else {
        match decode(addr) {
            Ok(e) => Some(e),
            Err(e) => return e,
        }
    };
    result(net::sendto(h, buf, peer))
}
pub fn recvfrom(h: i32, buf: &mut [u8], flags: i32, addr: &mut [u8]) -> i32 {
    if flags & !(2 | 0x40) != 0 {
        return -95;
    }
    let mut peer = None;
    let r = result(net::recvfrom(h, buf, flags & 2 != 0, &mut peer));
    if r >= 0 {
        encode(peer, addr);
    }
    r
}
pub fn setsockopt(h: i32, level: i32, name: i32, value: &[u8]) -> i32 {
    if value.len() < 4 {
        return -22;
    }
    let enabled = value[..4] != [0; 4];
    let option = match (level, name) {
        (1, 2) => SocketOption::ReuseAddress(enabled),
        (6, 1) => SocketOption::TcpNoDelay(enabled),
        _ => return -92,
    };
    result(net::setsockopt(h, option))
}
pub fn getsockname(h: i32, addr: &mut [u8]) -> i32 {
    name(h, addr, false)
}
pub fn getpeername(h: i32, addr: &mut [u8]) -> i32 {
    name(h, addr, true)
}
fn name(h: i32, addr: &mut [u8], peer: bool) -> i32 {
    let mut endpoint = None;
    let r = result(if peer {
        net::getpeername(h, &mut endpoint)
    } else {
        net::getsockname(h, &mut endpoint)
    });
    if r >= 0 {
        encode(endpoint, addr);
    }
    r
}
pub fn shutdown(h: i32, how: i32) -> i32 {
    let how = match how {
        0 => Shutdown::Read,
        1 => Shutdown::Write,
        2 => Shutdown::Both,
        _ => return -22,
    };
    result(net::shutdown(h, how))
}
pub fn socket_error(h: i32) -> i32 {
    match net::socket_error(h) {
        Ok(e) => e.map_or(0, errno),
        Err(e) => -errno(e),
    }
}
pub fn readiness(h: i32, events: i16) -> i16 {
    let r = net::readiness(h);
    ((if r.readable { 1 } else { 0 }) | (if r.writable { 4 } else { 0 })) & events
        | (if r.error { 8 } else { 0 })
        | (if r.closed { 16 } else { 0 })
        | (if r.invalid { 32 } else { 0 })
}
