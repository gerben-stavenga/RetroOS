//! Linux socket ABI translation. Socket ownership and protocol processing live
//! in kernel::net so OS/2 sockets and Winsock can use that same implementation.
use crate::kernel::net::{self, local, Endpoint, Error, Shutdown, SocketKind, SocketOption};
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
pub fn socket(domain: i32, ty: i32, protocol: i32, pid: i32) -> i32 {
    if domain == 1 {
        if ty & 0xf != 1 { return -94; }
        if protocol != 0 { return -93; }
        if ty & !(0xf | 0x800 | 0x80000) != 0 { return -22; }
        return result(local::socket(ty & 0x800 != 0, credentials(pid)));
    }
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
pub fn connect(h: i32, addr: &[u8], pid: i32, linux: &super::LinuxState) -> i32 {
    if local::is_local(h) {
        let body = match local_address(addr) { Ok(body) => body, Err(e) => return e };
        if body[0] == 0 { return result(local::connect(h, &(0, body.to_vec()), credentials(pid))); }
        let mut path = [0; crate::kernel::vfs::PATH_KEY_MAX];
        return local_result(crate::kernel::vfs::connect_local_socket(h,
            super::resolve_path(body, linux.cwd_str(), &mut path), credentials(pid)));
    }
    match decode(addr) {
        Ok(e) => result(net::connect(h, e)),
        Err(e) => e,
    }
}
pub fn bind(h: i32, addr: &[u8], linux: &super::LinuxState) -> i32 {
    if local::is_local(h) {
        let body = match local_address(addr) { Ok(body) => body, Err(e) => return e };
        let mode = (0o777 & !linux.creation_mask) as u16;
        if body[0] == 0 { return result(local::bind(h, (0, body.to_vec()), body.to_vec(), mode)); }
        let mut path = [0; crate::kernel::vfs::PATH_KEY_MAX];
        let mut name = body.to_vec(); name.push(0);
        return local_result(crate::kernel::vfs::bind_local_socket(h,
            super::resolve_path(body, linux.cwd_str(), &mut path), name, mode));
    }
    match decode(addr) {
        Ok(e) => result(net::bind(h, e)),
        Err(e) => e,
    }
}
pub fn listen(h: i32, backlog: i32, pid: i32) -> i32 {
    if local::is_local(h) { return result(local::listen(h, backlog, credentials(pid))); }
    result(net::listen(h, backlog))
}
pub fn accept(h: i32, addr: &mut [u8]) -> i32 {
    if local::is_local(h) {
        let accepted = result(local::accept(h));
        if accepted >= 0 { let _ = name(accepted, addr, true); }
        return accepted;
    }
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
    if local::is_local(h) {
        if !addr.is_empty() { return -106; }
        return result(local::send(h, buf));
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
    if local::is_local(h) {
        let r = result(local::receive(h, buf, flags & 2 != 0));
        if r >= 0 { let _ = name(h, addr, true); }
        return r;
    }
    let mut peer = None;
    let r = result(net::recvfrom(h, buf, flags & 2 != 0, &mut peer));
    if r >= 0 {
        encode(peer, addr);
    }
    r
}
pub fn setsockopt(h: i32, level: i32, name: i32, value: &[u8]) -> i32 {
    if local::is_local(h) { return -92; }
    if value.len() < 4 {
        return -22;
    }
    let enabled = value[..4] != [0; 4];
    let option = match (level, name) {
        (1, 2) => SocketOption::ReuseAddress(enabled),
        (6, 1) => SocketOption::TcpNoDelay(enabled),
        (0, 11) => SocketOption::ReceiveErrors(enabled), // IP_RECVERR, required by glibc DNS
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
    if local::is_local(h) {
        let body = match local::name(h, peer) { Ok(name) => name, Err(e) => return -errno(e) };
        for (to, from) in addr.iter_mut().zip([1,0].iter().chain(body.iter())) { *to = *from; }
        return (body.len() + 2) as i32;
    }
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
    if local::is_local(h) {
        if !(0..=2).contains(&how) { return -22; }
        return result(local::shutdown(h, how != 1, how != 0));
    }
    let how = match how {
        0 => Shutdown::Read,
        1 => Shutdown::Write,
        2 => Shutdown::Both,
        _ => return -22,
    };
    result(net::shutdown(h, how))
}
pub fn receive_errors(h: i32) -> i32 {
    net::receive_errors(h)
        .map(i32::from)
        .unwrap_or_else(|e| -errno(e))
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

fn credentials(pid: i32) -> local::Credentials {
    let (uid, gid) = super::environment::identity();
    local::Credentials { pid, uid, gid }
}
fn local_result(value: Result<i32, crate::kernel::vfs::LocalSocketError>) -> i32 {
    value.unwrap_or_else(|error| match error {
        crate::kernel::vfs::LocalSocketError::Namespace(e) => e,
        crate::kernel::vfs::LocalSocketError::Transport(e) => -errno(e),
    })
}
fn local_address(address: &[u8]) -> Result<&[u8], i32> {
    if address.len() < 3 || address.len() > 110 || address[..2] != [1,0] { return Err(-22); }
    let body = &address[2..];
    if body[0] == 0 { return Ok(body); }
    let end = body.iter().position(|b| *b == 0).unwrap_or(body.len());
    if end == 0 { Err(-22) } else { Ok(&body[..end]) }
}
pub fn address_length(h: i32, peer: bool) -> usize {
    if local::is_local(h) { local::name(h, peer).map_or(2, |name| name.len() + 2) } else { 16 }
}
pub fn local_option(h: i32, level: i32, option: i32) -> Result<alloc::vec::Vec<u8>, i32> {
    if level != 1 { return Err(-92); }
    let value: i32 = match option {
        3 | 39 => 1, 4 | 38 => 0, 7 | 8 => 65536,
        17 => {
            let peer = local::credentials(h).map_err(|e| -errno(e))?;
            let mut bytes = alloc::vec::Vec::with_capacity(12);
            bytes.extend_from_slice(&peer.pid.to_le_bytes()); bytes.extend_from_slice(&peer.uid.to_le_bytes());
            bytes.extend_from_slice(&peer.gid.to_le_bytes()); return Ok(bytes);
        },
        _ => return Err(-92),
    };
    local::available(h).map_err(|e| -errno(e))?;
    Ok(value.to_le_bytes().to_vec())
}
