//! Hosted implementation of the common RetroOS socket contract.
//! Guest socket layouts and error numbers are translated by personalities;
//! this backend receives typed endpoints and returns common socket errors.
//! Hosted TCP operations retain their existing synchronous host I/O behavior.

use arch_abi::net::{Endpoint, Error, Result, Shutdown, SocketKind, SocketOption};
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};

enum HostSocket {
    /// Created but not yet connected/bound.
    Fresh {
        bind_addr: Option<SocketAddrV4>,
        nonblocking: bool,
    },
    Stream(TcpStream),
    Listener(TcpListener),
}

struct Sockets {
    map: HashMap<i32, HostSocket>,
    next: i32,
}

impl Sockets {
    fn insert(&mut self, s: HostSocket) -> Result<i32> {
        let h = self.next;
        self.next += 1;
        self.map.insert(h, s);
        Ok(h)
    }
}

thread_local! {
    /// The native socket table for the injected backend. Set by
    /// `install_native_sockets` on the CPU/kernel thread before startup.
    static NATIVE_SOCKETS: RefCell<Option<Sockets>> = const { RefCell::new(None) };
}

/// Enable the native socket backend on this (CPU/kernel) thread.
pub fn install_native_sockets() {
    NATIVE_SOCKETS.with(|s| {
        *s.borrow_mut() = Some(Sockets {
            map: HashMap::new(),
            next: 1,
        })
    });
}

fn with<R>(f: impl FnOnce(&mut Sockets) -> R, miss: R) -> R {
    NATIVE_SOCKETS.with(|s| match s.borrow_mut().as_mut() {
        Some(sk) => f(sk),
        None => miss,
    })
}

fn address(e: Endpoint) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::from(e.address), e.port)
}
fn encode_sockaddr(sa: SocketAddrV4, out: &mut Option<Endpoint>) {
    *out = Some(Endpoint {
        address: sa.ip().octets(),
        port: sa.port(),
    });
}

pub fn host_sock_socket(kind: SocketKind, nonblocking: bool) -> Result<i32> {
    if kind != SocketKind::Tcp {
        return Err(Error::Unsupported);
    }
    with(
        |s| {
            s.insert(HostSocket::Fresh {
                bind_addr: None,
                nonblocking,
            })
        },
        Err(Error::InvalidHandle),
    )
}

pub fn host_sock_connect(h: i32, addr: Endpoint) -> Result<i32> {
    let sa = address(addr);
    with(
        |s| {
            if !matches!(s.map.get(&h), Some(HostSocket::Fresh { .. })) {
                return Err(Error::InvalidHandle);
            }
            let nonblocking = matches!(
                s.map.get(&h),
                Some(HostSocket::Fresh {
                    nonblocking: true,
                    ..
                })
            );
            let connection = if nonblocking {
                TcpStream::connect_timeout(
                    &std::net::SocketAddr::V4(sa),
                    std::time::Duration::from_secs(3),
                )
            } else {
                TcpStream::connect(sa)
            };
            match connection {
                Ok(stream) => {
                    stream.set_nonblocking(nonblocking).map_err(|_| Error::Io)?;
                    s.map.insert(h, HostSocket::Stream(stream));
                    Ok(0)
                }
                Err(_) => Err(Error::ConnectionRefused),
            }
        },
        Err(Error::InvalidHandle),
    )
}

pub fn host_sock_bind(h: i32, addr: Endpoint) -> Result<i32> {
    let sa = address(addr);
    with(
        |s| match s.map.get_mut(&h) {
            Some(HostSocket::Fresh { bind_addr, .. }) => {
                *bind_addr = Some(sa);
                Ok(0)
            }
            _ => Err(Error::InvalidHandle),
        },
        Err(Error::InvalidHandle),
    )
}

pub fn host_sock_listen(h: i32, _backlog: i32) -> Result<i32> {
    with(
        |s| {
            let addr = match s.map.get(&h) {
                Some(HostSocket::Fresh {
                    bind_addr: Some(a), ..
                }) => *a,
                Some(HostSocket::Fresh {
                    bind_addr: None, ..
                }) => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
                _ => return Err(Error::InvalidHandle),
            };
            match TcpListener::bind(addr) {
                Ok(l) => {
                    s.map.insert(h, HostSocket::Listener(l));
                    Ok(0)
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(Error::WouldBlock),
                Err(_) => Err(Error::Io),
            }
        },
        Err(Error::InvalidHandle),
    )
}

pub fn host_sock_accept(h: i32, addr_out: &mut Option<Endpoint>) -> Result<i32> {
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
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(Error::WouldBlock),
                Err(_) => Err(Error::Io),
            },
            _ => Err(Error::InvalidHandle),
        },
        Err(Error::InvalidHandle),
    )
}

pub fn host_sock_sendto(h: i32, buf: &[u8], _addr: Option<Endpoint>) -> Result<i32> {
    with(
        |s| match s.map.get_mut(&h) {
            Some(HostSocket::Stream(stream)) => match stream.write(buf) {
                Ok(n) => Ok(n as i32),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(Error::WouldBlock),
                Err(_) => Err(Error::Io),
            },
            Some(_) => Err(Error::NotConnected),
            None => Err(Error::InvalidHandle),
        },
        Err(Error::InvalidHandle),
    )
}

pub fn host_sock_recvfrom(
    h: i32,
    buf: &mut [u8],
    peek: bool,
    _addr_out: &mut Option<Endpoint>,
) -> Result<i32> {
    with(
        |s| match s.map.get_mut(&h) {
            Some(HostSocket::Stream(stream)) => match if peek {
                stream.peek(buf)
            } else {
                stream.read(buf)
            } {
                Ok(n) => Ok(n as i32),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(Error::WouldBlock),
                Err(_) => Err(Error::Io),
            },
            Some(_) => Err(Error::NotConnected),
            None => Err(Error::InvalidHandle),
        },
        Err(Error::InvalidHandle),
    )
}

pub fn host_sock_setsockopt(_h: i32, _option: SocketOption) -> Result<i32> {
    Ok(0) // best-effort no-op (SO_REUSEADDR, TCP_NODELAY, …)
}

pub fn host_sock_getsockname(h: i32, addr_out: &mut Option<Endpoint>) -> Result<i32> {
    with(
        |s| match s.map.get(&h) {
            Some(HostSocket::Stream(stream)) => match stream.local_addr() {
                Ok(std::net::SocketAddr::V4(a)) => {
                    encode_sockaddr(a, addr_out);
                    Ok(0)
                }
                _ => Err(Error::Io),
            },
            Some(HostSocket::Listener(l)) => match l.local_addr() {
                Ok(std::net::SocketAddr::V4(a)) => {
                    encode_sockaddr(a, addr_out);
                    Ok(0)
                }
                _ => Err(Error::Io),
            },
            _ => Err(Error::InvalidHandle),
        },
        Err(Error::InvalidHandle),
    )
}

pub fn host_sock_getpeername(h: i32, addr_out: &mut Option<Endpoint>) -> Result<i32> {
    with(
        |s| match s.map.get(&h) {
            Some(HostSocket::Stream(stream)) => match stream.peer_addr() {
                Ok(std::net::SocketAddr::V4(a)) => {
                    encode_sockaddr(a, addr_out);
                    Ok(0)
                }
                _ => Err(Error::Io),
            },
            _ => Err(Error::NotConnected),
        },
        Err(Error::InvalidHandle),
    )
}

pub fn host_sock_shutdown(h: i32, how: Shutdown) -> Result<i32> {
    let how = match how {
        Shutdown::Read => std::net::Shutdown::Read,
        Shutdown::Write => std::net::Shutdown::Write,
        Shutdown::Both => std::net::Shutdown::Both,
    };
    with(
        |s| match s.map.get(&h) {
            Some(HostSocket::Stream(stream)) => {
                let _ = stream.shutdown(how);
                Ok(0)
            }
            _ => Err(Error::InvalidHandle),
        },
        Err(Error::InvalidHandle),
    )
}

pub fn host_sock_close(h: i32) {
    with(
        |s| {
            s.map.remove(&h);
        },
        (),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonblocking_host_transport_reports_pending_reads() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        install_native_sockets();
        let handle = host_sock_socket(SocketKind::Tcp, true).unwrap();
        host_sock_connect(
            handle,
            Endpoint {
                address: [127, 0, 0, 1],
                port,
            },
        )
        .unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        assert_eq!(
            host_sock_recvfrom(handle, &mut [0; 1], false, &mut None),
            Err(Error::WouldBlock)
        );
        assert_eq!(host_sock_sendto(handle, b"pending", None), Ok(7));
        let mut bytes = [0; 7];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"pending");
        host_sock_close(handle);
    }

    #[test]
    fn typed_socket_api_works_without_a_linux_personality() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = [0; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"PING");
            stream.write_all(b"PONG").unwrap();
        });
        install_native_sockets();
        let socket = host_sock_socket(SocketKind::Tcp, false).unwrap();
        assert_eq!(
            host_sock_connect(
                socket,
                Endpoint {
                    address: [127, 0, 0, 1],
                    port
                }
            ),
            Ok(0)
        );
        assert_eq!(host_sock_sendto(socket, b"PING", None), Ok(4));
        let mut peer = None;
        assert_eq!(host_sock_getpeername(socket, &mut peer), Ok(0));
        assert_eq!(
            peer,
            Some(Endpoint {
                address: [127, 0, 0, 1],
                port
            })
        );
        let mut response = [0; 4];
        // TCP reads may be partial; peek must leave the returned bytes queued.
        let count = host_sock_recvfrom(socket, &mut response, true, &mut None).unwrap() as usize;
        assert!(count > 0);
        assert_eq!(&response[..count], &b"PONG"[..count]);
        let mut offset = 0;
        while offset < 4 {
            let count =
                host_sock_recvfrom(socket, &mut response[offset..], false, &mut None).unwrap();
            assert!(count > 0);
            offset += count as usize;
        }
        assert_eq!(&response, b"PONG");
        host_sock_close(socket);
        assert_eq!(
            host_sock_sendto(socket, b"x", None),
            Err(Error::InvalidHandle)
        );
        server.join().unwrap();
    }
}
