//! IPv4 socket backend. Hardware is polled by the event loop, never by IRQ
//! handlers. Each operation returns promptly; personality adapters suspend blocking
//! calls and retry them after the stack has made progress.

use super::{
    Endpoint, Error, EthernetDevice, Readiness, Shutdown, SocketHooks, SocketKind as Kind,
    SocketOption,
};
use alloc::{boxed::Box, vec, vec::Vec};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{dhcpv4, tcp, udp},
    time::{Duration, Instant},
    wire::{EthernetAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address},
};

const MAX_SOCKETS: usize = 64;
const TCP_BUFFER: usize = 16384;
const UDP_BUFFER: usize = 8192;

struct Nic(Box<dyn EthernetDevice>);
struct Receive(Vec<u8>);
struct Transmit<'a>(&'a mut dyn EthernetDevice);
impl RxToken for Receive {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl TxToken for Transmit<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = vec![0; len];
        let result = f(&mut frame);
        self.0.transmit(&frame);
        result
    }
}
impl Device for Nic {
    type RxToken<'a> = Receive;
    type TxToken<'a> = Transmit<'a>;
    fn receive(&mut self, _: Instant) -> Option<(Receive, Transmit<'_>)> {
        if !self.0.can_transmit() {
            return None;
        }
        let frame = self.0.receive()?;
        Some((Receive(frame), Transmit(&mut *self.0)))
    }
    fn transmit(&mut self, _: Instant) -> Option<Transmit<'_>> {
        self.0.can_transmit().then_some(Transmit(&mut *self.0))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1514;
        caps.max_burst_size = Some(16);
        caps
    }
}

#[derive(Clone, Copy)]
struct Entry {
    id: i32,
    handle: SocketHandle,
    kind: Kind,
    local: IpListenEndpoint,
    peer: Option<IpEndpoint>,
    connecting: bool,
    listening: bool,
    nonblocking: bool,
    read_shutdown: bool,
    receive_errors: bool,
    references: usize,
}

struct Network {
    nic: Nic,
    iface: Interface,
    sockets: SocketSet<'static>,
    dhcp: SocketHandle,
    entries: Vec<Entry>,
    next_id: i32,
    next_port: u16,
    address: Option<Ipv4Address>,
    closing: Vec<(SocketHandle, Instant)>,
}
static NETWORK: spin::Mutex<Option<Network>> = spin::Mutex::new(None);

fn now() -> Instant {
    Instant::from_millis((crate::kernel::portio::now_ns() / 1_000_000) as i64)
}
fn with<T>(f: impl FnOnce(&mut Network) -> Result<T, Error>) -> Result<T, Error> {
    let mut guard = NETWORK.lock();
    f(guard.as_mut().ok_or(Error::Unavailable)?)
}
pub fn installed() -> bool {
    NETWORK.lock().is_some()
}
pub fn socket_kind(h: i32) -> Result<Kind, Error> {
    with(|n| Ok(n.entries[n.index(h)?].kind))
}

pub fn nonblocking(h: i32) -> bool {
    with(|n| {
        n.entries
            .iter()
            .find(|e| e.id == h)
            .map_or(Ok(false), |e| Ok(e.nonblocking))
    })
    .unwrap_or(false)
}
pub(super) fn available_bytes(h: i32) -> Result<i32, Error> {
    with(|network| {
        let entry = network.entries[network.index(h)?];
        if entry.read_shutdown { return Ok(0); }
        let count = if entry.kind == Kind::Tcp {
            network.sockets.get::<tcp::Socket>(entry.handle).recv_queue()
        } else {
            let socket = network.sockets.get_mut::<udp::Socket>(entry.handle);
            if socket.can_recv() { socket.peek().map(|(bytes, _)| bytes.len()).unwrap_or(0) } else { 0 }
        };
        Ok(count.min(i32::MAX as usize) as i32)
    })
}
pub fn set_nonblocking(h: i32, value: bool) {
    with(|n| {
        if let Some(e) = n.entries.iter_mut().find(|e| e.id == h) {
            e.nonblocking = value;
        }
        Ok(0)
    })
    .ok();
}
pub fn add_ref(h: i32) {
    with(|n| {
        if let Ok(i) = n.index(h) {
            n.entries[i].references += 1;
        }
        Ok(0)
    })
    .ok();
}

pub fn install(device: Box<dyn EthernetDevice>) {
    let mac = device.mac_address();
    let mut nic = Nic(device);
    let mut config = Config::new(EthernetAddress(mac).into());
    config.random_seed = crate::kernel::portio::now_ns()
        ^ u64::from_le_bytes([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 0, 0]);
    let iface = Interface::new(config, &mut nic, now());
    let mut sockets = SocketSet::new(vec![]);
    let dhcp = sockets.add(dhcpv4::Socket::new());
    *NETWORK.lock() = Some(Network {
        nic,
        iface,
        sockets,
        dhcp,
        entries: Vec::new(),
        next_id: 1,
        next_port: 49152,
        address: None,
        closing: Vec::new(),
    });
    super::install_socket_backend(SocketHooks {
        socket,
        connect,
        bind,
        listen,
        accept,
        sendto,
        recvfrom,
        setsockopt,
        getsockname,
        getpeername,
        shutdown,
        close,
    });
    crate::compact_println!("Network: IPv4 DHCP started");
    poll();
}

pub(super) fn wait_for_initial_lease() {
    // Give the initial lease a short startup window so programs that resolve
    // names immediately can read DHCP's resolv.conf. Renewals and slower DHCP
    // servers continue in the ordinary event-loop poll path.
    // Never call this during Wi-Fi attachment: its adapter queues packets for
    // wifi::poll(), which cannot progress while this stack-only loop spins.
    let deadline = now() + Duration::from_secs(3);
    while now() < deadline && !with(|n| Ok(n.address.is_some())).unwrap_or(false) {
        poll();
        core::hint::spin_loop();
    }
}

pub fn poll() {
    with(|n| {
        let timestamp = now();
        // Bound ingress work so a busy link cannot starve the guest or audio.
        for _ in 0..64 {
            if n.iface
                .poll_ingress_single(timestamp, &mut n.nic, &mut n.sockets)
                == smoltcp::iface::PollIngressSingleResult::None
            {
                break;
            }
        }
        n.iface.poll_egress(timestamp, &mut n.nic, &mut n.sockets);
        for entry in &mut n.entries {
            if entry.kind == Kind::Tcp {
                let socket = n.sockets.get_mut::<tcp::Socket>(entry.handle);
                if matches!(
                    socket.state(),
                    tcp::State::Established | tcp::State::CloseWait
                ) {
                    socket.set_timeout(None);
                    if entry.nonblocking {
                        entry.connecting = false;
                    }
                }
            }
        }
        let mut i = 0;
        while i < n.closing.len() {
            let (handle, deadline) = n.closing[i];
            if !n.sockets.get::<tcp::Socket>(handle).is_open() || timestamp >= deadline {
                n.sockets.remove(handle);
                n.closing.swap_remove(i);
            } else {
                i += 1;
            }
        }
        match n.sockets.get_mut::<dhcpv4::Socket>(n.dhcp).poll() {
            Some(dhcpv4::Event::Configured(config)) => {
                n.address = Some(config.address.address());
                n.iface.update_ip_addrs(|addrs| {
                    addrs.clear();
                    addrs.push(IpCidr::Ipv4(config.address)).unwrap();
                });
                n.iface.routes_mut().remove_default_ipv4_route();
                if let Some(router) = config.router {
                    let _ = n.iface.routes_mut().add_default_ipv4_route(router);
                }
                let a = config.address.address().octets();
                crate::compact_println!(
                    "Network: DHCP IPv4 {}.{}.{}.{}/{}",
                    a[0],
                    a[1],
                    a[2],
                    a[3],
                    config.address.prefix_len()
                );
                super::config::update(&config.dns_servers);
                for server in config.dns_servers {
                    let d = server.octets();
                    crate::compact_println!("Network: DNS {}.{}.{}.{}", d[0], d[1], d[2], d[3]);
                }
            }
            Some(dhcpv4::Event::Deconfigured) => {
                let had_lease = n.address.take().is_some();
                n.iface.update_ip_addrs(|a| a.clear());
                n.iface.routes_mut().remove_default_ipv4_route();
                super::config::update(&[]);
                if had_lease {
                    crate::compact_println!("Network: DHCP lease lost");
                }
            }
            None => {}
        }
        Ok(0)
    })
    .ok();
}

fn tcp_socket() -> tcp::Socket<'static> {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
        tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
    );
    socket.set_timeout(Some(Duration::from_secs(30)));
    socket
}

impl Network {
    fn index(&self, id: i32) -> Result<usize, Error> {
        self.entries
            .iter()
            .position(|e| e.id == id)
            .ok_or(Error::InvalidHandle)
    }
    fn insert(&mut self, mut e: Entry) -> Result<i32, Error> {
        let Some(next) = self.next_id.checked_add(1) else {
            return Err(Error::TooManySockets);
        };
        e.id = self.next_id;
        self.next_id = next;
        self.entries.push(e);
        Ok(e.id)
    }
    fn port(&mut self, kind: Kind) -> Option<u16> {
        for _ in 0..16384 {
            let p = self.next_port;
            self.next_port = if p == 65535 { 49152 } else { p + 1 };
            if !self
                .entries
                .iter()
                .any(|e| e.kind == kind && e.local.port == p)
            {
                return Some(p);
            }
        }
        None
    }
    fn udp_bind(&mut self, i: usize) -> Result<(), Error> {
        if self
            .sockets
            .get::<udp::Socket>(self.entries[i].handle)
            .is_open()
        {
            return Ok(());
        }
        if self.entries[i].local.port == 0 {
            self.entries[i].local.port = self.port(Kind::Udp).ok_or(Error::AddressInUse)?;
        }
        self.sockets
            .get_mut::<udp::Socket>(self.entries[i].handle)
            .bind(self.entries[i].local)
            .map_err(|_| Error::AddressInUse)
    }
}

fn endpoint(e: Endpoint) -> IpEndpoint {
    IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::from(e.address)), e.port)
}
fn encode(e: IpEndpoint, out: &mut Option<Endpoint>) {
    let IpAddress::Ipv4(address) = e.addr;
    *out = Some(Endpoint {
        address: address.octets(),
        port: e.port,
    });
}

fn socket(kind: Kind, nonblocking: bool) -> Result<i32, Error> {
    with(|n| {
        if n.entries.len() + n.closing.len() >= MAX_SOCKETS {
            return Err(Error::TooManySockets);
        }
        let handle = match kind {
            Kind::Tcp => n.sockets.add(tcp_socket()),
            Kind::Udp => n.sockets.add(udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; UDP_BUFFER]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; UDP_BUFFER]),
            )),
        };
        n.insert(Entry {
            id: 0,
            handle,
            kind,
            local: IpListenEndpoint {
                addr: None,
                port: 0,
            },
            peer: None,
            connecting: false,
            listening: false,
            nonblocking,
            read_shutdown: false,
            receive_errors: false,
            references: 1,
        })
    })
}

fn bind(h: i32, addr: Endpoint) -> Result<i32, Error> {
    let endpoint = endpoint(addr);
    with(|n| {
        let i = n.index(h)?;
        let e = n.entries[i];
        if e.local.port != 0 || e.peer.is_some() || e.listening {
            return Err(Error::InvalidArgument);
        }
        let local = IpListenEndpoint {
            addr: (!endpoint.addr.is_unspecified()).then_some(endpoint.addr),
            port: endpoint.port,
        };
        if local.addr.is_some() && local.addr != n.address.map(IpAddress::Ipv4) {
            return Err(Error::AddressUnavailable);
        }
        if local.port != 0
            && n.entries
                .iter()
                .any(|s| s.id != h && s.kind == e.kind && s.local.port == local.port)
        {
            return Err(Error::AddressInUse);
        }
        n.entries[i].local = local;
        if e.kind == Kind::Udp {
            n.udp_bind(i).map(|_| 0)
        } else {
            Ok(0)
        }
    })
}

fn connect(h: i32, addr: Endpoint) -> Result<i32, Error> {
    let peer = endpoint(addr);
    if peer.port == 0 || peer.addr.is_unspecified() {
        return Err(Error::InvalidArgument);
    }
    with(|n| {
        let i = n.index(h)?;
        let e = n.entries[i];
        if n.address.is_none() {
            return Err(Error::WouldBlock);
        }
        if e.kind == Kind::Udp {
            n.udp_bind(i)?;
            n.entries[i].peer = Some(peer);
            return Ok(0);
        }
        if e.listening {
            return Err(Error::InvalidArgument);
        }
        let state = n.sockets.get::<tcp::Socket>(e.handle).state();
        if e.connecting {
            return match state {
                tcp::State::Established | tcp::State::CloseWait => {
                    n.entries[i].connecting = false;
                    Ok(0)
                }
                tcp::State::Closed => Err(Error::ConnectionRefused),
                _ => {
                    if e.nonblocking {
                        Err(Error::AlreadyConnecting)
                    } else {
                        Err(Error::WouldBlock)
                    }
                }
            };
        }
        if state != tcp::State::Closed {
            return Err(Error::AlreadyConnected);
        }
        if n.entries[i].local.port == 0 {
            n.entries[i].local.port = match n.port(Kind::Tcp) {
                Some(p) => p,
                None => return Err(Error::AddressInUse),
            };
        }
        let local = n.entries[i].local;
        if n.sockets
            .get_mut::<tcp::Socket>(e.handle)
            .connect(n.iface.context(), peer, local)
            .is_err()
        {
            return Err(Error::NetworkUnreachable);
        }
        n.entries[i].peer = Some(peer);
        n.entries[i].connecting = true;
        if e.nonblocking {
            Err(Error::InProgress)
        } else {
            Err(Error::WouldBlock)
        }
    })
}

fn listen(h: i32, _: i32) -> Result<i32, Error> {
    with(|n| {
        let i = n.index(h)?;
        if n.entries[i].kind != Kind::Tcp {
            return Err(Error::Unsupported);
        }
        if n.entries[i].listening {
            return Ok(0);
        }
        if n.entries[i].local.port == 0 {
            n.entries[i].local.port = match n.port(Kind::Tcp) {
                Some(p) => p,
                None => return Err(Error::AddressInUse),
            };
        }
        let e = n.entries[i];
        if n.sockets
            .get_mut::<tcp::Socket>(e.handle)
            .listen(e.local)
            .is_err()
        {
            return Err(Error::InvalidArgument);
        }
        n.entries[i].listening = true;
        Ok(0)
    })
}
fn accept(h: i32, addr: &mut Option<Endpoint>) -> Result<i32, Error> {
    with(|n| {
        let i = n.index(h)?;
        let e = n.entries[i];
        if e.kind != Kind::Tcp || !e.listening {
            return Err(Error::InvalidArgument);
        }
        if n.entries.len() + n.closing.len() >= MAX_SOCKETS {
            return Err(Error::TooManySockets);
        }
        let old = n.sockets.get::<tcp::Socket>(e.handle);
        if !matches!(old.state(), tcp::State::Established | tcp::State::CloseWait) {
            return Err(Error::WouldBlock);
        }
        let peer = old.remote_endpoint().unwrap();
        let mut replacement = tcp_socket();
        if replacement.listen(e.local).is_err() {
            return Err(Error::InvalidArgument);
        }
        let new_handle = n.sockets.add(replacement);
        n.entries[i].handle = new_handle;
        encode(peer, addr);
        n.insert(Entry {
            id: 0,
            peer: Some(peer),
            listening: false,
            nonblocking: false,
            references: 1,
            ..e
        })
    })
}

fn sendto(h: i32, buf: &[u8], addr: Option<Endpoint>) -> Result<i32, Error> {
    with(|n| {
        let i = n.index(h)?;
        let e = n.entries[i];
        if n.address.is_none() {
            return Err(Error::WouldBlock);
        }
        if e.kind == Kind::Tcp {
            let s = n.sockets.get_mut::<tcp::Socket>(e.handle);
            if !s.may_send() {
                return Err(if e.peer.is_some() {
                    Error::BrokenPipe
                } else {
                    Error::NotConnected
                });
            }
            if buf.is_empty() {
                return Ok(0);
            }
            if !s.can_send() {
                return Err(Error::WouldBlock);
            }
            return s
                .send_slice(buf)
                .map(|n| n as i32)
                .map_err(|_| Error::BrokenPipe);
        }
        // IP fragmentation is not enabled; never silently drop oversized UDP.
        if buf.len() > 1472 {
            return Err(Error::MessageTooLarge);
        }
        let peer = match addr.map(endpoint).or(e.peer) {
            Some(p) => p,
            None => return Err(Error::DestinationRequired),
        };
        if peer.port == 0 || peer.addr.is_unspecified() {
            return Err(Error::InvalidArgument);
        }
        n.udp_bind(i)?;
        let s = n.sockets.get_mut::<udp::Socket>(e.handle);
        if !s.can_send() {
            return Err(Error::WouldBlock);
        }
        s.send_slice(buf, peer)
            .map(|_| buf.len() as i32)
            .map_err(|_| Error::WouldBlock)
    })
}
fn recvfrom(h: i32, buf: &mut [u8], peek: bool, addr: &mut Option<Endpoint>) -> Result<i32, Error> {
    with(|n| {
        let i = n.index(h)?;
        let e = n.entries[i];
        if e.read_shutdown {
            return Ok(0);
        }
        if e.kind == Kind::Tcp {
            let s = n.sockets.get_mut::<tcp::Socket>(e.handle);
            if e.peer.is_none() {
                return Err(Error::NotConnected);
            }
            if buf.is_empty() {
                return Ok(0);
            }
            if !s.can_recv() {
                return if s.may_recv()
                    || matches!(s.state(), tcp::State::SynSent | tcp::State::SynReceived)
                {
                    Err(Error::WouldBlock)
                } else {
                    Ok(0)
                };
            }
            if let Some(peer) = s.remote_endpoint() {
                encode(peer, addr);
            }
            return if peek {
                s.peek_slice(buf)
            } else {
                s.recv_slice(buf)
            }
            .map(|n| n as i32)
            .map_err(|_| Error::NotConnected);
        }
        n.udp_bind(i)?;
        let s = n.sockets.get_mut::<udp::Socket>(e.handle);
        if !s.can_recv() {
            return Err(Error::WouldBlock);
        }
        // Peek first to filter connected UDP peers and support peeking.
        for _ in 0..16 {
            let Ok((data, meta)) = s.peek() else {
                return Err(Error::WouldBlock);
            };
            if e.peer.is_some_and(|peer| peer != meta.endpoint) {
                let _ = s.recv();
                continue;
            }
            let count = buf.len().min(data.len());
            buf[..count].copy_from_slice(&data[..count]);
            encode(meta.endpoint, addr);
            if !peek {
                let _ = s.recv();
            }
            return Ok(count as i32);
        }
        Err(Error::WouldBlock)
    })
}

fn setsockopt(h: i32, option: SocketOption) -> Result<i32, Error> {
    with(|n| {
        let i = n.index(h)?;
        match option {
            // No TIME_WAIT port retention in this implementation.
            SocketOption::ReuseAddress(_) => Ok(0),
            // The transport currently delivers no auxiliary ICMP records;
            // retain registration so UDP clients can request them without
            // losing ordinary send/receive and timeout behavior.
            SocketOption::ReceiveErrors(value) if n.entries[i].kind == Kind::Udp => {
                n.entries[i].receive_errors = value;
                Ok(0)
            }
            SocketOption::TcpNoDelay(value) if n.entries[i].kind == Kind::Tcp => {
                n.sockets
                    .get_mut::<tcp::Socket>(n.entries[i].handle)
                    .set_nagle_enabled(!value);
                Ok(0)
            }
            _ => Err(Error::UnsupportedOption),
        }
    })
}
pub(super) fn receive_errors(h: i32) -> Result<bool, Error> {
    with(|n| {
        let i = n.index(h)?;
        if n.entries[i].kind != Kind::Udp {
            return Err(Error::UnsupportedOption);
        }
        Ok(n.entries[i].receive_errors)
    })
}
fn getsockname(h: i32, addr: &mut Option<Endpoint>) -> Result<i32, Error> {
    with(|n| {
        let i = n.index(h)?;
        let e = n.entries[i];
        let endpoint = if e.kind == Kind::Tcp {
            n.sockets.get::<tcp::Socket>(e.handle).local_endpoint()
        } else {
            None
        };
        encode(
            endpoint.unwrap_or(IpEndpoint::new(
                e.local
                    .addr
                    .unwrap_or(IpAddress::Ipv4(Ipv4Address::UNSPECIFIED)),
                e.local.port,
            )),
            addr,
        );
        Ok(0)
    })
}
fn getpeername(h: i32, addr: &mut Option<Endpoint>) -> Result<i32, Error> {
    with(|n| {
        let i = n.index(h)?;
        let e = n.entries[i];
        if e.kind == Kind::Tcp
            && !matches!(
                n.sockets.get::<tcp::Socket>(e.handle).state(),
                tcp::State::Established
                    | tcp::State::CloseWait
                    | tcp::State::FinWait1
                    | tcp::State::FinWait2
            )
        {
            return Err(Error::NotConnected);
        }
        if let Some(peer) = n.entries[i].peer {
            encode(peer, addr);
            Ok(0)
        } else {
            Err(Error::NotConnected)
        }
    })
}
fn shutdown(h: i32, how: Shutdown) -> Result<i32, Error> {
    with(|n| {
        let i = n.index(h)?;
        let e = n.entries[i];
        if e.peer.is_none() {
            return Err(Error::NotConnected);
        }
        if how != Shutdown::Write {
            n.entries[i].read_shutdown = true;
        }
        if how != Shutdown::Read && e.kind == Kind::Tcp {
            n.sockets.get_mut::<tcp::Socket>(e.handle).close();
        }
        Ok(0)
    })
}
fn close(h: i32) {
    with(|n| {
        if let Ok(i) = n.index(h) {
            if n.entries[i].references > 1 {
                n.entries[i].references -= 1;
                return Ok(0);
            }
            let e = n.entries.remove(i);
            if e.kind == Kind::Tcp {
                // Keep queued data and FIN alive after the last fd closes.
                n.sockets.get_mut::<tcp::Socket>(e.handle).close();
                n.iface.poll_egress(now(), &mut n.nic, &mut n.sockets);
                if n.sockets.get::<tcp::Socket>(e.handle).is_open() {
                    n.closing.push((e.handle, now() + Duration::from_secs(30)));
                    return Ok(0);
                }
            }
            n.sockets.remove(e.handle);
        }
        Ok(0)
    })
    .ok();
}
pub fn readiness(h: i32) -> Readiness {
    with(|n| {
        let Ok(i) = n.index(h) else {
            return Ok(Readiness {
                invalid: true,
                ..Readiness::default()
            });
        };
        let e = n.entries[i];
        let mut ready = Readiness::default();
        if e.kind == Kind::Udp {
            let s = n.sockets.get::<udp::Socket>(e.handle);
            ready.readable = s.can_recv();
            ready.writable = s.can_send();
        } else {
            let s = n.sockets.get::<tcp::Socket>(e.handle);
            ready.error = e.connecting && s.state() == tcp::State::Closed;
            if e.listening {
                ready.readable =
                    matches!(s.state(), tcp::State::Established | tcp::State::CloseWait);
            } else {
                ready.readable =
                    s.can_recv() || (e.peer.is_some() && !s.may_recv() && !e.connecting);
                ready.writable = s.can_send();
                ready.closed = e.peer.is_some() && !s.is_open() && !e.connecting;
            }
        }
        Ok(ready)
    })
    .unwrap_or(Readiness {
        invalid: true,
        ..Readiness::default()
    })
}

pub fn socket_error(h: i32) -> Result<Option<Error>, Error> {
    with(|n| {
        let i = n.index(h)?;
        let e = n.entries[i];
        Ok((e.kind == Kind::Tcp
            && e.connecting
            && n.sockets.get::<tcp::Socket>(e.handle).state() == tcp::State::Closed)
            .then_some(Error::ConnectionRefused))
    })
}

pub(super) fn lan_identity() -> Option<([u8; 4], [u8; 6])> {
    let guard = NETWORK.lock();
    let n = guard.as_ref()?;
    Some((n.address?.octets(), n.nic.0.mac_address()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DeferredAdapter { polls: usize }
    impl EthernetDevice for DeferredAdapter {
        fn mac_address(&self) -> [u8; 6] { [2, 0, 0, 0, 0, 1] }
        fn receive(&mut self) -> Option<Vec<u8>> { None }
        fn can_transmit(&mut self) -> bool {
            self.polls += 1;
            // Like Wi-Fi, this adapter cannot deliver a DHCP response until
            // the outer event loop gets control back. Fail boundedly if
            // installation starts spinning for a lease again.
            assert!(self.polls <= 32, "network installation waited for DHCP");
            true
        }
        fn transmit(&mut self, _: &[u8]) -> bool { true }
    }

    #[test]
    fn attachment_returns_before_a_deferred_adapter_has_a_lease() {
        install(Box::new(DeferredAdapter { polls: 0 }));
        let network = NETWORK.lock().take().unwrap();
        assert!(network.address.is_none());
        // This is the only unit test which installs the native socket backend.
        unsafe { super::super::SOCKET_BACKEND = None; }
    }
}
