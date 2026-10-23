//! OSD LAN discovery plus DOSBox-compatible IPXNET over UDP.
//! The optional two-machine serial cable uses an ordered TCP stream.
use super::{Endpoint, Error, SocketKind, SocketOption};
use alloc::{collections::VecDeque, format, string::String, vec::Vec};
use spin::Mutex;

const PORT: u16 = 1213;
const SERIAL_PORT: u16 = 1214;
const HEADER: usize = 30;
mod ipx_tunnel;
use ipx_tunnel::MAX_PACKET;
const MAX_PEERS: usize = 16;
const QUEUE: usize = 4096;
const BROADCAST: [u8; 6] = [255; 6];
#[derive(Clone, Copy)]
struct Peer {
    mac: [u8; 6],
    endpoint: Endpoint,
    room: u64,
    cable: [u8; 6],
    seen: u64,
}
#[derive(Clone, Copy)]
pub(crate) struct Session {
    id: u64,
    epoch: u64,
    pub address: [u8; 10],
}
struct Client {
    connection: ipx_tunnel::Connection,
    session: Session,
    packets: VecDeque<Vec<u8>>,
}
struct Lan {
    fd: Option<i32>,
    server: Option<ipx_tunnel::Server>,
    remote: Option<Endpoint>,
    hosting: bool,
    editing: bool,
    input: String,
    input_error: bool,
    scan: bool,
    identity: Option<([u8; 4], [u8; 6])>,
    room: u64,
    epoch: u64,
    sequence: u64,
    hello_at: u64,
    peers: Vec<Peer>,
    clients: Vec<Client>,
    cable: Option<[u8; 6]>,
    listener: Option<i32>,
    stream: Option<i32>,
    serial_owner: Option<u64>,
    cable_epoch: u64,
    connected: bool,
    retry_at: u64,
    connect_until: u64,
    rx: VecDeque<u8>,
    tx: VecDeque<u8>,
}
impl Lan {
    const fn new() -> Self {
        Self {
            fd: None,
            server: None,
            remote: None,
            hosting: false,
            editing: false,
            input: String::new(),
            input_error: false,
            scan: false,
            identity: None,
            room: 0,
            epoch: 0,
            sequence: 0,
            hello_at: 0,
            peers: Vec::new(),
            clients: Vec::new(),
            cable: None,
            listener: None,
            stream: None,
            serial_owner: None,
            cable_epoch: 0,
            connected: false,
            retry_at: 0,
            connect_until: 0,
            rx: VecDeque::new(),
            tx: VecDeque::new(),
        }
    }
    fn reset_stream(&mut self) {
        self.cable_epoch = self.cable_epoch.wrapping_add(1);
        if let Some(fd) = self.stream.take() {
            super::close(fd);
        }
        if self.connected {
            repaint();
        }
        self.connected = false;
        self.rx.clear();
        self.tx.clear();
        self.retry_at = now() + 500;
    }
    fn select_room(&mut self, room: u64) {
        self.reset_stream();
        // A queued TCP accept from the previous room cannot become a cable.
        if let Some(fd) = self.listener.take() {
            super::close(fd);
        }
        self.cable = None;
        self.clients.clear();
        self.server = None;
        self.remote = None;
        self.hosting = false;
        self.epoch = self.epoch.wrapping_add(1);
        self.room = room;
        self.hello_at = 0;
        crate::compact_println!("LAN: selected {:016x}", room);
    }
    fn frame(&self, kind: u8, dest: [u8; 6], payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER + payload.len());
        out.extend_from_slice(b"RLAN\x01");
        out.push(kind);
        out.extend_from_slice(&[0; 2]);
        out.extend_from_slice(&self.room.to_be_bytes());
        out.extend_from_slice(&self.identity.unwrap().1);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&dest);
        out.extend_from_slice(payload);
        out
    }
    fn deliver(&mut self, source: Option<u64>, dest: [u8; 6], payload: &[u8]) {
        for client in &mut self.clients {
            if client.session.id != 0
                && source != Some(client.session.id)
                && (dest == BROADCAST || dest == client.session.address[4..])
                && client.packets.len() < 32
            {
                client.packets.push_back(payload.to_vec());
            }
        }
    }
    fn rooms(&self) -> Vec<u64> {
        let mut rooms = Vec::new();
        for peer in &self.peers {
            if peer.room != 0
                && peer.endpoint.address == ((peer.room >> 32) as u32).to_be_bytes()
                && peer.room != self.room
                && !rooms.contains(&peer.room)
                && rooms.len() < 8
            {
                rooms.push(peer.room);
            }
        }
        rooms.sort_unstable();
        rooms
    }
    fn cable_peers(&self) -> Vec<[u8; 6]> {
        let mut peers: Vec<_> = self
            .peers
            .iter()
            .filter(|p| self.room != 0 && p.room == self.room)
            .map(|p| p.mac)
            .collect();
        peers.sort_unstable();
        peers
    }
    fn serial_poll(&mut self, time: u64) {
        let peer = self.cable.and_then(|mac| {
            self.peers
                .iter()
                .find(|p| p.mac == mac && p.room == self.room)
                .copied()
        });
        let Some(peer) = peer.filter(|p| Some(p.cable) == self.identity.map(|i| i.1)) else {
            if self.stream.is_some() {
                self.reset_stream();
            }
            return;
        };
        if self.listener.is_none() {
            self.listener = bound(SocketKind::Tcp, SERIAL_PORT).and_then(|fd| {
                if super::listen(fd, 2).is_ok() {
                    Some(fd)
                } else {
                    super::close(fd);
                    None
                }
            });
        }
        if let Some(listener) = self.listener {
            // Drain unexpected connections too; they must never become a cable.
            for _ in 0..4 {
                let mut endpoint = None;
                let Ok(fd) = super::accept(listener, &mut endpoint) else {
                    break;
                };
                if self.stream.is_none()
                    && self.identity.unwrap().1 > peer.mac
                    && endpoint.is_some_and(|e| e.address == peer.endpoint.address)
                {
                    super::set_nonblocking(fd, true);
                    let _ = super::setsockopt(fd, SocketOption::TcpNoDelay(true));
                    self.stream = Some(fd);
                    self.connected = true;
                    crate::compact_println!("LAN: null-modem connected");
                    repaint();
                } else {
                    super::close(fd);
                }
            }
        }
        if self.stream.is_none()
            && self.identity.unwrap().1 < peer.mac
            && time >= self.retry_at
            && let Ok(fd) = super::socket(SocketKind::Tcp, true)
        {
            let _ = super::setsockopt(fd, SocketOption::TcpNoDelay(true));
            match super::connect(
                fd,
                Endpoint {
                    address: peer.endpoint.address,
                    port: SERIAL_PORT,
                },
            ) {
                Ok(_) | Err(Error::InProgress) | Err(Error::WouldBlock) => {
                    self.stream = Some(fd);
                    self.connect_until = time + 3000;
                }
                Err(_) => {
                    super::close(fd);
                    self.retry_at = time + 500;
                }
            }
        }
        let Some(fd) = self.stream else { return };
        let ready = super::readiness(fd);
        if ready.error
            || ready.closed
            || ready.invalid
            || (!self.connected && time > self.connect_until)
        {
            self.reset_stream();
            return;
        }
        if ready.writable && !self.connected {
            self.connected = true;
            crate::compact_println!("LAN: null-modem connected");
            repaint();
        }
        if !self.connected {
            return;
        }
        let mut buf = [0; 512];
        for _ in 0..8 {
            let capacity = (QUEUE - self.rx.len()).min(buf.len());
            if capacity == 0 {
                break;
            }
            match super::recvfrom(fd, &mut buf[..capacity], false, &mut None) {
                Ok(0) => {
                    self.reset_stream();
                    return;
                }
                Ok(n) => self.rx.extend(&buf[..n as usize]),
                Err(Error::WouldBlock) => break,
                Err(_) => {
                    self.reset_stream();
                    return;
                }
            }
        }
        if !self.tx.is_empty() {
            let data = self.tx.make_contiguous();
            match super::sendto(fd, data, None) {
                Ok(n) => {
                    self.tx.drain(..n as usize);
                }
                Err(Error::WouldBlock) => {}
                Err(_) => self.reset_stream(),
            }
        }
    }
}
static LAN: Mutex<Lan> = Mutex::new(Lan::new());
fn now() -> u64 {
    crate::kernel::portio::now_ns() / 1_000_000
}
fn repaint() {
    crate::kernel::osd::request_repaint();
}
fn bound(kind: SocketKind, port: u16) -> Option<i32> {
    let fd = super::socket(kind, true).ok()?;
    if super::bind(
        fd,
        Endpoint {
            address: [0; 4],
            port,
        },
    )
    .is_ok()
    {
        Some(fd)
    } else {
        super::close(fd);
        None
    }
}
fn valid_frame(packet: &[u8]) -> bool {
    packet.len() >= HEADER
        && packet.len() <= HEADER + MAX_PACKET
        && &packet[..5] == b"RLAN\x01"
        && packet[6..8] == [0; 2]
        && u16::from_be_bytes([packet[22], packet[23]]) as usize == packet.len() - HEADER
        && packet[5] == 1
        && packet.len() == HEADER + 6
}
pub(crate) fn poll() {
    let mut lan = LAN.lock();
    let identity = super::stack::lan_identity();
    if identity != lan.identity {
        lan.select_room(0);
        lan.peers.clear();
        lan.identity = identity;
        if let Some(fd) = lan.fd.take() {
            super::close(fd);
        }
        if let Some(fd) = lan.listener.take() {
            super::close(fd);
        }
        repaint();
    }
    if identity.is_none() || (!lan.scan && lan.room == 0) {
        return;
    }
    if lan.fd.is_none() {
        lan.fd = bound(SocketKind::Udp, PORT);
    }
    let Some(fd) = lan.fd else { return };
    let time = now();
    let count = lan.peers.len();
    lan.peers.retain(|p| time.saturating_sub(p.seen) < 5000);
    if count != lan.peers.len() {
        repaint();
    }
    if time >= lan.hello_at {
        let packet = lan.frame(1, BROADCAST, &lan.cable.unwrap_or([0; 6]));
        let _ = super::sendto(
            fd,
            &packet,
            Some(Endpoint {
                address: [255; 4],
                port: PORT,
            }),
        );
        lan.hello_at = time + 1000;
    }
    for _ in 0..32 {
        let mut packet = [0; HEADER + MAX_PACKET + 1];
        let mut endpoint = None;
        let Ok(n) = super::recvfrom(fd, &mut packet, false, &mut endpoint) else {
            break;
        };
        let packet = &packet[..n as usize];
        let Some(endpoint) = endpoint.filter(|e| e.port == PORT) else {
            continue;
        };
        if !valid_frame(packet) {
            continue;
        }
        let mac: [u8; 6] = packet[16..22].try_into().unwrap();
        if mac == identity.unwrap().1 || mac == [0; 6] || mac[0] & 1 != 0 {
            continue;
        }
        let room = u64::from_be_bytes(packet[8..16].try_into().unwrap());
        if packet[5] == 1 {
            let peer = Peer {
                mac,
                endpoint,
                room,
                cable: packet[HEADER..].try_into().unwrap(),
                seen: time,
            };
            if let Some(p) = lan.peers.iter_mut().find(|p| p.mac == mac) {
                if p.room != room || p.cable != peer.cable {
                    repaint();
                }
                *p = peer;
            } else if lan.peers.len() < MAX_PEERS {
                lan.peers.push(peer);
                repaint();
            }
            if room == 0 && lan.room != 0 {
                let reply = lan.frame(1, BROADCAST, &lan.cable.unwrap_or([0; 6]));
                let _ = super::sendto(fd, &reply, Some(endpoint));
            }
        }
    }
    lan.ipx_poll(time);
    lan.serial_poll(time);
}
pub(crate) fn scanning(value: bool) {
    let mut lan = LAN.lock();
    lan.scan = value;
    if !value {
        lan.editing = false;
    }
    if value {
        lan.hello_at = 0;
    }
}
pub(crate) fn item_count() -> usize {
    5 + LAN.lock().rooms().len()
}
pub(crate) fn line(row: usize) -> String {
    let lan = LAN.lock();
    match row {
        0 if lan.identity.is_none() => String::from("Waiting for IPv4 network"),
        0 => {
            let mac = lan.identity.unwrap().1;
            if lan.room == 0 {
                format!("PC {:02X}{:02X}{:02X}: no LAN", mac[3], mac[4], mac[5])
            } else {
                let endpoint = lan.remote.unwrap_or(Endpoint {
                    address: lan.identity.unwrap().0,
                    port: ipx_tunnel::PORT,
                });
                let state = if lan.hosting {
                    if lan.server.is_some() {
                        "Hosting"
                    } else {
                        "Host failed"
                    }
                } else if lan.clients.iter().any(|c| c.connection.address.is_some()) {
                    "Connected"
                } else {
                    "Connecting"
                };
                format!(
                    "{} {}.{}.{}.{}:{}",
                    state,
                    endpoint.address[0],
                    endpoint.address[1],
                    endpoint.address[2],
                    endpoint.address[3],
                    endpoint.port
                )
            }
        }
        1 => String::from("Create LAN"),
        2 => format!("Leave LAN ({} peers)", lan.cable_peers().len()),
        3 => match lan.cable {
            None => String::from("COM1 cable: off"),
            Some(mac) => format!(
                "COM1: {:02X}{:02X}{:02X} {}",
                mac[3],
                mac[4],
                mac[5],
                if lan.connected {
                    "connected"
                } else {
                    "waiting"
                }
            ),
        },
        4 => {
            if lan.editing {
                format!("Server IPv4:port: {}_", lan.input)
            } else if lan.input_error {
                String::from("Invalid server; use IPv4:port")
            } else {
                String::from("Join DOSBox server...")
            }
        }
        _ => lan
            .rooms()
            .get(row - 5)
            .map(|room| format!("Join LAN {:04X}", *room as u16))
            .unwrap_or_default(),
    }
}
pub(crate) fn activate(row: usize) {
    let mut lan = LAN.lock();
    match row {
        1 if lan.identity.is_some() => {
            let ip = lan.identity.unwrap().0;
            let room = ((u32::from_be_bytes(ip) as u64) << 32) | (now() as u32 as u64).max(1);
            lan.select_room(room);
            lan.hosting = true;
            lan.ipx_poll(now());
        }
        2 => lan.select_room(0),
        3 => {
            drop(lan);
            cycle_cable(true);
            return;
        }
        4 => {
            lan.editing = true;
            lan.input.clear();
            lan.input_error = false;
        }
        5.. => {
            if let Some(room) = lan.rooms().get(row - 5).copied() {
                lan.select_room(room);
                lan.remote = Some(Endpoint {
                    address: ((room >> 32) as u32).to_be_bytes(),
                    port: ipx_tunnel::PORT,
                });
                lan.ipx_poll(now());
            }
        }
        _ => {}
    }
    repaint();
}
pub(crate) fn cycle_cable(forward: bool) {
    let mut lan = LAN.lock();
    let peers = lan.cable_peers();
    let count = peers.len() + 1;
    let current = lan
        .cable
        .and_then(|mac| peers.iter().position(|p| *p == mac))
        .map_or(0, |i| i + 1);
    let next = (current + if forward { 1 } else { count - 1 }) % count;
    lan.reset_stream();
    lan.cable = next.checked_sub(1).map(|i| peers[i]);
    lan.hello_at = 0;
    repaint();
}
pub(crate) fn attach() -> Option<Session> {
    let mut lan = LAN.lock();
    if lan.room == 0 {
        return None;
    }
    let index = lan
        .clients
        .iter()
        .position(|c| c.session.id == 0 && c.connection.address.is_some())?;
    lan.sequence = lan.sequence.wrapping_add(1).max(1);
    let session = Session {
        id: lan.sequence,
        epoch: lan.epoch,
        address: lan.clients[index].connection.address?,
    };
    lan.clients[index].session = session;
    Some(session)
}

pub(crate) fn valid(session: Session) -> bool {
    let lan = LAN.lock();
    lan.epoch == session.epoch && lan.room != 0
}
pub(crate) fn detach(session: Session) {
    // DOSBox has no unregister message. Reuse an idle connection on the next
    // DOS launch instead of exhausting the relay's registration table.
    let mut lan = LAN.lock();
    if let Some(client) = lan
        .clients
        .iter_mut()
        .find(|c| c.session.id == session.id && c.session.epoch == session.epoch)
    {
        client.session.id = 0;
        client.packets.clear();
    }
}
pub(crate) fn receive(session: Session) -> Option<Vec<u8>> {
    LAN.lock()
        .clients
        .iter_mut()
        .find(|c| c.session.id == session.id && c.session.epoch == session.epoch)?
        .packets
        .pop_front()
}
pub(crate) fn send(session: Session, dest: [u8; 6], packet: &[u8]) -> bool {
    if !ipx_tunnel::valid(packet) || packet[10..16] != dest || packet[18..28] != session.address {
        return false;
    }
    let mut lan = LAN.lock();
    if session.epoch != lan.epoch || lan.room == 0 {
        return false;
    }
    let Some(client) = lan.clients.iter().find(|c| c.session.id == session.id) else {
        return false;
    };
    if !lan.hosting {
        return client.connection.send(packet);
    }
    lan.deliver(Some(session.id), dest, packet);
    lan.server
        .as_ref()
        .is_some_and(|server| server.forward(packet))
}
pub(crate) fn serial_claim() -> Option<u64> {
    let mut lan = LAN.lock();
    if lan.serial_owner.is_some() {
        return None;
    }
    lan.sequence = lan.sequence.wrapping_add(1);
    lan.serial_owner = Some(lan.sequence);
    lan.serial_owner
}
pub(crate) fn serial_release(owner: u64) {
    let mut lan = LAN.lock();
    if lan.serial_owner == Some(owner) {
        lan.serial_owner = None;
        lan.rx.clear();
        lan.tx.clear();
    }
}
pub(crate) fn serial_receive(owner: u64) -> Option<u8> {
    let mut lan = LAN.lock();
    if lan.serial_owner != Some(owner) {
        return None;
    }
    lan.rx.pop_front()
}
pub(crate) fn serial_send(owner: u64, byte: u8) -> bool {
    let mut lan = LAN.lock();
    if lan.serial_owner != Some(owner) || !lan.connected || lan.tx.len() == QUEUE {
        return false;
    }
    lan.tx.push_back(byte);
    true
}
pub(crate) fn serial_epoch() -> u64 {
    LAN.lock().cable_epoch
}
pub(crate) fn serial_connected() -> bool {
    LAN.lock().connected
}

impl Lan {
    fn ipx_poll(&mut self, time: u64) {
        if self.room == 0 {
            return;
        }
        let Some((ip, _)) = self.identity else { return };
        if self.hosting && self.server.is_none() {
            self.server = ipx_tunnel::Server::new(ip);
            if self.server.is_some() {
                crate::compact_println!(
                    "IPXNET: hosting {}.{}.{}.{}:213",
                    ip[0],
                    ip[1],
                    ip[2],
                    ip[3]
                );
            }
        }
        if (self.server.is_some() || self.remote.is_some())
            && self.clients.len() < 16
            && !self.clients.iter().any(|c| c.session.id == 0)
            && let Some(connection) = ipx_tunnel::Connection::new(self.remote, ip)
        {
            self.clients.push(Client {
                connection,
                session: Session {
                    id: 0,
                    epoch: self.epoch,
                    address: [0; 10],
                },
                packets: VecDeque::new(),
            });
        }
        for _ in 0..32 {
            let Some(packet) = self.server.as_mut().and_then(|s| s.receive()) else {
                break;
            };
            self.server.as_ref().unwrap().forward(&packet);
            self.deliver(None, packet[10..16].try_into().unwrap(), &packet);
        }
        for client in &mut self.clients {
            for _ in 0..32 {
                let Some(packet) = client.connection.poll(time) else {
                    break;
                };
                if client.session.id != 0 && client.packets.len() < 32 {
                    client.packets.push_back(packet);
                }
            }
        }
    }
}

fn parse_server(value: &str) -> Option<Endpoint> {
    let (ip, port) = value.split_once(':').map_or((value, "213"), |v| v);
    let port = port.parse::<u16>().ok().filter(|p| *p != 0)?;
    let mut address = [0; 4];
    let mut parts = ip.split('.');
    for byte in &mut address {
        *byte = parts.next()?.parse().ok()?;
    }
    if parts.next().is_some() || address == [0; 4] || address[0] >= 224 {
        return None;
    }
    Some(Endpoint { address, port })
}

/// Numeric IPv4:port editor; consumes keys only while the server field is open.
pub(crate) fn key(sc: u8) -> bool {
    let mut lan = LAN.lock();
    if !lan.editing {
        return false;
    }
    match sc {
        0x01 | 0x58 => lan.editing = false,
        0x0e => {
            lan.input.pop();
        }
        0x1c => {
            if let Some(server) = parse_server(&lan.input) {
                let room = ((u32::from_be_bytes(server.address) as u64) << 32) | server.port as u64;
                lan.select_room(room);
                lan.remote = Some(server);
                lan.ipx_poll(now());
                lan.editing = false;
            } else {
                lan.input_error = true;
                lan.editing = false;
            }
        }
        _ => {
            let byte = match sc {
                0x02..=0x0a => Some(b'1' + sc - 2),
                0x0b => Some(b'0'),
                0x34 => Some(b'.'),
                0x27 => Some(b':'),
                _ => None,
            };
            if let Some(byte) = byte
                && lan.input.len() < 21
            {
                lan.input.push(byte as char);
            }
        }
    }
    repaint();
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovery_does_not_accept_old_ipx_frames() {
        let mut lan = Lan::new();
        lan.identity = Some(([10, 0, 0, 1], [2, 0, 0, 0, 0, 1]));
        let mut packet = lan.frame(1, BROADCAST, &[0; 6]);
        assert!(valid_frame(&packet));
        packet[5] = 2;
        assert!(!valid_frame(&packet));
    }
    #[test]
    fn server_address_validation() {
        assert_eq!(parse_server("10.0.2.2").unwrap().port, 213);
        assert_eq!(parse_server("10.0.2.2:12345").unwrap().port, 12345);
        for value in [
            "",
            "1.2.3",
            "256.2.3.4",
            "1.2.3.4:0",
            "1.2.3.4:65536",
            "1.2.3.4.5",
            "255.255.255.255",
        ] {
            assert!(parse_server(value).is_none());
        }
    }
}
