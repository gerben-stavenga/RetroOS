//! OSD-managed rooms on the local IPv4 network. Discovery and datagrams use
//! UDP; the optional two-machine serial cable uses an ordered TCP stream.
use super::{Endpoint, Error, SocketKind, SocketOption};
use alloc::{collections::VecDeque, format, string::String, vec::Vec};
use spin::Mutex;

const PORT: u16 = 1213;
const SERIAL_PORT: u16 = 1214;
const HEADER: usize = 30;
const MAX_PACKET: usize = 1424;
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
    pub node: [u8; 6],
}
struct Client {
    session: Session,
    packets: VecDeque<Vec<u8>>,
}
struct Lan {
    fd: Option<i32>,
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
            if source != Some(client.session.id)
                && (dest == BROADCAST || dest == client.session.node)
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
        if self.stream.is_none() && self.identity.unwrap().1 < peer.mac && time >= self.retry_at {
            if let Ok(fd) = super::socket(SocketKind::Tcp, true) {
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
        && ((packet[5] == 1 && packet.len() == HEADER + 6)
            || (packet[5] == 2 && packet.len() > HEADER))
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
        } else if room != 0
            && room == lan.room
            && lan
                .peers
                .iter()
                .any(|p| p.mac == mac && p.endpoint == endpoint && p.room == room)
        {
            lan.deliver(None, packet[24..30].try_into().unwrap(), &packet[HEADER..]);
        }
    }
    lan.serial_poll(time);
}
pub(crate) fn scanning(value: bool) {
    let mut lan = LAN.lock();
    lan.scan = value;
    if value {
        lan.hello_at = 0;
    }
}
pub(crate) fn item_count() -> usize {
    4 + LAN.lock().rooms().len()
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
                format!(
                    "LAN {:04X} PC {:02X}{:02X}{:02X}",
                    lan.room as u16, mac[3], mac[4], mac[5]
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
        _ => lan
            .rooms()
            .get(row - 4)
            .map(|room| format!("Join LAN {:04X}", *room as u16))
            .unwrap_or_default(),
    }
}
pub(crate) fn activate(row: usize) {
    let mut lan = LAN.lock();
    match row {
        1 if lan.identity.is_some() => {
            let mac = lan.identity.unwrap().1;
            let mut seed = now().wrapping_add(lan.epoch).wrapping_add(1);
            for b in mac {
                seed = seed.wrapping_mul(1099511628211) ^ b as u64;
            }
            lan.select_room(seed.max(1));
        }
        2 => lan.select_room(0),
        3 => {
            drop(lan);
            cycle_cable(true);
            return;
        }
        4.. => {
            if let Some(room) = lan.rooms().get(row - 4).copied() {
                lan.select_room(room);
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
    if lan.room == 0 || lan.clients.len() >= 16 {
        return None;
    }
    lan.sequence = lan.sequence.wrapping_add(1);
    let mut hash = lan.sequence.wrapping_mul(0x9e3779b97f4a7c15);
    for b in lan.identity?.1 {
        hash = (hash ^ b as u64).wrapping_mul(1099511628211);
    }
    let mut node: [u8; 6] = hash.to_be_bytes()[2..].try_into().unwrap();
    node[0] = (node[0] & !1) | 2;
    let session = Session {
        id: lan.sequence,
        epoch: lan.epoch,
        node,
    };
    lan.clients.push(Client {
        session,
        packets: VecDeque::new(),
    });
    Some(session)
}
pub(crate) fn valid(session: Session) -> bool {
    let lan = LAN.lock();
    lan.epoch == session.epoch && lan.room != 0
}
pub(crate) fn detach(session: Session) {
    LAN.lock().clients.retain(|c| c.session.id != session.id);
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
    if packet.len() > MAX_PACKET {
        return false;
    }
    let mut lan = LAN.lock();
    if session.epoch != lan.epoch || lan.room == 0 {
        return false;
    }
    lan.deliver(Some(session.id), dest, packet);
    let Some(fd) = lan.fd else { return false };
    let frame = lan.frame(2, dest, packet);
    let mut success = true;
    for peer in &lan.peers {
        if peer.room == lan.room && super::sendto(fd, &frame, Some(peer.endpoint)).is_err() {
            success = false;
        }
    }
    success
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing_and_room_isolation() {
        let mut lan = Lan::new();
        lan.identity = Some(([10, 0, 0, 1], [2, 0, 0, 0, 0, 1]));
        let packet = lan.frame(1, BROADCAST, &[0; 6]);
        assert!(valid_frame(&packet));
        assert!(!valid_frame(&packet[..packet.len() - 1]));
        let mut bad = packet.clone();
        bad[23] = 255;
        assert!(!valid_frame(&bad));
        let session = Session {
            id: 1,
            epoch: 0,
            node: [2; 6],
        };
        lan.clients.push(Client {
            session,
            packets: VecDeque::new(),
        });
        lan.deliver(None, [3; 6], b"wrong");
        assert!(lan.clients[0].packets.is_empty());
        lan.deliver(Some(1), BROADCAST, b"self");
        assert!(lan.clients[0].packets.is_empty());
        lan.deliver(None, BROADCAST, b"ok");
        assert_eq!(lan.clients[0].packets.pop_front().unwrap(), b"ok");
    }
}
