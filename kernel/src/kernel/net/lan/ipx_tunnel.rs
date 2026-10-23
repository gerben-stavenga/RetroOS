//! DOSBox IPXNET wire protocol: raw IPX datagrams and socket-2 registration.
//! Reference: DOSBox src/hardware/ipxserver.cpp and ipx.cpp. Discovery remains
//! an independent OSD service; no RetroOS framing is added to IPX packets.
use super::{Endpoint, SocketKind, bound};
use alloc::vec::Vec;

pub(super) const PORT: u16 = 213;
pub(super) const MAX_PACKET: usize = 1424;
pub(super) const BROADCAST: [u8; 6] = [255; 6];

pub(super) fn valid(packet: &[u8]) -> bool {
    (30..=MAX_PACKET).contains(&packet.len())
        && u16::from_be_bytes([packet[2], packet[3]]) as usize == packet.len()
}
pub(super) fn node(endpoint: Endpoint) -> [u8; 6] {
    let mut node = [0; 6];
    node[..4].copy_from_slice(&endpoint.address);
    node[4..].copy_from_slice(&endpoint.port.to_be_bytes());
    node
}
fn registration() -> [u8; 30] {
    let mut packet = [0; 30];
    packet[..2].fill(255);
    packet[3] = 30;
    packet[17] = 2;
    packet[29] = 2;
    packet
}
fn is_registration(packet: &[u8]) -> bool {
    valid(packet) && packet.len() == 30 && packet[10..16] == [0; 6] && packet[16..18] == [0, 2]
}
fn acknowledgement(client: Endpoint, server: Endpoint) -> [u8; 30] {
    let mut packet = registration();
    packet[10..16].copy_from_slice(&node(client));
    packet[21] = 1;
    packet[22..28].copy_from_slice(&node(server));
    packet
}

pub(super) struct Server {
    fd: i32,
    endpoint: Endpoint,
    peers: Vec<Endpoint>,
}
impl Drop for Server {
    fn drop(&mut self) {
        super::super::close(self.fd);
    }
}
impl Server {
    pub fn new(address: [u8; 4]) -> Option<Self> {
        Some(Self {
            fd: bound(SocketKind::Udp, PORT)?,
            endpoint: Endpoint {
                address,
                port: PORT,
            },
            peers: Vec::new(),
        })
    }
    pub fn receive(&mut self) -> Option<Vec<u8>> {
        // Bound work even under a registration flood.
        for _ in 0..32 {
            let mut packet = [0; MAX_PACKET + 1];
            let mut from = None;
            let n = super::super::recvfrom(self.fd, &mut packet, false, &mut from).ok()? as usize;
            let Some(from) = from else { continue };
            let packet = &packet[..n];
            if !valid(packet) {
                continue;
            }
            if is_registration(packet) {
                if !self.peers.contains(&from) {
                    if self.peers.len() == 16 {
                        continue;
                    }
                    self.peers.push(from);
                    crate::compact_println!(
                        "IPXNET: client {}.{}.{}.{}:{}",
                        from.address[0],
                        from.address[1],
                        from.address[2],
                        from.address[3],
                        from.port
                    );
                }
                let _ = super::super::sendto(
                    self.fd,
                    &acknowledgement(from, self.endpoint),
                    Some(from),
                );
                continue;
            }
            // Only registered sources can inject traffic or impersonate a node.
            if self.peers.contains(&from) && packet[22..28] == node(from) {
                return Some(packet.to_vec());
            }
        }
        None
    }
    pub fn forward(&self, packet: &[u8]) -> bool {
        let dest = &packet[10..16];
        let source = &packet[22..28];
        let mut success = true;
        for peer in &self.peers {
            let peer_node = node(*peer);
            if source != peer_node && (dest == BROADCAST || dest == peer_node) {
                success &= super::super::sendto(self.fd, packet, Some(*peer)).is_ok();
            }
        }
        success
    }
}

pub(super) struct Connection {
    fd: i32,
    server: Option<Endpoint>,
    pub address: Option<[u8; 10]>,
    retry_at: u64,
}
impl Drop for Connection {
    fn drop(&mut self) {
        super::super::close(self.fd);
    }
}
impl Connection {
    pub fn new(server: Option<Endpoint>, local_ip: [u8; 4]) -> Option<Self> {
        let fd = bound(SocketKind::Udp, 0)?;
        let mut connection = Self {
            fd,
            server,
            address: None,
            retry_at: 0,
        };
        if server.is_none() {
            let mut endpoint = None;
            super::super::getsockname(fd, &mut endpoint).ok()?;
            let mut endpoint = endpoint?;
            endpoint.address = local_ip;
            let mut address = [0; 10];
            address[4..].copy_from_slice(&node(endpoint));
            connection.address = Some(address);
        }
        Some(connection)
    }
    pub fn poll(&mut self, time: u64) -> Option<Vec<u8>> {
        let server = self.server?;
        if self.address.is_none() && time >= self.retry_at {
            let _ = super::super::sendto(self.fd, &registration(), Some(server));
            self.retry_at = time + 1000;
        }
        for _ in 0..32 {
            let mut packet = [0; MAX_PACKET + 1];
            let mut from = None;
            let n = super::super::recvfrom(self.fd, &mut packet, false, &mut from).ok()? as usize;
            let packet = &packet[..n];
            if from != Some(server) || !valid(packet) {
                continue;
            }
            if packet.len() == 30
                && packet[16..18] == [0, 2]
                && packet[28..30] == [0, 2]
                && packet[10..16] != [0; 6]
                && packet[10..16] != BROADCAST
            {
                if self.address.is_none() {
                    self.address = Some(packet[6..16].try_into().unwrap());
                    crate::compact_println!(
                        "IPXNET: connected to {}.{}.{}.{}:{}",
                        server.address[0],
                        server.address[1],
                        server.address[2],
                        server.address[3],
                        server.port
                    );
                    super::repaint();
                }
                continue;
            }
            if self.address.is_some() {
                return Some(packet.to_vec());
            }
        }
        None
    }
    pub fn send(&self, packet: &[u8]) -> bool {
        self.server
            .is_some_and(|server| super::super::sendto(self.fd, packet, Some(server)).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dosbox_registration_and_address_layout() {
        let request = registration();
        assert!(is_registration(&request));
        let client = Endpoint {
            address: [192, 168, 1, 2],
            port: 0xabcd,
        };
        let server = Endpoint {
            address: [192, 168, 1, 1],
            port: 213,
        };
        let ack = acknowledgement(client, server);
        assert!(valid(&ack));
        assert!(!is_registration(&ack));
        assert_eq!(&ack[6..16], &[0, 0, 0, 0, 192, 168, 1, 2, 0xab, 0xcd]);
        assert_eq!(&ack[18..30], &[0, 0, 0, 1, 192, 168, 1, 1, 0, 213, 0, 2]);
        assert!(!valid(&ack[..29]));
        assert!(!valid(&[0; 30]));
    }
}
