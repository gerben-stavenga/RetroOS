//! Transport-independent QRTR v1/v3 framing and service discovery.
//! This layer carries firmware RPCs; it is not an application socket API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Packet,
    ServiceLost,
}
pub type Result<T> = core::result::Result<T, Error>;

/// QRTR service identity; instance contains the wire-format version/instance word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Service {
    pub id: u32,
    pub instance: u32,
}
use alloc::{vec, vec::Vec};
const CONTROL: u32 = 0xffff_fffe;
const BROADCAST: u32 = u32::MAX;

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .ok_or(Error::Packet)
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<u32> {
    bytes
        .get(offset..offset + 2)
        .map(|b| u32::from(u16::from_le_bytes(b.try_into().unwrap())))
        .ok_or(Error::Packet)
}
fn port(value: u32) -> u32 {
    if value == 0xfffe || value == 0xffff {
        CONTROL
    } else {
        value
    }
}

pub struct Packet<'a> {
    pub kind: u32,
    pub source_node: u32,
    pub source_port: u32,
    pub destination_node: u32,
    pub destination_port: u32,
    pub confirm: bool,
    pub payload: &'a [u8],
}
impl<'a> Packet<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let (header, size, this) = match bytes.first() {
            Some(1) if bytes.len() >= 32 => {
                if u32_at(bytes, 0)? != 1 {
                    return Err(Error::Packet);
                }
                (
                    32,
                    u32_at(bytes, 20)? as usize,
                    Self {
                        kind: u32_at(bytes, 4)?,
                        source_node: u32_at(bytes, 8)?,
                        source_port: port(u32_at(bytes, 12)?),
                        destination_node: u32_at(bytes, 24)?,
                        destination_port: port(u32_at(bytes, 28)?),
                        confirm: u32_at(bytes, 16)? != 0,
                        payload: &[],
                    },
                )
            }
            Some(3) if bytes.len() >= 16 => {
                if bytes[2] & !1 != 0 {
                    return Err(Error::Packet);
                }
                (
                    16 + usize::from(bytes[3]),
                    u32_at(bytes, 4)? as usize,
                    Self {
                        kind: u32::from(bytes[1]),
                        source_node: u16_at(bytes, 8)?,
                        source_port: port(u16_at(bytes, 10)?),
                        destination_node: u16_at(bytes, 12)?,
                        destination_port: port(u16_at(bytes, 14)?),
                        confirm: bytes[2] & 1 != 0,
                        payload: &[],
                    },
                )
            }
            _ => return Err(Error::Packet),
        };
        if size == 0 || size.checked_add(3).map(|s| (s & !3) + header) != Some(bytes.len()) {
            return Err(Error::Packet);
        }
        let payload = bytes.get(header..header + size).ok_or(Error::Packet)?;
        if !matches!(this.kind, 1 | 7) && this.destination_port != CONTROL {
            return Err(Error::Packet);
        }
        Ok(Self { payload, ..this })
    }
}

fn encode(
    host: u32,
    kind: u32,
    source_port: u32,
    destination_node: u32,
    destination_port: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + payload.len().div_ceil(4) * 4);
    for word in [
        1,
        kind,
        host,
        source_port,
        0,
        payload.len() as u32,
        destination_node,
        destination_port,
    ] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.extend_from_slice(payload);
    bytes.resize(bytes.len().div_ceil(4) * 4, 0);
    bytes
}
fn control(host: u32, kind: u32, node: u32, values: [u32; 4]) -> Vec<u8> {
    let mut payload = Vec::new();
    for word in [kind, values[0], values[1], values[2], values[3]] {
        payload.extend_from_slice(&word.to_le_bytes());
    }
    encode(host, kind, CONTROL, node, CONTROL, &payload)
}

pub struct Router {
    host: u32,
    wanted: Service,
    server: Option<(u32, u32)>,
    replied_hello: bool,
}
impl Router {
    pub fn new(host: u32, wanted: Service) -> Self {
        Self {
            host,
            wanted,
            server: None,
            replied_hello: false,
        }
    }
    pub fn hello(&self) -> Vec<u8> {
        control(self.host, 2, BROADCAST, [0; 4])
    }
    pub fn lookup(&self) -> Vec<u8> {
        control(
            self.host,
            10,
            BROADCAST,
            [self.wanted.id, self.wanted.instance, 0, 0],
        )
    }
    pub fn server(&self) -> Option<(u32, u32)> {
        self.server
    }
    pub fn data(&self, local_port: u32, payload: &[u8]) -> Result<Vec<u8>> {
        let (node, port) = self.server.ok_or(Error::ServiceLost)?;
        if local_port >= CONTROL || payload.is_empty() || payload.len() > 8192 - 32 {
            return Err(Error::Packet);
        }
        Ok(encode(self.host, 1, local_port, node, port, payload))
    }
    /// Only deliver data from the discovered service to this local socket.
    pub fn data_payload<'a>(&self, bytes: &'a [u8], local_port: u32) -> Result<Option<&'a [u8]>> {
        let packet = Packet::parse(bytes)?;
        Ok((packet.kind == 1
            && packet.destination_node == self.host
            && packet.destination_port == local_port
            && self.server == Some((packet.source_node, packet.source_port)))
        .then_some(packet.payload))
    }
    pub fn receive(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
        let packet = Packet::parse(bytes)?;
        let mut replies = Vec::new();
        if packet.destination_node != self.host && packet.destination_node != BROADCAST {
            return Ok(replies);
        }
        if packet.kind != 1 {
            if packet.payload.len() < 20 || u32_at(packet.payload, 0)? != packet.kind {
                return Err(Error::Packet);
            }
            match packet.kind {
                2 if !self.replied_hello => {
                    self.replied_hello = true;
                    replies.push(control(self.host, 2, packet.source_node, [0; 4]));
                    replies.push(control(
                        self.host,
                        10,
                        packet.source_node,
                        [self.wanted.id, self.wanted.instance, 0, 0],
                    ));
                }
                3 => return Err(Error::ServiceLost),
                4 | 5
                    if u32_at(packet.payload, 4)? == self.wanted.id
                        && u32_at(packet.payload, 8)? == self.wanted.instance =>
                {
                    let node = u32_at(packet.payload, 12)?;
                    let server_port = u32_at(packet.payload, 16)?;
                    if node == BROADCAST || server_port >= CONTROL {
                        return Err(Error::Packet);
                    }
                    if packet.kind == 4 {
                        self.server = Some((node, server_port));
                    } else if self.server == Some((node, server_port)) {
                        return Err(Error::ServiceLost);
                    }
                }
                _ => {}
            }
        }
        if packet.confirm {
            let mut payload = vec![0; 20];
            payload[..4].copy_from_slice(&7u32.to_le_bytes());
            payload[4..8].copy_from_slice(&self.host.to_le_bytes());
            payload[8..12].copy_from_slice(&packet.destination_port.to_le_bytes());
            replies.push(encode(
                self.host,
                7,
                packet.destination_port,
                packet.source_node,
                packet.source_port,
                &payload,
            ));
        }
        Ok(replies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const HOST: u32 = 1;
    fn router() -> Router {
        Router::new(
            HOST,
            Service {
                id: 0x45,
                instance: 0x101,
            },
        )
    }
    #[test]
    fn qrtr_framing_rejects_truncation_and_bad_lengths() {
        let bytes = router().hello();
        for count in 0..bytes.len() {
            assert!(Packet::parse(&bytes[..count]).is_err());
        }
        assert_eq!(Packet::parse(&bytes).unwrap().kind, 2);
        let mut bad = bytes.clone();
        bad[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Packet::parse(&bad).is_err());
        let mut short = vec![3, 1, 0, 4];
        short.extend_from_slice(&4u32.to_le_bytes());
        short.extend_from_slice(&[2, 0, 3, 0, 1, 0, 5, 0]);
        short.extend_from_slice(&[0; 8]);
        assert_eq!(Packet::parse(&short).unwrap().payload.len(), 4);
        short[3] = 255;
        assert!(Packet::parse(&short).is_err());
    }
    #[test]
    fn service_discovery_filters_instances_and_handles_removal() {
        let mut router = router();
        let wrong = control(HOST, 4, HOST, [0x45, 0x201, 2, 17]);
        router.receive(&wrong).unwrap();
        assert_eq!(router.server(), None);
        let right = control(HOST, 4, HOST, [0x45, 0x101, 2, 17]);
        router.receive(&right).unwrap();
        assert_eq!(router.server(), Some((2, 17)));
        assert!(
            router
                .receive(&control(HOST, 5, HOST, [0x45, 0x101, 2, 17]))
                .is_err()
        );
    }
    #[test]
    fn hello_is_answered_once_and_confirmed_data_is_acknowledged() {
        let mut router = router();
        let hello = control(HOST, 2, HOST, [0; 4]);
        assert_eq!(router.receive(&hello).unwrap().len(), 2);
        assert!(router.receive(&hello).unwrap().is_empty());
        let mut data = encode(HOST, 1, 17, HOST, 0x4000, b"QMI");
        data[8..12].copy_from_slice(&2u32.to_le_bytes());
        data[16..20].copy_from_slice(&1u32.to_le_bytes());
        let reply = router.receive(&data).unwrap();
        let packet = Packet::parse(&reply[0]).unwrap();
        assert_eq!(packet.kind, 7);
        assert_eq!(packet.destination_node, 2);
        assert_eq!(packet.destination_port, 17);
    }

    #[test]
    fn discovery_uses_the_callers_node_service_and_instance() {
        let mut router = Router::new(
            9,
            Service {
                id: 0x99,
                instance: 0x305,
            },
        );
        let lookup = router.lookup();
        let packet = Packet::parse(&lookup).unwrap();
        assert_eq!(packet.source_node, 9);
        assert_eq!(u32_at(packet.payload, 4), Ok(0x99));
        assert_eq!(u32_at(packet.payload, 8), Ok(0x305));
        router
            .receive(&control(2, 4, 9, [0x45, 0x101, 42, 77]))
            .unwrap();
        assert_eq!(router.server(), None);
        router
            .receive(&control(2, 4, 1, [0x99, 0x305, 42, 77]))
            .unwrap();
        assert_eq!(router.server(), None);
        router
            .receive(&control(2, 4, 9, [0x99, 0x305, 42, 77]))
            .unwrap();
        assert_eq!(router.server(), Some((42, 77)));
    }
    #[test]
    fn service_data_checks_both_socket_endpoints() {
        let mut router = router();
        assert!(router.data(0x4000, b"request").is_err());
        router
            .receive(&control(7, 4, HOST, [0x45, 0x101, 7, 19]))
            .unwrap();
        let bytes = router.data(0x4000, b"request").unwrap();
        let packet = Packet::parse(&bytes).unwrap();
        assert_eq!((packet.source_node, packet.source_port), (HOST, 0x4000));
        assert_eq!((packet.destination_node, packet.destination_port), (7, 19));
        for (node, source, dest, local, expected) in [
            (7, 19, HOST, 0x4000, true),
            (8, 19, HOST, 0x4000, false),
            (7, 20, HOST, 0x4000, false),
            (7, 19, 9, 0x4000, false),
            (7, 19, HOST, 0x4001, false),
        ] {
            let bytes = encode(node, 1, source, dest, local, b"reply");
            assert_eq!(
                router.data_payload(&bytes, 0x4000).unwrap().is_some(),
                expected
            );
        }
    }
}
