//! Shared station association and authentication policy. Drivers execute the
//! actions below; firmware command encodings and DMA never enter this layer.
use super::{
    auth::{self, Key, KeyId, Security, Supplicant},
    scan::Network,
};
use alloc::{vec, vec::Vec};
use zeroize::Zeroizing;
static NEXT_TX: spin::Mutex<u64> = spin::Mutex::new(1);

pub enum Event {
    ChannelReady,
    Management(Vec<u8>),
    Associated,
    Eapol { source: [u8; 6], bytes: Vec<u8> },
    KeyInstalled { id: KeyId, success: bool },
    EapolSent { id: u64, success: bool },
    Authorized,
    Disconnected,
}
pub enum Action {
    StartChannel(Network),
    Management(Vec<u8>),
    Associate { network: Network, aid: u16 },
    Eapol { id: u64, bytes: Vec<u8> },
    InstallKey(Key),
    Authorize,
    Disconnect,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Channel,
    Authentication,
    Association,
    LinkSetup,
    Handshake,
    Installing,
    Confirming,
    Authorizing,
    Connected,
    Backoff,
}
pub struct Connection {
    pub phase: Phase,
    pub network: Network,
    pub security: Security,
    station: [u8; 6],
    supplicant: Supplicant,
    pending: Vec<KeyId>,
    deadline: u64,
    retries: u8,
    sequence: u16,
    retry_frame: Vec<u8>,
    authorized: bool,
    confirming_tx: Option<u64>,
}
const SECOND: u64 = 1_000_000_000;
fn header(kind: u8, station: [u8; 6], peer: [u8; 6], seq: u16) -> Vec<u8> {
    let mut bytes = vec![0u8; 24];
    bytes[0] = kind;
    bytes[4..10].copy_from_slice(&peer);
    bytes[10..16].copy_from_slice(&station);
    bytes[16..22].copy_from_slice(&peer);
    bytes[22..24].copy_from_slice(&((seq & 0xfff) << 4).to_le_bytes());
    bytes
}
pub fn legacy_rates(network: &Network) -> Result<Vec<u8>, auth::Error> {
    let mut ies = network.ies.as_slice();
    let mut rates = Vec::new();
    while !ies.is_empty() {
        if ies.len() < 2 {
            return Err(auth::Error::Packet);
        }
        let len = usize::from(ies[1]);
        let value = ies.get(2..2 + len).ok_or(auth::Error::Packet)?;
        if matches!(ies[0], 1 | 50) {
            for &rate in value {
                let supported = matches!(
                    rate & 0x7f,
                    2 | 4 | 11 | 22 | 12 | 18 | 24 | 36 | 48 | 72 | 96 | 108
                ) && (network.frequency < 3000
                    || !matches!(rate & 0x7f, 2 | 4 | 11 | 22));
                if !supported && rate & 0x80 != 0 {
                    return Err(auth::Error::Unsupported);
                }
                if supported && !rates.iter().any(|r| r & 0x7f == rate & 0x7f) {
                    rates.push(rate);
                }
            }
        }
        ies = &ies[2 + len..];
    }
    if rates.is_empty() || rates.len() > 12 {
        return Err(auth::Error::Unsupported);
    }
    Ok(rates)
}
impl Connection {
    pub fn new(
        network: Network,
        station: [u8; 6],
        pmk: Zeroizing<[u8; 32]>,
        nonce: [u8; 32],
        now: u64,
    ) -> Result<Self, auth::Error> {
        let security = Security::negotiate(&network.rsn)?;
        legacy_rates(&network)?;
        let supplicant = Supplicant::new(pmk, station, network.bssid, security.clone(), nonce)?;
        Ok(Self {
            phase: Phase::Channel,
            network,
            security,
            station,
            supplicant,
            pending: Vec::new(),
            deadline: now + 5 * SECOND,
            retries: 0,
            sequence: 0,
            retry_frame: Vec::new(),
            authorized: false,
            confirming_tx: None,
        })
    }
    pub fn first(&self) -> Action {
        Action::StartChannel(self.network.clone())
    }
    fn eapol(&mut self, bytes: Vec<u8>) -> Action {
        let id = {
            let mut next = NEXT_TX.lock();
            let id = *next;
            *next = next.wrapping_add(1);
            id
        };
        if self.phase == Phase::Confirming {
            self.confirming_tx = Some(id);
        }
        Action::Eapol { id, bytes }
    }
    fn management(&mut self, kind: u8, body: &[u8], now: u64) -> Vec<Action> {
        self.sequence = self.sequence.wrapping_add(1);
        let mut frame = header(kind, self.station, self.network.bssid, self.sequence);
        frame.extend_from_slice(body);
        self.retry_frame = frame.clone();
        self.deadline = now + 2 * SECOND;
        self.retries = 0;
        vec![Action::Management(frame)]
    }
    pub fn fail(&mut self, now: u64) -> Vec<Action> {
        self.phase = Phase::Backoff;
        self.deadline = now + 5 * SECOND;
        self.pending.clear();
        self.authorized = false;
        vec![Action::Disconnect]
    }
    pub fn event(&mut self, event: Event, now: u64) -> Vec<Action> {
        match event {
            Event::ChannelReady if self.phase == Phase::Channel => {
                self.phase = Phase::Authentication;
                self.management(0xb0, &[0, 0, 1, 0, 0, 0], now)
            }
            Event::Management(frame) => {
                if frame.len() < 26
                    || frame[1] & 0x47 != 0
                    || frame[4..10] != self.station
                    || frame[22] & 15 != 0
                    || frame[10..16] != self.network.bssid
                    || frame[16..22] != self.network.bssid
                {
                    return Vec::new();
                }
                if matches!(frame[0], 0xa0 | 0xc0) {
                    return self.fail(now);
                }
                if frame[0] == 0xb0 && self.phase == Phase::Authentication {
                    if frame.len() < 30 || frame[24..28] != [0, 0, 2, 0] {
                        return Vec::new();
                    }
                    if frame[28..30] != [0, 0] {
                        return self.fail(now);
                    }
                    let rates = match legacy_rates(&self.network) {
                        Ok(r) => r,
                        Err(_) => return self.fail(now),
                    };
                    let caps = (self.network.capability & (0x10 | 0x20 | 0x400)) | 1;
                    let mut body = caps.to_le_bytes().to_vec();
                    body.extend_from_slice(&10u16.to_le_bytes());
                    body.extend_from_slice(&[0, self.network.ssid.len() as u8]);
                    body.extend_from_slice(&self.network.ssid);
                    let n = rates.len().min(8);
                    body.extend_from_slice(&[1, n as u8]);
                    body.extend_from_slice(&rates[..n]);
                    if n < rates.len() {
                        body.extend_from_slice(&[50, (rates.len() - n) as u8]);
                        body.extend_from_slice(&rates[n..]);
                    }
                    body.extend_from_slice(&self.security.association_ie);
                    self.phase = Phase::Association;
                    self.management(0, &body, now)
                } else if frame[0] == 0x10 && self.phase == Phase::Association {
                    if frame.len() < 30 {
                        return Vec::new();
                    }
                    if frame[26..28] != [0, 0] {
                        return self.fail(now);
                    }
                    let aid = u16::from_le_bytes([frame[28], frame[29]]) & 0x3fff;
                    if !(1..=2007).contains(&aid) {
                        return self.fail(now);
                    }
                    self.phase = Phase::LinkSetup;
                    self.deadline = now + 5 * SECOND;
                    vec![Action::Associate {
                        network: self.network.clone(),
                        aid,
                    }]
                } else {
                    Vec::new()
                }
            }
            Event::Associated if self.phase == Phase::LinkSetup => {
                self.phase = Phase::Handshake;
                self.deadline = now + 15 * SECOND;
                Vec::new()
            }
            Event::Eapol { source, bytes }
                if source == self.network.bssid
                    && matches!(
                        self.phase,
                        Phase::Handshake | Phase::Installing | Phase::Confirming | Phase::Connected
                    ) =>
            {
                match self.supplicant.receive(&bytes) {
                    Ok(exchange) => {
                        let mut actions = Vec::new();
                        if !exchange.keys.is_empty() {
                            self.pending = exchange.keys.iter().map(|k| k.id).collect();
                            self.phase = Phase::Installing;
                            self.deadline = now + 5 * SECOND;
                            actions.extend(exchange.keys.into_iter().map(Action::InstallKey));
                        }
                        if let Some(reply) = exchange.reply {
                            if self.supplicant.complete() && !self.authorized {
                                self.phase = Phase::Confirming;
                            }
                            actions.push(self.eapol(reply));
                        }
                        actions
                    }
                    // Forged/bad packets cannot change authorization or force
                    // keys into hardware. The existing handshake timeout stays.
                    Err(_) => Vec::new(),
                }
            }
            Event::KeyInstalled { id, success } if self.phase == Phase::Installing => {
                let Some(index) = self.pending.iter().position(|k| *k == id) else {
                    return Vec::new();
                };
                if !success {
                    return self.fail(now);
                }
                self.pending.remove(index);
                if self.pending.is_empty() {
                    if let Ok(reply) = self.supplicant.installed() {
                        self.phase = Phase::Confirming;
                        self.deadline = now + 5 * SECOND;
                        vec![self.eapol(reply)]
                    } else {
                        self.fail(now)
                    }
                } else {
                    Vec::new()
                }
            }
            Event::EapolSent { id, success }
                if self.phase == Phase::Confirming && self.confirming_tx == Some(id) =>
            {
                if !success {
                    return self.fail(now);
                }
                if self.authorized {
                    self.phase = Phase::Connected;
                    Vec::new()
                } else {
                    self.phase = Phase::Authorizing;
                    self.deadline = now + 5 * SECOND;
                    vec![Action::Authorize]
                }
            }
            Event::Authorized if self.phase == Phase::Authorizing => {
                self.phase = Phase::Connected;
                self.authorized = true;
                Vec::new()
            }
            Event::Disconnected => self.fail(now),
            _ => Vec::new(),
        }
    }
    pub fn tick(&mut self, now: u64) -> Vec<Action> {
        if matches!(self.phase, Phase::Connected | Phase::Idle) || now < self.deadline {
            return Vec::new();
        }
        if self.phase == Phase::Backoff {
            self.phase = Phase::Idle;
            return Vec::new();
        }
        if matches!(self.phase, Phase::Authentication | Phase::Association) && self.retries < 2 {
            self.retries += 1;
            self.deadline = now + 2 * SECOND;
            let mut frame = self.retry_frame.clone();
            frame[1] |= 8;
            return vec![Action::Management(frame)];
        }
        self.fail(now)
    }
    pub fn status(&self) -> &'static str {
        match self.phase {
            Phase::Idle => "waiting to reconnect",
            Phase::Channel => "starting station channel",
            Phase::Authentication => "802.11 authentication",
            Phase::Association => "associating",
            Phase::LinkSetup => "configuring associated peer",
            Phase::Handshake => "WPA2 key exchange",
            Phase::Installing => "installing encryption keys",
            Phase::Confirming => "confirming WPA2 keys",
            Phase::Authorizing => "authorizing encrypted link",
            Phase::Connected => "Wi-Fi connected",
            Phase::Backoff => "connection attempt failed; retrying",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn network() -> Network {
        Network {
            bssid: [2, 0, 0, 0, 0, 2],
            ssid: b"test-ap".to_vec(),
            frequency: 2412,
            signal_dbm: -50,
            privacy: true,
            rsn: vec![
                1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0,
            ],
            wpa: Vec::new(),
            ies: vec![1, 4, 0x82, 0x84, 0x8b, 0x96],
            capability: 0x431,
            beacon_interval: 100,
        }
    }
    fn connection() -> Connection {
        Connection::new(
            network(),
            [2, 0, 0, 0, 0, 1],
            Zeroizing::new([1; 32]),
            [2; 32],
            0,
        )
        .unwrap()
    }
    fn response(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut frame = header(kind, [2, 0, 0, 0, 0, 2], [2, 0, 0, 0, 0, 1], 0);
        frame[16..22].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        frame.extend_from_slice(body);
        frame
    }
    #[test]
    fn association_checks_peer_and_status_before_installing_peer() {
        let mut c = connection();
        assert!(matches!(c.first(), Action::StartChannel(_)));
        let auth = c.event(Event::ChannelReady, 1);
        assert!(matches!(&auth[..],[Action::Management(f)] if f[0]==0xb0));
        let mut wrong = response(0xb0, &[0, 0, 2, 0, 0, 0]);
        wrong[10] ^= 4;
        assert!(c.event(Event::Management(wrong), 2).is_empty());
        assert_eq!(c.phase, Phase::Authentication);
        let assoc = c.event(Event::Management(response(0xb0, &[0, 0, 2, 0, 0, 0])), 3);
        let Action::Management(frame) = &assoc[0] else {
            panic!()
        };
        assert_eq!(frame[0], 0);
        assert!(frame.windows(7).any(|v| v == b"test-ap"));
        assert_eq!(&frame[frame.len() - 22..], c.security.association_ie);
        assert!(matches!(
            &c.event(Event::Management(response(0x10, &[1, 0, 0, 0, 7, 0xc0])), 4)[..],
            [Action::Associate { aid: 7, .. }]
        ));
        c.event(Event::Associated, 5);
        assert_eq!(c.phase, Phase::Handshake);
    }
    #[test]
    fn timeouts_retry_same_sequence_then_disconnect_and_backoff() {
        let mut c = connection();
        let first = c.event(Event::ChannelReady, 0);
        let Action::Management(frame) = &first[0] else {
            panic!()
        };
        for now in [2 * SECOND, 4 * SECOND] {
            let retry = c.tick(now);
            let Action::Management(retry) = &retry[0] else {
                panic!()
            };
            assert_eq!(retry[1], 8);
            assert_eq!(&retry[2..], &frame[2..]);
        }
        assert!(matches!(&c.tick(6 * SECOND)[..], [Action::Disconnect]));
        assert_eq!(c.phase, Phase::Backoff);
        c.tick(11 * SECOND);
        assert_eq!(c.phase, Phase::Idle);
    }
    #[test]
    fn stale_transmit_completion_cannot_authorize_link() {
        let mut c = connection();
        c.phase = Phase::Confirming;
        c.confirming_tx = Some(2);
        assert!(
            c.event(
                Event::EapolSent {
                    id: 1,
                    success: true
                },
                0
            )
            .is_empty()
        );
        assert_eq!(c.phase, Phase::Confirming);
        assert!(matches!(
            &c.event(
                Event::EapolSent {
                    id: 2,
                    success: true
                },
                1
            )[..],
            [Action::Authorize]
        ));
        c.event(Event::Authorized, 2);
        assert_eq!(c.phase, Phase::Connected);
    }
}
