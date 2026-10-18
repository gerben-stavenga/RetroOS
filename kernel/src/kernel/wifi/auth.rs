//! Driver-independent WPA2-PSK/CCMP negotiation and EAPOL key exchange.
//! Protocol layouts follow IEEE RSN and hostap's rsn_supp/wpa.c. Crypto
//! primitives and AES key unwrap are supplied by RustCrypto, not NIC firmware.
use aes_kw::KwAes128;
use alloc::{vec, vec::Vec};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Packet,
    Unsupported,
    Replay,
    Mic,
    KeyData,
    State,
}
type Result<T> = core::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cipher {
    Ccmp128,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyId {
    pub pairwise: bool,
    pub index: u8,
}
#[derive(Clone)]
pub struct Key {
    pub id: KeyId,
    pub peer: [u8; 6],
    pub cipher: Cipher,
    pub receive_counter: [u8; 6],
    pub bytes: Zeroizing<[u8; 16]>,
}
impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WifiKey")
            .field("id", &self.id)
            .field("cipher", &self.cipher)
            .finish_non_exhaustive()
    }
}
/// Receive counters for the initial non-QoS CCMP link. Drivers call `install`
/// only for fresh keys after firmware acknowledgement; retransmissions must
/// never call it. QoS support needs one pairwise counter per TID.
#[derive(Default)]
pub struct Replay {
    counters: [Option<u64>; 5],
}
impl Replay {
    pub fn install(&mut self, id: KeyId, counter: u64) {
        if id.index <= 3 {
            self.counters[if id.pairwise { 4 } else { id.index as usize }] = Some(counter);
        }
    }
    pub fn accept(&mut self, id: KeyId, counter: u64) -> bool {
        if id.index > 3 || counter == 0 || counter >= 1 << 48 {
            return false;
        }
        let at = if id.pairwise { 4 } else { id.index as usize };
        let Some(previous) = self.counters[at] else {
            return false;
        };
        if counter <= previous {
            return false;
        }
        self.counters[at] = Some(counter);
        true
    }
}
#[derive(Clone)]
pub struct Security {
    /// AP's original RSN IE body, authenticated again in message 3.
    pub ap_rsn: Vec<u8>,
    /// Our association/M2 RSN IE, including its IE header.
    pub association_ie: Vec<u8>,
}
fn le16(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes
            .get(at..at + 2)
            .ok_or(Error::Packet)?
            .try_into()
            .unwrap(),
    ))
}
impl Security {
    pub fn negotiate(rsn: &[u8]) -> Result<Self> {
        if rsn.len() > 255 || le16(rsn, 0)? != 1 || rsn.get(2..6) != Some(&[0, 15, 172, 4][..]) {
            return Err(Error::Unsupported);
        }
        let mut at = 6;
        let mut suites = |wanted: [u8; 4]| -> Result<bool> {
            let count = usize::from(le16(rsn, at)?);
            at += 2;
            if count == 0 || count > 32 {
                return Err(Error::Packet);
            }
            let list = rsn.get(at..at + count * 4).ok_or(Error::Packet)?;
            at += count * 4;
            Ok(list.chunks_exact(4).any(|s| s == wanted))
        };
        if !suites([0, 15, 172, 4])? || !suites([0, 15, 172, 2])? {
            return Err(Error::Unsupported);
        }
        if rsn.len() > at {
            let caps = le16(rsn, at)?;
            at += 2;
            if caps & (1 << 6) != 0 {
                return Err(Error::Unsupported);
            } // PMF required
        }
        if rsn.len() > at {
            let pmkids = usize::from(le16(rsn, at)?);
            at += 2;
            at = at
                .checked_add(pmkids.checked_mul(16).ok_or(Error::Packet)?)
                .ok_or(Error::Packet)?;
            if at > rsn.len() {
                return Err(Error::Packet);
            }
            if rsn.len() > at {
                at += 4;
            } // optional management group cipher
        }
        if at != rsn.len() {
            return Err(Error::Packet);
        }
        Ok(Self {
            ap_rsn: rsn.to_vec(),
            association_ie: vec![
                48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0,
            ],
        })
    }
}

const PAIRWISE: u16 = 8;
const INSTALL: u16 = 64;
const ACK: u16 = 128;
const MIC: u16 = 256;
const SECURE: u16 = 512;
const ENCRYPTED: u16 = 4096;

struct Packet<'a> {
    bytes: &'a [u8],
    info: u16,
    replay: u64,
    nonce: [u8; 32],
    rsc: [u8; 6],
    data: &'a [u8],
}
impl<'a> Packet<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < 99 || !(1..=3).contains(&bytes[0]) || bytes[1] != 3 || bytes[4] != 2 {
            return Err(Error::Packet);
        }
        let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]])) + 4;
        let bytes = bytes.get(..length).ok_or(Error::Packet)?;
        if !(99..=2048).contains(&length) {
            return Err(Error::Packet);
        }
        let info = u16::from_be_bytes([bytes[5], bytes[6]]);
        if info & 7 != 2 || info & !0x13cau16 != 0 {
            return Err(Error::Unsupported);
        }
        let key_len = u16::from_be_bytes([bytes[7], bytes[8]]);
        if (info & PAIRWISE != 0 && key_len != 16) || !matches!(key_len, 0 | 16) {
            return Err(Error::Unsupported);
        }
        let data_len = usize::from(u16::from_be_bytes([bytes[97], bytes[98]]));
        if data_len + 99 != length || data_len > 1024 || bytes[71..73] != [0, 0] {
            return Err(Error::Packet);
        }
        Ok(Self {
            bytes,
            info,
            replay: u64::from_be_bytes(bytes[9..17].try_into().unwrap()),
            nonce: bytes[17..49].try_into().unwrap(),
            rsc: bytes[65..71].try_into().unwrap(),
            data: &bytes[99..],
        })
    }
}
fn mac(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 20]> {
    let mut m = Hmac::<Sha1>::new_from_slice(key).unwrap();
    for part in parts {
        m.update(part);
    }
    Zeroizing::new(m.finalize().into_bytes().into())
}
fn ptk(
    pmk: &[u8; 32],
    station: [u8; 6],
    peer: [u8; 6],
    snonce: &[u8; 32],
    anonce: &[u8; 32],
) -> Zeroizing<[u8; 48]> {
    let mut data = Zeroizing::new(Vec::with_capacity(76));
    data.extend_from_slice(&station.min(peer));
    data.extend_from_slice(&station.max(peer));
    data.extend_from_slice(snonce.min(anonce));
    data.extend_from_slice(snonce.max(anonce));
    let mut key = Zeroizing::new([0u8; 48]);
    for (counter, chunk) in key.chunks_mut(20).enumerate() {
        let h = mac(
            pmk,
            &[b"Pairwise key expansion", &[0], &data, &[counter as u8]],
        );
        chunk.copy_from_slice(&h[..chunk.len()]);
    }
    key
}
fn verify(packet: &Packet<'_>, kck: &[u8]) -> Result<()> {
    let mic = mac(kck, &[&packet.bytes[..81], &[0; 16], &packet.bytes[97..]]);
    if bool::from(mic[..16].ct_eq(&packet.bytes[81..97])) {
        Ok(())
    } else {
        Err(Error::Mic)
    }
}
fn reply(packet: &Packet<'_>, flags: u16, nonce: &[u8; 32], data: &[u8], kck: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 99];
    out[0] = packet.bytes[0];
    out[1] = 3;
    out[4] = 2;
    out[2..4].copy_from_slice(&((95 + data.len()) as u16).to_be_bytes());
    out[5..7].copy_from_slice(&flags.to_be_bytes());
    out[9..17].copy_from_slice(&packet.replay.to_be_bytes());
    out[17..49].copy_from_slice(nonce);
    out[97..99].copy_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    let mic = mac(kck, &[&out]);
    out[81..97].copy_from_slice(&mic[..16]);
    out
}
fn unwrap(kek: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < 24 || !data.len().is_multiple_of(8) {
        return Err(Error::KeyData);
    }
    let kw = KwAes128::new_from_slice(kek).map_err(|_| Error::KeyData)?;
    let mut out = Zeroizing::new(vec![0; data.len() - 8]);
    kw.unwrap_key(data, &mut out).map_err(|_| Error::KeyData)?;
    Ok(out)
}
struct KeyData {
    rsn: Option<Vec<u8>>,
    gtk: Option<(u8, Zeroizing<[u8; 16]>)>,
}
fn key_data(mut bytes: &[u8]) -> Result<KeyData> {
    let mut out = KeyData {
        rsn: None,
        gtk: None,
    };
    while !bytes.is_empty() {
        if bytes[0] == 221 && bytes[1..].iter().all(|b| *b == 0) {
            break;
        } // RSN padding
        if bytes.len() < 2 {
            return Err(Error::KeyData);
        }
        let len = usize::from(bytes[1]);
        let value = bytes.get(2..2 + len).ok_or(Error::KeyData)?;
        match bytes[0] {
            48 => {
                if out.rsn.replace(value.to_vec()).is_some() {
                    return Err(Error::KeyData);
                }
            }
            221 if value.starts_with(&[0, 15, 172, 1]) => {
                if value.len() != 22 || out.gtk.is_some() || value[4] & !7 != 0 || value[5] != 0 {
                    return Err(Error::KeyData);
                }
                out.gtk = Some((
                    value[4] & 3,
                    Zeroizing::new(value[6..22].try_into().unwrap()),
                ));
            }
            _ => {}
        }
        bytes = &bytes[2 + len..];
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    AwaitOne,
    AwaitThree,
    Installing,
    Complete,
    GroupInstalling,
}
pub struct Exchange {
    pub reply: Option<Vec<u8>>,
    pub keys: Vec<Key>,
}
pub struct Supplicant {
    pmk: Zeroizing<[u8; 32]>,
    station: [u8; 6],
    peer: [u8; 6],
    security: Security,
    snonce: Zeroizing<[u8; 32]>,
    anonce: [u8; 32],
    ptk: Option<Zeroizing<[u8; 48]>>,
    phase: Phase,
    replay: Option<u64>,
    one_replay: u64,
    two: Vec<u8>,
    ack: Vec<u8>,
    installed_gtk: Option<(u8, Zeroizing<[u8; 16]>)>,
    last_packet: Vec<u8>,
}
impl Supplicant {
    /// Nonce must come from the kernel CSPRNG, freshly generated per association.
    pub fn new(
        pmk: Zeroizing<[u8; 32]>,
        station: [u8; 6],
        peer: [u8; 6],
        security: Security,
        snonce: [u8; 32],
    ) -> Result<Self> {
        if snonce == [0; 32] || station == peer || station[0] & 1 != 0 || peer[0] & 1 != 0 {
            return Err(Error::State);
        }
        Ok(Self {
            pmk,
            station,
            peer,
            security,
            snonce: Zeroizing::new(snonce),
            anonce: [0; 32],
            ptk: None,
            phase: Phase::AwaitOne,
            replay: None,
            one_replay: 0,
            two: Vec::new(),
            ack: Vec::new(),
            installed_gtk: None,
            last_packet: Vec::new(),
        })
    }
    pub fn receive(&mut self, bytes: &[u8]) -> Result<Exchange> {
        let packet = Packet::parse(bytes)?;
        if packet.info == 2 | PAIRWISE | ACK {
            if packet.nonce == [0; 32] {
                return Err(Error::Packet);
            }
            if self.phase == Phase::AwaitThree
                && packet.replay == self.one_replay
                && packet.nonce == self.anonce
            {
                return Ok(Exchange {
                    reply: Some(self.two.clone()),
                    keys: Vec::new(),
                });
            }
            if self.phase != Phase::AwaitOne {
                return Err(Error::Replay);
            }
            let key = ptk(
                &self.pmk,
                self.station,
                self.peer,
                &self.snonce,
                &packet.nonce,
            );
            self.two = reply(
                &packet,
                2 | PAIRWISE | MIC,
                &self.snonce,
                &self.security.association_ie,
                &key[..16],
            );
            self.ptk = Some(key);
            self.anonce = packet.nonce;
            self.one_replay = packet.replay;
            self.replay = Some(packet.replay);
            self.phase = Phase::AwaitThree;
            return Ok(Exchange {
                reply: Some(self.two.clone()),
                keys: Vec::new(),
            });
        }
        let pairwise = packet.info & PAIRWISE != 0;
        let expected =
            2 | ACK | MIC | SECURE | ENCRYPTED | if pairwise { PAIRWISE | INSTALL } else { 0 };
        if packet.info != expected {
            return Err(Error::Unsupported);
        }
        let ptk = self.ptk.as_ref().ok_or(Error::State)?;
        verify(&packet, &ptk[..16])?;
        if self.replay == Some(packet.replay) && packet.bytes != self.last_packet {
            return Err(Error::Replay);
        }
        if self.replay.is_some_and(|old| packet.replay < old) || packet.replay <= self.one_replay {
            return Err(Error::Replay);
        }
        if pairwise && packet.nonce != self.anonce {
            return Err(Error::Mic);
        }
        let plain = unwrap(&ptk[16..32], packet.data)?;
        let data = key_data(&plain)?;
        if pairwise && data.rsn.as_deref() != Some(self.security.ap_rsn.as_slice()) {
            return Err(Error::KeyData);
        }
        let (index, gtk) = data.gtk.ok_or(Error::KeyData)?;
        let same_gtk = self
            .installed_gtk
            .as_ref()
            .is_some_and(|(old_id, key)| *old_id == index && bool::from(key[..].ct_eq(&gtk[..])));
        let already = matches!(
            self.phase,
            Phase::Installing | Phase::Complete | Phase::GroupInstalling
        );
        if self.phase == Phase::GroupInstalling && (pairwise || !same_gtk) {
            return Err(Error::State);
        }
        if pairwise && already && !same_gtk {
            return Err(Error::State);
        }
        if !pairwise && self.phase != Phase::Complete && self.phase != Phase::GroupInstalling {
            return Err(Error::State);
        }
        if self.replay == Some(packet.replay) && !same_gtk {
            return Err(Error::Replay);
        }
        let mut keys = Vec::new();
        if pairwise && !already {
            keys.push(Key {
                id: KeyId {
                    pairwise: true,
                    index: 0,
                },
                peer: self.peer,
                cipher: Cipher::Ccmp128,
                receive_counter: [0; 6],
                bytes: Zeroizing::new(ptk[32..48].try_into().unwrap()),
            });
        }
        if !same_gtk {
            keys.push(Key {
                id: KeyId {
                    pairwise: false,
                    index,
                },
                peer: self.peer,
                cipher: Cipher::Ccmp128,
                receive_counter: packet.rsc,
                bytes: gtk.clone(),
            });
        }
        self.ack = reply(
            &packet,
            2 | MIC | SECURE | if pairwise { PAIRWISE } else { 0 },
            &[0; 32],
            &[],
            &ptk[..16],
        );
        self.replay = Some(packet.replay);
        self.last_packet = packet.bytes.to_vec();
        self.installed_gtk = Some((index, gtk));
        if !keys.is_empty() {
            self.phase = if pairwise {
                Phase::Installing
            } else {
                Phase::GroupInstalling
            };
            Ok(Exchange { reply: None, keys })
        } else {
            Ok(Exchange {
                reply: if self.phase == Phase::Complete {
                    Some(self.ack.clone())
                } else {
                    None
                },
                keys,
            })
        }
    }
    /// Called only after every returned key has been acknowledged by hardware.
    /// Duplicate message 3/group messages never install a key or reset its PN.
    pub fn installed(&mut self) -> Result<Vec<u8>> {
        if !matches!(self.phase, Phase::Installing | Phase::GroupInstalling) {
            return Err(Error::State);
        }
        self.phase = Phase::Complete;
        Ok(self.ack.clone())
    }
    pub fn complete(&self) -> bool {
        self.phase == Phase::Complete
    }
}

#[cfg(test)]
mod tests;
