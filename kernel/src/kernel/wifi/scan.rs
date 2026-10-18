//! Bounded 802.11 discovery, shared by native radio drivers and guest ABIs.
use alloc::{string::String, vec::Vec};
use core::fmt::Write;

pub const MAX_NETWORKS: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Network {
    pub bssid: [u8; 6],
    pub ssid: Vec<u8>,
    pub frequency: u32,
    pub signal_dbm: i32,
    pub privacy: bool,
    /// Keep the complete RSN IE for later cipher/AKM negotiation. Presence
    /// alone does not establish that the network supports a particular WPA.
    pub rsn: Vec<u8>,
    pub wpa: Vec<u8>,
    /// Complete information elements for future rate/cipher negotiation.
    pub ies: Vec<u8>,
    pub capability: u16,
    pub beacon_interval: u16,
}
impl Network {
    /// Parse beacons and probe responses only. Malformed over-the-air input
    /// must be discarded without bringing down the control transport.
    pub fn from_management(frame: &[u8], frequency: u32, signal_dbm: i32) -> Option<Self> {
        if frame.len() < 36
            || frame.len() > 4096
            || !matches!(frame[0], 0x80 | 0x50)
            || frame[1] & 0x47 != 0
            || frame[22] & 0x0f != 0
            || !(2300..=7125).contains(&frequency)
        {
            return None;
        }
        let bssid: [u8; 6] = frame[16..22].try_into().ok()?;
        if bssid == [0; 6] || bssid[0] & 1 != 0 {
            return None;
        }
        let mut ssid = None;
        let mut rsn = Vec::new();
        let mut wpa = Vec::new();
        let mut ies = &frame[36..];
        while !ies.is_empty() {
            let (&kind, rest) = ies.split_first()?;
            let (&length, rest) = rest.split_first()?;
            let value = rest.get(..usize::from(length))?;
            ies = &rest[usize::from(length)..];
            match kind {
                0 => {
                    if ssid.is_some() || value.len() > 32 {
                        return None;
                    }
                    ssid = Some(if value.iter().all(|b| *b == 0) {
                        Vec::new()
                    } else {
                        value.to_vec()
                    });
                }
                48 => {
                    if !rsn.is_empty() || value.len() < 2 || value[..2] != [1, 0] {
                        return None;
                    }
                    rsn = value.to_vec();
                }
                221 if value.starts_with(&[0x00, 0x50, 0xf2, 1]) => {
                    wpa = value.to_vec();
                }
                _ => {}
            }
        }
        let capability = u16::from_le_bytes(frame[34..36].try_into().ok()?);
        Some(Self {
            bssid,
            ssid: ssid?,
            frequency,
            signal_dbm,
            privacy: capability & 0x10 != 0,
            rsn,
            wpa,
            ies: frame[36..].to_vec(),
            capability,
            beacon_interval: u16::from_le_bytes(frame[32..34].try_into().ok()?),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Starting,
    Running,
    Complete,
    Failed(u32),
}

pub struct Survey {
    pub phase: Phase,
    pub networks: Vec<Network>,
    pub dropped: usize,
}
impl Survey {
    pub const fn new() -> Self {
        Self {
            phase: Phase::Idle,
            networks: Vec::new(),
            dropped: 0,
        }
    }
    pub fn begin(&mut self) {
        self.phase = Phase::Starting;
        self.networks.clear();
        self.dropped = 0;
    }
    pub fn observe(&mut self, mut network: Network) {
        if !matches!(self.phase, Phase::Starting | Phase::Running) {
            return;
        }
        if let Some(old) = self
            .networks
            .iter_mut()
            .find(|old| old.bssid == network.bssid && old.frequency == network.frequency)
        {
            if network.ssid.is_empty() {
                network.ssid = old.ssid.clone();
            }
            *old = network;
        } else if self.networks.len() < MAX_NETWORKS {
            self.networks.push(network);
        } else {
            self.dropped = self.dropped.saturating_add(1);
        }
    }
    pub fn text(&self) -> String {
        let mut text = String::new();
        let _ = match self.phase {
            Phase::Idle => writeln!(text, "Scan: idle"),
            Phase::Starting => writeln!(text, "Scan: starting"),
            Phase::Running => writeln!(text, "Scan: running"),
            Phase::Complete => writeln!(text, "Scan: complete"),
            Phase::Failed(reason) => writeln!(text, "Scan: failed ({reason})"),
        };
        let _ = writeln!(text, "Networks: {}", self.networks.len());
        for n in &self.networks {
            let _ = write!(
                text,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} {} MHz {} dBm {} \"",
                n.bssid[0],
                n.bssid[1],
                n.bssid[2],
                n.bssid[3],
                n.bssid[4],
                n.bssid[5],
                n.frequency,
                n.signal_dbm,
                if !n.rsn.is_empty() {
                    "RSN"
                } else if !n.wpa.is_empty() {
                    "WPA"
                } else if n.privacy {
                    "protected"
                } else {
                    "open"
                }
            );
            for &byte in &n.ssid {
                if (0x20..=0x7e).contains(&byte) && !matches!(byte, b'"' | b'\\') {
                    text.push(char::from(byte));
                } else {
                    let _ = write!(text, "\\x{byte:02x}");
                }
            }
            let _ = writeln!(text, "\"");
        }
        if self.dropped != 0 {
            let _ = writeln!(text, "Additional observations dropped: {}", self.dropped);
        }
        text
    }
}
impl Default for Survey {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    fn beacon(ssid: &[u8]) -> Vec<u8> {
        let mut frame = vec![0; 36];
        frame[0] = 0x80;
        frame[16..22].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
        frame.extend_from_slice(&[0, ssid.len() as u8]);
        frame.extend_from_slice(ssid);
        frame
    }
    #[test]
    fn discovery_validates_frames_and_preserves_binary_ssids() {
        let frame = beacon(b"a\n\xff");
        let n = Network::from_management(&frame, 2412, -51).unwrap();
        let mut survey = Survey::new();
        survey.begin();
        survey.observe(n);
        assert!(survey.text().contains("a\\x0a\\xff"));
        for len in 0..frame.len() {
            assert!(Network::from_management(&frame[..len], 2412, -51).is_none());
        }
        let mut bad = frame.clone();
        bad[1] = 0x40;
        assert!(Network::from_management(&bad, 2412, -51).is_none());
        let mut bad = frame.clone();
        bad.extend_from_slice(&[0, 0]);
        assert!(Network::from_management(&bad, 2412, -51).is_none());
    }
    #[test]
    fn hidden_beacons_do_not_erase_revealed_names_and_cache_is_bounded() {
        let mut survey = Survey::new();
        survey.begin();
        survey.observe(Network::from_management(&beacon(b"test"), 2412, -50).unwrap());
        survey.observe(Network::from_management(&beacon(b""), 2412, -60).unwrap());
        assert_eq!(survey.networks.len(), 1);
        assert_eq!(survey.networks[0].ssid, b"test");
        for id in 0..200 {
            let mut n = survey.networks[0].clone();
            n.bssid[5] = id;
            survey.observe(n);
        }
        assert_eq!(survey.networks.len(), MAX_NETWORKS);
        assert!(survey.dropped > 0);
        survey.begin();
        assert!(survey.networks.is_empty());
    }
}
