// SPDX-License-Identifier: BSD-3-Clause-Clear
// Startup fields reference Linux v6.8 ath12k wmi.c/h.
// Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
// Copyright (c) 2021-2023 Qualcomm Innovation Center, Inc. All rights reserved.
//! Shared WMI startup, regulatory reports, station configuration and scanning.
use alloc::vec::Vec;
pub mod radio;
pub mod regulatory;
pub mod scan;
pub mod station;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Packet,
    State,
    Firmware(u32),
}
pub type Result<T> = core::result::Result<T, Error>;
fn word(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .ok_or(Error::Packet)?
            .try_into()
            .unwrap(),
    ))
}
pub fn tlvs(mut bytes: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut values = Vec::new();
    while !bytes.is_empty() {
        let header = word(bytes, 0)?;
        let length = (header & 0xffff) as usize;
        values.push((
            (header >> 16) as u16,
            bytes.get(4..4 + length).ok_or(Error::Packet)?,
        ));
        bytes = &bytes[4 + length..];
    }
    Ok(values)
}
fn required<'a>(values: &[(u16, &'a [u8])], tag: u16) -> Result<&'a [u8]> {
    let mut found = values.iter().filter(|(kind, _)| *kind == tag);
    let value = found.next().ok_or(Error::Packet)?.1;
    if found.next().is_some() {
        return Err(Error::Packet);
    }
    Ok(value)
}

fn log_rejected_packet(bytes: &[u8]) {
    let captured = &bytes[..bytes.len().min(2048)];
    crate::compact_println!(
        "WiFi: rejected WMI bytes={} captured={}",
        bytes.len(),
        captured.len()
    );
    for (index, chunk) in captured.chunks(16).enumerate() {
        let mut words = [0u32; 4];
        for (at, byte) in chunk.iter().enumerate() {
            words[at / 4] |= u32::from(*byte) << (8 * (at % 4));
        }
        crate::compact_println!(
            "WiFi: rejected WMI +{:04x}: {:08x} {:08x} {:08x} {:08x}",
            index * 16,
            words[0],
            words[1],
            words[2],
            words[3]
        );
    }
}
pub fn tlv(out: &mut Vec<u8>, tag: u16, value: &[u8]) -> Result<()> {
    if value.len() > u16::MAX as usize {
        return Err(Error::Packet);
    }
    out.extend_from_slice(&((u32::from(tag) << 16) | value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
    Ok(())
}
pub struct State {
    service: bool,
    extended: bool,
    extended2: bool,
    init_sent: bool,
    services: [bool; 384],
    chains: u32,
    pub ready: bool,
    pub mac: [u8; 6],
    pub regulatory: Vec<regulatory::Report>,
    events: alloc::collections::VecDeque<scan::Event>,
    pub management_stats: ManagementStats,
    pub rfkill_supported: bool,
    pub radio_on: Option<bool>,
}
#[derive(Clone, Copy, Default)]
pub struct ManagementStats {
    pub received: u32,
    pub decoded: u32,
    pub ignored: u32,
    pub malformed: u32,
    pub queue_dropped: u32,
}
impl ManagementStats {
    pub fn log(&self) {
        crate::compact_println!(
            "WiFi: management RX={} decoded={} ignored={} malformed={} queue-dropped={}",
            self.received,
            self.decoded,
            self.ignored,
            self.malformed,
            self.queue_dropped
        );
    }
}
impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
impl State {
    pub fn new() -> Self {
        Self {
            service: false,
            extended: false,
            extended2: false,
            init_sent: false,
            services: [false; 384],
            chains: 0,
            ready: false,
            mac: [0; 6],
            regulatory: Vec::new(),
            events: alloc::collections::VecDeque::new(),
            management_stats: ManagementStats::default(),
            rfkill_supported: false,
            radio_on: None,
        }
    }
    pub fn services_ready(&self) -> bool {
        self.service
            && (!self.services[77] || self.extended)
            && (!self.services[220] || self.extended2)
    }
    pub fn receive(&mut self, bytes: &[u8]) -> Result<()> {
        let id = word(bytes, 0)? & 0x00ff_ffff;
        let values = tlvs(&bytes[4..])?;
        if !matches!(id, 0x7001 | 0x1d011) {
            crate::compact_println!("WiFi: WMI event={:06x} bytes={}", id, bytes.len());
        }
        if !self.ready {
            for (tag, value) in &values {
                crate::compact_println!(
                    "WiFi: WMI TLV tag={} bytes={}",
                    u32::from(*tag),
                    value.len()
                );
            }
        }
        if let Some(event) = station::event(id, &values)? {
            if self.events.len() >= 64 {
                return Err(Error::State);
            }
            self.events.push_back(scan::Event::Station(event));
        }
        match id {
            0x1e004 => {
                let event = required(&values, 231)?;
                let state = word(event, 8)?;
                if !matches!(state, 1 | 2) {
                    return Err(Error::Packet);
                }
                self.radio_on = Some(state == 2);
                crate::compact_println!(
                    "WiFi: RF-kill GPIO={} radio={}",
                    word(event, 0)?,
                    if state == 2 { "on" } else { "off" }
                );
            }
            0x3001 => {
                let event = scan::ScanEvent::parse(&values)?;
                crate::compact_println!(
                    "WiFi: scan event={} reason={} id={:04x} vdev={} frequency={}",
                    event.kind,
                    event.reason,
                    event.scan,
                    event.vdev,
                    event.frequency
                );
                if self.events.len() < 64 {
                    self.events.push_back(scan::Event::Scan(event));
                }
            }
            0x7001 => {
                // Bad RF input is local to this frame, not a fatal firmware
                // transport error. Bound queued observations if the consumer
                // is temporarily busy sending another control command.
                let stats = &mut self.management_stats;
                stats.received = stats.received.saturating_add(1);
                if stats.received == 1 {
                    for (tag, value) in &values {
                        crate::compact_println!(
                            "WiFi: management TLV tag={} bytes={}",
                            u32::from(*tag),
                            value.len()
                        );
                    }
                }
                if let Ok(Some((frame, _, _))) = scan::management_frame(&values)
                    && matches!(frame.first(), Some(0xb0 | 0x10 | 0xa0 | 0xc0))
                    && self.events.len() < 64
                {
                    self.events
                        .push_back(scan::Event::Station(station::Event::Management(
                            frame.to_vec(),
                        )));
                }
                match scan::management(&values) {
                    Ok(Some(network)) => {
                        stats.decoded = stats.decoded.saturating_add(1);
                        if self.events.len() < 64 {
                            self.events.push_back(scan::Event::Network(network));
                        } else {
                            stats.queue_dropped = stats.queue_dropped.saturating_add(1);
                        }
                    }
                    Ok(None) => {
                        stats.ignored = stats.ignored.saturating_add(1);
                    }
                    Err(_) => {
                        if stats.malformed == 0 {
                            log_rejected_packet(bytes);
                        }
                        stats.malformed = stats.malformed.saturating_add(1);
                    }
                }
            }
            1 => {
                if self.service {
                    return Err(Error::State);
                }
                let event = required(&values, 32)?;
                let chains = word(event, 9 * 4)?;
                crate::compact_println!("WiFi: WMI RF chains={}", chains);
                if !(1..=8).contains(&chains) {
                    return Err(Error::Packet);
                }
                let memory = word(event, 18 * 4)?;
                if memory != 0 {
                    crate::compact_println!(
                        "WiFi: unsupported WMI host memory requests={}",
                        memory
                    );
                    return Err(Error::State);
                }
                // ARRAY_UINT32 is an array type, not a unique field ID. The
                // first array is the service bitmap; later arrays describe
                // other capabilities (ath12k_wmi_svc_rdy_parse uses the same
                // positional rule). Keep fixed-event TLVs unique.
                let bitmap = values
                    .iter()
                    .find(|(tag, _)| *tag == 16)
                    .ok_or(Error::Packet)?
                    .1;
                if bitmap.len() < 32 * 4 {
                    return Err(Error::Packet);
                }
                for service in 0..128 {
                    self.services[service] |=
                        word(bitmap, service / 4 * 4)? & (1 << (service % 4)) != 0;
                }
                self.chains = chains;
                self.rfkill_supported = word(event, 15 * 4)? & 2 != 0;
                self.service = true;
                crate::compact_println!(
                    "WiFi: WMI service ready build={:08x} RF chains={}",
                    word(event, 0)?,
                    chains
                );
            }
            3 => {
                let event = required(&values, 559)?;
                if event.len() < 20 {
                    return Err(Error::Packet);
                }
                for service in 128..256 {
                    self.services[service] |=
                        word(event, 4 + (service - 128) / 32 * 4)? & (1 << (service % 32)) != 0;
                }
                if let Some((_, bitmap)) = values.iter().find(|(tag, _)| *tag == 16) {
                    if bitmap.len() < 16 {
                        return Err(Error::Packet);
                    }
                    for service in 256..384 {
                        self.services[service] |=
                            word(bitmap, (service - 256) / 32 * 4)? & (1 << (service % 32)) != 0;
                    }
                }
            }
            0x4009 => {
                required(&values, 428)?;
                self.extended = true;
            }
            0x4022 => {
                required(&values, 820)?;
                self.extended2 = true;
            }
            0x16005 => {
                let event = required(&values, 397)?;
                crate::compact_println!(
                    "WiFi: WMI firmware dump notification={:08x} {:08x}",
                    word(event, 0)?,
                    word(event, 4)?
                );
            }
            0x3a003 => {
                let report = regulatory::Report::parse(&values).inspect_err(|_| {
                    if let Ok(fixed) = required(&values, 938)
                        && fixed.len() >= 78 * 4 {
                            crate::compact_println!("WiFi: invalid regulatory report status={} PHY={} PHYs={} country={:02x}{:02x} 2G={} 5G={}",
                                word(fixed, 0).unwrap_or(u32::MAX), word(fixed, 4).unwrap_or(u32::MAX),
                                word(fixed, 12).unwrap_or(u32::MAX), fixed[8], fixed[9],
                                word(fixed, 48).unwrap_or(u32::MAX), word(fixed, 52).unwrap_or(u32::MAX));
                    }
                    log_rejected_packet(bytes);
                })?;
                crate::compact_println!(
                    "WiFi: regulatory PHY={} country={}{} rules={}",
                    report.phy,
                    report.country[0] as char,
                    report.country[1] as char,
                    report.rules.len()
                );
                crate::compact_println!(
                    "WiFi: regulatory extension arrays={}",
                    report.extensions.len()
                );
                if let Some(old) = self.regulatory.iter_mut().find(|old| old.phy == report.phy) {
                    *old = report;
                } else {
                    self.regulatory.push(report);
                }
            }
            2 => {
                if !self.init_sent || self.ready {
                    return Err(Error::State);
                }
                let event = required(&values, 35)?;
                let status = word(event, 32)?;
                if status != 0 {
                    return Err(Error::Firmware(status));
                }
                let mac = event.get(24..30).ok_or(Error::Packet)?;
                if mac[0] & 1 != 0 || mac == [0; 6] {
                    return Err(Error::Packet);
                }
                self.mac.copy_from_slice(mac);
                self.ready = true;
            }
            _ => {}
        }
        Ok(())
    }
    pub fn rf_chains(&self) -> u32 {
        self.chains
    }
    pub fn next_event(&mut self) -> Option<scan::Event> {
        self.events.pop_front()
    }
    pub fn initialize_command(&self, resources: &[u32]) -> Result<Vec<u8>> {
        if !self.services_ready() || self.init_sent {
            return Err(Error::State);
        }
        // Single-pdev startup: no hardware-mode override and no WMI memory
        // chunks (firmware memory was supplied through WLANFW QMI).
        crate::compact_println!(
            "WiFi: WMI extended regulatory support={}",
            self.services[281]
        );
        let mut bytes = 1u32.to_le_bytes().to_vec();
        tlv(&mut bytes, 74, &[0; 28])?; // ABI negotiation fields and num_host_mem_chunks
        if resources.is_empty()
            || resources[0] >> 16 != 75
            || resources[0] & 0xffff != ((resources.len() - 1) * 4) as u32
            || (self.services[281] && resources.len() < 70)
        {
            return Err(Error::Packet);
        }
        for (index, value) in resources.iter().enumerate() {
            // Firmware advertises extended regulatory events as service 281;
            // acknowledge their receive support in host_service_flags.
            let mut value = *value;
            if index == 69 && self.services[281] {
                value |= 1 << 4;
            }
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        tlv(&mut bytes, 18, &[])?; // empty host memory chunk array
        Ok(bytes)
    }
    pub fn mark_init_sent(&mut self) -> Result<()> {
        if !self.services_ready() || self.init_sent {
            return Err(Error::State);
        }
        self.init_sent = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
