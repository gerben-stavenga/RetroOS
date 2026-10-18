// SPDX-License-Identifier: BSD-3-Clause-Clear
// Wire formats reference Linux ath12k htc.h/htc.c (no Linux runtime).
// Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
// Copyright (c) 2021-2023 Qualcomm Innovation Center, Inc. All rights reserved.
//! Qualcomm HTC control negotiation and endpoint credit flow control.
use alloc::vec::Vec;

pub const WMI_CONTROL: u16 = 0x100;
pub const HTT_DATA: u16 = 0x300;
const ENDPOINTS: usize = 16;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Packet,
    State,
    Full,
    Rejected(u8),
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
pub struct Frame<'a> {
    pub endpoint: u8,
    pub payload: &'a [u8],
    trailer: &'a [u8],
}
impl<'a> Frame<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let header = word(bytes, 0)?;
        let control = word(bytes, 4)?;
        let endpoint = header as u8;
        let flags = (header >> 8) as u8;
        let length = (header >> 16) as usize;
        if endpoint as usize >= ENDPOINTS || flags & 0xf0 != 0 {
            return Err(Error::Packet);
        }
        let payload = bytes.get(8..8 + length).ok_or(Error::Packet)?;
        let trailer = if flags & 2 != 0 {
            (control & 255) as usize
        } else {
            0
        };
        if trailer > length || (flags & 2 != 0 && trailer < 4) {
            return Err(Error::Packet);
        }
        Ok(Self {
            endpoint,
            payload: &payload[..length - trailer],
            trailer: &payload[length - trailer..],
        })
    }
}
fn frame(endpoint: u8, sequence: u8, credit: bool, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > 2040 {
        return Err(Error::Packet);
    }
    let mut bytes = Vec::new();
    let header = u32::from(endpoint) | (u32::from(credit) << 8) | ((payload.len() as u32) << 16);
    bytes.extend_from_slice(&header.to_le_bytes());
    bytes.extend_from_slice(&(u32::from(sequence) << 8).to_le_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}
#[derive(Clone, Copy, Default)]
struct Endpoint {
    service: u16,
    credits: u16,
    sequence: u8,
    max_message: u16,
    flow: bool,
}
pub struct Prepared {
    pub bytes: Vec<u8>,
    endpoint: u8,
    sequence: u8,
    credits: u16,
}
pub struct State {
    endpoints: [Endpoint; ENDPOINTS],
    pending: Option<(u16, u16)>,
    pub ready: bool,
    pub credit_size: u16,
    credits: u16,
    max_endpoints: usize,
}
impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
impl State {
    pub fn new() -> Self {
        Self {
            endpoints: [Endpoint::default(); ENDPOINTS],
            pending: None,
            ready: false,
            credit_size: 0,
            credits: 0,
            max_endpoints: 0,
        }
    }
    pub fn endpoint(&self, service: u16) -> Option<u8> {
        self.endpoints
            .iter()
            .position(|ep| ep.service == service && service != 0)
            .map(|n| n as u8)
    }
    fn control(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let sequence = self.endpoints[0].sequence;
        let bytes = frame(0, sequence, false, payload)?;
        self.endpoints[0].sequence = sequence.wrapping_add(1);
        Ok(bytes)
    }
    pub fn connect(&mut self, service: u16) -> Result<Vec<u8>> {
        if !self.ready
            || self.pending.is_some()
            || self.endpoint(service).is_some()
            || !matches!(service, WMI_CONTROL | HTT_DATA)
        {
            return Err(Error::State);
        }
        let allocation = if service == WMI_CONTROL {
            self.credits.min(255)
        } else {
            0
        };
        let flags = (u32::from(allocation) << 8) | if service == WMI_CONTROL { 0 } else { 8 };
        let mut payload = Vec::new();
        payload.extend_from_slice(&(2 | (u32::from(service) << 16)).to_le_bytes());
        payload.extend_from_slice(&flags.to_le_bytes());
        let bytes = self.control(&payload)?;
        self.pending = Some((service, allocation));
        Ok(bytes)
    }
    pub fn setup_complete(&mut self) -> Result<Vec<u8>> {
        if self.pending.is_some()
            || self.endpoint(WMI_CONTROL).is_none()
            || self.endpoint(HTT_DATA).is_none()
        {
            return Err(Error::State);
        }
        let mut payload = Vec::new();
        for value in [5u32, 0, 0] {
            payload.extend_from_slice(&value.to_le_bytes());
        }
        self.control(&payload)
    }
    pub fn prepare(&self, service: u16, payload: &[u8]) -> Result<Prepared> {
        let endpoint = self.endpoint(service).ok_or(Error::State)?;
        let ep = &self.endpoints[endpoint as usize];
        if payload.len() > ep.max_message as usize {
            return Err(Error::Packet);
        }
        let credits = if ep.flow {
            (payload.len() + 8).div_ceil(self.credit_size as usize) as u16
        } else {
            0
        };
        if credits > ep.credits {
            return Err(Error::Full);
        }
        Ok(Prepared {
            bytes: frame(endpoint, ep.sequence, ep.flow, payload)?,
            endpoint,
            sequence: ep.sequence,
            credits,
        })
    }
    /// Commit only after the packet has been enqueued by the underlying transport.
    pub fn commit(&mut self, packet: &Prepared) -> Result<()> {
        let ep = &mut self.endpoints[packet.endpoint as usize];
        if ep.sequence != packet.sequence || ep.credits < packet.credits {
            return Err(Error::State);
        }
        ep.sequence = ep.sequence.wrapping_add(1);
        ep.credits -= packet.credits;
        Ok(())
    }
    pub fn receive<'a>(&mut self, bytes: &'a [u8]) -> Result<Option<Frame<'a>>> {
        let frame = Frame::parse(bytes)?;
        let mut trailer = frame.trailer;
        // Validate the complete trailer before applying credit updates.
        let mut grants = [0u16; ENDPOINTS];
        while !trailer.is_empty() {
            let header = trailer.get(..4).ok_or(Error::Packet)?;
            let length = header[1] as usize;
            let values = trailer.get(4..4 + length).ok_or(Error::Packet)?;
            if header[0] == 1 {
                if length == 0 || !length.is_multiple_of(4) {
                    return Err(Error::Packet);
                }
                for value in values.chunks_exact(4) {
                    if value[0] as usize >= ENDPOINTS {
                        return Err(Error::Packet);
                    }
                    let grant = &mut grants[value[0] as usize];
                    *grant = grant
                        .checked_add(u16::from(value[1]))
                        .ok_or(Error::Packet)?;
                }
            }
            trailer = &trailer[4 + length..];
        }
        for (ep, grant) in self.endpoints.iter().zip(grants) {
            ep.credits.checked_add(grant).ok_or(Error::Packet)?;
        }
        for (ep, grant) in self.endpoints.iter_mut().zip(grants) {
            ep.credits += grant;
        }
        if frame.payload.is_empty() {
            return Ok(None);
        }
        if frame.endpoint != 0 {
            if self.endpoints[frame.endpoint as usize].service == 0 {
                return Err(Error::State);
            }
            return Ok(Some(frame));
        }
        let first = word(frame.payload, 0)?;
        match first & 0xffff {
            1 => {
                if self.ready {
                    return Err(Error::State);
                }
                let second = word(frame.payload, 4)?;
                let credits = (first >> 16) as u16;
                let credit_size = second as u16;
                let endpoints = ((second >> 16) & 255) as usize;
                if credits == 0 || credit_size == 0 || !(2..=ENDPOINTS).contains(&endpoints) {
                    return Err(Error::Packet);
                }
                self.credits = credits;
                self.credit_size = credit_size;
                self.max_endpoints = endpoints;
                self.ready = true;
            }
            3 => {
                if frame.payload.len() < 12 {
                    return Err(Error::Packet);
                }
                let (service, allocation) = self.pending.ok_or(Error::State)?;
                let value = word(frame.payload, 4)?;
                let endpoint = ((value >> 8) & 255) as usize;
                if first >> 16 != u32::from(service) {
                    return Err(Error::State);
                }
                if value & 255 != 0 {
                    return Err(Error::Rejected(value as u8));
                }
                if endpoint == 0
                    || endpoint >= self.max_endpoints
                    || self.endpoints[endpoint].service != 0
                    || value >> 16 == 0
                {
                    return Err(Error::Packet);
                }
                self.endpoints[endpoint] = Endpoint {
                    service,
                    credits: allocation,
                    sequence: 0,
                    max_message: (value >> 16) as u16,
                    flow: service == WMI_CONTROL,
                };
                self.pending = None;
            }
            _ => return Err(Error::State),
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests;
