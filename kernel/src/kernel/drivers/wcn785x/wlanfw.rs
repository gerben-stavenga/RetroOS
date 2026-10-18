// SPDX-License-Identifier: BSD-3-Clause-Clear
// WLANFW field definitions and startup order reference Linux ath12k qmi.c.
// Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
// Copyright (c) 2021-2023 Qualcomm Innovation Center, Inc. All rights reserved.
//! WLANFW boot RPCs. No RF operation is enabled here: CE/HTC/WMI follow this.
use super::{Dma, hardware::Chip, mhi};
use crate::kernel::drivers::ce;
use crate::kernel::{firmware, qmi, qrtr};
use alloc::{collections::VecDeque, format, string::String, vec::Vec};
use mhi::{Memory, Registers};

const LOCAL_PORT: u32 = 0x4000;
const TIMEOUT: u64 = 10_000_000_000;
const MAX_SPINS: usize = 5_000_000;
const MAX_MEMORY: usize = 48 * 1024 * 1024;
const MAX_BOARD: usize = 256 * 1024;
const CHUNK: usize = 6144;

#[derive(Debug)]
pub(super) enum Error {
    Transport(mhi::Error),
    Qmi(qmi::Error),
    Firmware,
    Memory,
    Board,
    State,
    Htc(crate::kernel::htc::Error),
    Wmi(crate::kernel::wmi::Error),
}
impl From<crate::kernel::htc::Error> for Error {
    fn from(error: crate::kernel::htc::Error) -> Self {
        Self::Htc(error)
    }
}
impl From<crate::kernel::wmi::Error> for Error {
    fn from(error: crate::kernel::wmi::Error) -> Self {
        Self::Wmi(error)
    }
}
impl From<mhi::Error> for Error {
    fn from(error: mhi::Error) -> Self {
        Self::Transport(error)
    }
}
impl From<qmi::Error> for Error {
    fn from(error: qmi::Error) -> Self {
        Self::Qmi(error)
    }
}
impl Error {
    pub(super) fn message(&self) -> String {
        match self {
            Self::Transport(error) => String::from(error.message()),
            Self::Qmi(error) => format!("QMI {:?}", error),
            Self::Firmware => String::from("firmware missing or invalid"),
            Self::Memory => {
                String::from("firmware memory request invalid or DMA allocation failed")
            }
            Self::Board => String::from("board bundle invalid or exact board entry missing"),
            Self::State => String::from("firmware control service lost or invalid state"),
            Self::Htc(error) => format!("HTC {:?}", error),
            Self::Wmi(error) => format!("WMI {:?}", error),
        }
    }
}
type Result<T> = core::result::Result<T, Error>;

pub(super) struct Boot {
    pub memory: Vec<HostMemory>,
    pub ce: ce::Engine<Dma>,
    pub dump: mhi::dump::CrashDump<Dma>,
    pub cmem: Option<(u64, u64)>,
    pub topology: Option<FirmwareTopology>,
}

fn diagnostic_request(address: u32, memory_type: u32, bytes: u32) -> Result<Vec<u8>> {
    if bytes == 0
        || bytes > 512
        || !bytes.is_multiple_of(4)
        || !address.is_multiple_of(4)
        || address.checked_add(bytes).is_none()
    {
        return Err(Error::State);
    }
    let mut body = Vec::new();
    for (tag, value) in [(1, address), (2, memory_type), (3, bytes)] {
        qmi::tlv(&mut body, tag, &value.to_le_bytes())?;
    }
    Ok(body)
}
fn diagnostic_response<'a>(message: &qmi::Message<'a>, requested: u32) -> Result<&'a [u8]> {
    let data = message.required(0x10)?;
    let length = data.get(..2).ok_or(qmi::Error::Packet)?;
    let length = u16::from_le_bytes(length.try_into().unwrap()) as usize;
    if length != requested as usize || data.len() != length + 2 {
        return Err(Error::Qmi(qmi::Error::Packet));
    }
    Ok(&data[2..])
}
fn log_diagnostic(address: u32, bytes: &[u8]) {
    crate::compact_println!(
        "WiFi: diagnostic address={:08x} bytes={}",
        address,
        bytes.len()
    );
    for (index, chunk) in bytes.chunks_exact(16).enumerate() {
        crate::compact_println!(
            "WiFi: diagnostic {:08x}: {:08x} {:08x} {:08x} {:08x}",
            address + index as u32 * 16,
            word(&chunk[..4]).unwrap(),
            word(&chunk[4..8]).unwrap(),
            word(&chunk[8..12]).unwrap(),
            word(&chunk[12..]).unwrap()
        );
    }
    let mut start = 0;
    for end in 0..=bytes.len() {
        if end == bytes.len() || !(bytes[end].is_ascii_graphic() || bytes[end] == b' ') {
            if end - start >= 4 {
                let text = core::str::from_utf8(&bytes[start..end]).unwrap();
                crate::compact_println!(
                    "WiFi: diagnostic text {:08x}: {}",
                    address + start as u32,
                    text
                );
            }
            start = end + 1;
        }
    }
}

pub(super) struct HostMemory<M = Dma> {
    pub region: M,
    pub kind: u32,
    pub bytes: usize,
}

/// Keep the raw RDDM image at offset zero. Append host DDR (QMI type 1)
/// and any single-chip MLO memory (type 8), absent from the SRAM sections.
/// The footer locates a versioned table: count:u32, then kind:u32, bytes:u32,
/// physical:u64 for each region, followed by the region bytes in table order.
/// Optional host CE storage uses private kind 0x100, not a WLANFW memory type.
pub(super) fn append_paging_dump<M: Memory>(
    dump: &mut Vec<u8>,
    memory: &[HostMemory<M>],
    ce: Option<(u64, &[u8])>,
) {
    let start = dump.len() as u64;
    let regions = memory.iter().filter(|region| matches!(region.kind, 1 | 8));
    dump.extend_from_slice(b"RTWFPAGE");
    dump.extend_from_slice(&1u32.to_le_bytes());
    dump.extend_from_slice(
        &((regions.clone().count() + usize::from(ce.is_some())) as u32).to_le_bytes(),
    );
    for region in regions.clone() {
        dump.extend_from_slice(&region.kind.to_le_bytes());
        dump.extend_from_slice(&(region.bytes as u32).to_le_bytes());
        dump.extend_from_slice(&region.region.physical().to_le_bytes());
    }
    if let Some((physical, bytes)) = ce {
        // Private trailer kind, outside WLANFW's memory-type namespace.
        dump.extend_from_slice(&0x100u32.to_le_bytes());
        dump.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        dump.extend_from_slice(&physical.to_le_bytes());
    }
    for region in regions {
        dump.extend_from_slice(&region.region.copy_out(0, region.bytes));
    }
    if let Some((_, bytes)) = ce {
        dump.extend_from_slice(bytes);
    }
    dump.extend_from_slice(b"RTWFEND1");
    dump.extend_from_slice(&start.to_le_bytes());
}

fn wlan_configuration(config: ce::Config, shadows: &[u32]) -> Result<Vec<u8>> {
    if config.target.len() > 12
        || config.services.len() > 24
        || shadows.len() > 60
        || shadows.iter().enumerate().any(|(index, value)| {
            !value.is_multiple_of(4)
                || !(0x100..=0x01ff_fffc).contains(value)
                || shadows[..index].contains(value)
        })
    {
        return Err(Error::State);
    }
    let mut body = Vec::new();
    // Firmware compatibility identifier used by ath12k; not an OS personality.
    qmi::tlv(&mut body, 0x10, b"WIN")?;
    let mut pipes = Vec::new();
    pipes.push(config.target.len() as u8);
    for record in config.target {
        for word in record {
            pipes.extend_from_slice(&word.to_le_bytes());
        }
    }
    qmi::tlv(&mut body, 0x11, &pipes)?;
    let mut services = Vec::new();
    services.push(config.services.len() as u8);
    for record in config.services {
        for word in record {
            services.extend_from_slice(&word.to_le_bytes());
        }
    }
    qmi::tlv(&mut body, 0x12, &services)?;
    if !shadows.is_empty() {
        let mut values = Vec::new();
        values.push(shadows.len() as u8);
        for value in shadows {
            values.extend_from_slice(&value.to_le_bytes());
        }
        qmi::tlv(&mut body, 0x17, &values)?;
    }
    Ok(body)
}

struct Session<'a, R, M> {
    transport: &'a mut mhi::Transport<R, M>,
    router: &'a mut qrtr::Router,
    client: qmi::Client,
    indications: VecDeque<Vec<u8>>,
    response: Option<Vec<u8>>,
}
impl<'a, R: Registers, M: Memory> Session<'a, R, M> {
    fn now(&mut self) -> u64 {
        self.transport.io.now()
    }
    fn pump(&mut self) -> Result<()> {
        self.transport.poll()?;
        for _ in 0..32 {
            let Some(bytes) = self.transport.receive() else {
                break;
            };
            for reply in self.router.receive(&bytes).map_err(|_| Error::State)? {
                self.transport.send(&reply)?;
            }
            let Some(payload) = self
                .router
                .data_payload(&bytes, LOCAL_PORT)
                .map_err(|_| Error::State)?
            else {
                continue;
            };
            if let Some(message) = self.client.receive(payload)? {
                match message.kind {
                    qmi::RESPONSE => {
                        if self.response.is_some() {
                            return Err(Error::State);
                        }
                        self.response = Some(payload.to_vec());
                    }
                    qmi::INDICATION => {
                        crate::compact_println!("WiFi: QMI indication={:04x}", message.id);
                        if matches!(message.id, 0x35 | 0x37 | 0x38) {
                            if self.indications.len() >= 16 {
                                return Err(Error::State);
                            }
                            self.indications.push_back(payload.to_vec());
                        }
                    }
                    _ => return Err(Error::State),
                }
            }
        }
        Ok(())
    }
    fn discover(&mut self) -> Result<(u32, u32)> {
        let deadline = self.now().saturating_add(TIMEOUT);
        for _ in 0..MAX_SPINS {
            self.pump()?;
            if let Some(server) = self.router.server() {
                return Ok(server);
            }
            if self.now() >= deadline {
                break;
            }
            core::hint::spin_loop();
        }
        Err(Error::Qmi(qmi::Error::Timeout))
    }
    fn request(&mut self, id: u16, body: &[u8]) -> Result<Vec<u8>> {
        self.request_timeout(id, body, TIMEOUT)
    }
    fn optional_request(&mut self, id: u16, body: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.request(id, body) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(Error::Qmi(qmi::Error::Remote { result, error })) => {
                // A matched negative reply clears the QMI transaction. Do not
                // hide transport failures or malformed packets as unsupported.
                crate::compact_println!(
                    "WiFi: optional QMI request={:04x} rejected result={} error={}",
                    id,
                    result,
                    error
                );
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
    fn request_timeout(&mut self, id: u16, body: &[u8], timeout: u64) -> Result<Vec<u8>> {
        crate::compact_println!("WiFi: QMI request={:04x} bytes={}", id, body.len());
        let now = self.now();
        let payload = self.client.request(now, timeout, id, body)?;
        let bytes = self
            .router
            .data(LOCAL_PORT, &payload)
            .map_err(|_| Error::State)?;
        self.transport.send(&bytes)?;
        for _ in 0..MAX_SPINS {
            self.pump()?;
            if let Some(bytes) = self.response.take() {
                crate::compact_println!("WiFi: QMI response={:04x} success", id);
                return Ok(bytes);
            }
            let now = self.now();
            self.client.check_timeout(now)?;
            core::hint::spin_loop();
        }
        Err(Error::Qmi(qmi::Error::Timeout))
    }
    fn indication(&mut self, id: u16) -> Result<Vec<u8>> {
        let deadline = self.now().saturating_add(TIMEOUT);
        for _ in 0..MAX_SPINS {
            if let Some(index) = self
                .indications
                .iter()
                .position(|bytes| qmi::Message::parse(bytes).is_ok_and(|message| message.id == id))
            {
                return Ok(self.indications.remove(index).unwrap());
            }
            self.pump()?;
            if self.now() >= deadline {
                break;
            }
            core::hint::spin_loop();
        }
        crate::compact_println!("WiFi: QMI waiting for indication={:04x} timed out", id);
        Err(Error::Qmi(qmi::Error::Timeout))
    }
    fn download(&mut self, board_id: u32, kind: u8, data: &[u8]) -> Result<()> {
        if data.is_empty() || data.len() > MAX_BOARD {
            return Err(Error::Board);
        }
        for (segment, chunk) in data.chunks(CHUNK).enumerate() {
            let body = download_request(board_id, kind, data.len(), segment, chunk)?;
            self.request(0x25, &body)?;
        }
        Ok(())
    }
}

fn registration() -> qmi::Result<Vec<u8>> {
    let mut body = Vec::new();
    qmi::tlv(&mut body, 0x10, &[1])?;
    qmi::tlv(&mut body, 0x15, &0x4b4e454cu32.to_le_bytes())?;
    for tag in [0x16, 0x17, 0x18, 0x1b] {
        qmi::tlv(&mut body, tag, &[1])?;
    }
    Ok(body)
}
fn host_capabilities(topology: Option<FirmwareTopology>) -> qmi::Result<Vec<u8>> {
    let mut body = Vec::new();
    qmi::tlv(&mut body, 0x10, &1u32.to_le_bytes())?; // one client
    qmi::tlv(&mut body, 0x13, &[0x0e])?; // internal sleep clock, host C-state, global reset
    for tag in [0x14, 0x16, 0x17] {
        qmi::tlv(&mut body, tag, &[1])?;
    } // BDF, M3, M3 cache
    qmi::tlv(&mut body, 0x1a, &[0])?; // calibration has not run
    qmi::tlv(&mut body, 0x1c, &[0])?; // default firmware memory mode
    qmi::tlv(&mut body, 0x21, &[u8::from(topology.is_some())])?;
    if let Some(topology) = topology {
        qmi::tlv(&mut body, 0x22, &topology.config.chip_id.to_le_bytes())?;
        qmi::tlv(&mut body, 0x23, &[topology.config.group_id])?;
        qmi::tlv(&mut body, 0x24, &topology.config.peer_limit.to_le_bytes())?;
        qmi::tlv(&mut body, 0x25, &[1])?; // one chip in this firmware group
        // QMI encodes three fixed-size chip records, each with two link IDs
        // and two validity bytes. Unused links and partner chips remain zero.
        let mut chips = [0u8; 18];
        chips[0] = topology.config.chip_id as u8;
        chips[1] = topology.links;
        for link in 0..usize::from(topology.links) {
            chips[2 + link] = link as u8;
            chips[4 + link] = 1;
        }
        qmi::tlv(&mut body, 0x26, &chips)?;
    }
    qmi::tlv(&mut body, 0x27, &0x18u64.to_le_bytes())?; // QDSS config absent; no PERST pull
    Ok(body)
}

#[derive(Debug, PartialEq, Eq)]
struct PhyCapabilities {
    phys: Option<u8>,
    board: Option<u32>,
    single_chip_mlo: Option<bool>,
}

/// Single-chip firmware boot topology, not an association/data-path API.
#[derive(Clone, Copy)]
pub(super) struct FirmwareTopology {
    config: super::hardware::SingleChipMlo,
    links: u8,
}
fn firmware_topology(
    config: Option<super::hardware::SingleChipMlo>,
    phy: &PhyCapabilities,
) -> Result<Option<FirmwareTopology>> {
    let (Some(config), Some(links), Some(true)) = (config, phy.phys, phy.single_chip_mlo) else {
        return Ok(None);
    };
    if !(1..=2).contains(&links) || config.chip_id > u8::MAX as u16 || config.peer_limit == 0 {
        return Err(Error::State);
    }
    Ok(Some(FirmwareTopology { config, links }))
}
fn phy_capabilities(message: &qmi::Message<'_>) -> Result<PhyCapabilities> {
    let byte = |tag| -> Result<Option<u8>> {
        message
            .get(tag)
            .map(|value| {
                if value.len() != 1 {
                    return Err(qmi::Error::Packet.into());
                }
                Ok(value[0])
            })
            .transpose()
    };
    let single_chip_mlo = byte(0x13)?
        .map(|value| match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(qmi::Error::Packet),
        })
        .transpose()?;
    Ok(PhyCapabilities {
        phys: byte(0x10)?,
        board: message.get(0x11).map(word).transpose()?,
        single_chip_mlo,
    })
}
fn firmware_logging() -> qmi::Result<Vec<u8>> {
    let mut body = Vec::new();
    qmi::tlv(&mut body, 0x10, &[1])?;
    Ok(body)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Segment {
    size: u32,
    kind: u32,
}
fn memory_response(segments: &[(Segment, u64)]) -> Result<Vec<u8>> {
    if segments.is_empty() || segments.len() > 52 {
        return Err(Error::Memory);
    }
    let mut encoded = Vec::new();
    encoded.push(segments.len() as u8);
    for (segment, address) in segments {
        encoded.extend_from_slice(&address.to_le_bytes());
        encoded.extend_from_slice(&segment.size.to_le_bytes());
        encoded.extend_from_slice(&segment.kind.to_le_bytes());
        encoded.push(0); // restore=false
    }
    let mut body = Vec::new();
    qmi::tlv(&mut body, 1, &encoded)?;
    Ok(body)
}
fn word(bytes: &[u8]) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| Error::Qmi(qmi::Error::Packet))?,
    ))
}
fn memory_request(message: &qmi::Message<'_>) -> Result<Vec<Segment>> {
    let mut bytes = message.required(1)?;
    let count = *bytes.first().ok_or(qmi::Error::Packet)? as usize;
    if count == 0 || count > 52 {
        return Err(Error::Memory);
    }
    bytes = &bytes[1..];
    let mut segments = Vec::new();
    let mut total = 0usize;
    for _ in 0..count {
        let header = bytes.get(..9).ok_or(qmi::Error::Packet)?;
        let size = word(&header[..4])?;
        let kind = word(&header[4..8])?;
        let configs = header[8] as usize;
        crate::compact_println!(
            "WiFi: QMI memory type={} bytes={} configs={}",
            kind,
            size,
            configs
        );
        if configs > 2 || size == 0 {
            return Err(Error::Memory);
        }
        let config_bytes = bytes.get(9..9 + configs * 9).ok_or(qmi::Error::Packet)?;
        for config in config_bytes.chunks_exact(9) {
            let offset = word(&config[..4])?;
            let length = word(&config[4..8])?;
            if offset.checked_add(length).is_none_or(|end| end > size) || config[8] > 1 {
                return Err(Error::Memory);
            }
        }
        bytes = &bytes[9 + configs * 9..];
        if matches!(kind, 1 | 3 | 4 | 8 | 9) {
            let padded = (size as usize).checked_add(4095).ok_or(Error::Memory)? & !4095;
            total = total.checked_add(padded).ok_or(Error::Memory)?;
            if total > MAX_MEMORY {
                crate::compact_println!(
                    "WiFi: QMI memory bytes={} exceeds host budget={}",
                    total,
                    MAX_MEMORY
                );
                return Err(Error::Memory);
            }
        }
        segments.push(Segment { size, kind });
    }
    if !bytes.is_empty() {
        return Err(Error::Qmi(qmi::Error::Packet));
    }
    Ok(segments)
}

struct Capabilities {
    chip: u32,
    board: u32,
    version: Option<u32>,
    cmem: Option<(u64, u64)>,
}
fn capabilities(message: &qmi::Message<'_>) -> Result<Capabilities> {
    let chip = message.required(0x10)?;
    if chip.len() != 8 {
        return Err(Error::Qmi(qmi::Error::Packet));
    }
    let board = message.get(0x11).map(word).transpose()?.unwrap_or(255);
    let chip_id = word(&chip[..4])?;
    crate::compact_println!(
        "WiFi: QMI chip={} family={} board={}",
        chip_id,
        word(&chip[4..])?,
        board
    );
    if let Some(soc) = message.get(0x12) {
        crate::compact_println!("WiFi: QMI SoC={:08x}", word(soc)?);
    }
    let version = if let Some(version) = message.get(0x13) {
        if version.len() < 4 {
            return Err(Error::Qmi(qmi::Error::Packet));
        }
        crate::compact_println!("WiFi: QMI firmware version={:08x}", word(&version[..4])?);
        Some(word(&version[..4])?)
    } else {
        None
    };
    let cmem = device_memory(message.get(0x1c))?;
    Ok(Capabilities {
        chip: chip_id,
        board,
        version,
        cmem,
    })
}

fn device_memory(bytes: Option<&[u8]>) -> Result<Option<(u64, u64)>> {
    let Some(bytes) = bytes else { return Ok(None) };
    // Four fixed records of u64 address/u64 size; no array count or padding.
    if bytes.len() != 64 {
        return Err(Error::Qmi(qmi::Error::Packet));
    }
    let start = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let size = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    crate::compact_println!("WiFi: QMI CMEM address={:016x} bytes={}", start, size);
    Ok(Some((start, size)))
}

/// Parse a padded ATH12K board bundle without treating it as executable data.
fn ie(bytes: &[u8]) -> Result<(u32, &[u8], &[u8])> {
    let header = bytes.get(..8).ok_or(Error::Board)?;
    let tag = word(&header[..4])?;
    let length = word(&header[4..])? as usize;
    let end = 8usize.checked_add(length).ok_or(Error::Board)?;
    let next = end.checked_add(3).ok_or(Error::Board)? & !3;
    Ok((
        tag,
        bytes.get(8..end).ok_or(Error::Board)?,
        bytes.get(next..).ok_or(Error::Board)?,
    ))
}
fn board_entry<'a>(bytes: &'a [u8], kind: u32, name: &[u8]) -> Result<Option<&'a [u8]>> {
    if !bytes.starts_with(b"QCA-ATH12K-BOARD\0") {
        return Err(Error::Board);
    }
    let mut tail = bytes.get(20..).ok_or(Error::Board)?;
    let mut found = None;
    while !tail.is_empty() {
        let (tag, mut entry, rest) = ie(tail)?;
        tail = rest;
        if tag != kind {
            continue;
        }
        let mut matches = false;
        while !entry.is_empty() {
            let (tag, value, rest) = ie(entry)?;
            entry = rest;
            if tag == 0 {
                // Multiple names can alias the following data entry.
                matches |= value == name;
            } else if tag == 1 {
                if matches {
                    if found.is_some() {
                        return Err(Error::Board);
                    }
                    found = Some(value);
                }
                matches = false;
            }
        }
    }
    Ok(found)
}
fn download_request(
    board: u32,
    kind: u8,
    total: usize,
    segment: usize,
    chunk: &[u8],
) -> Result<Vec<u8>> {
    if total == 0 || total > MAX_BOARD {
        return Err(Error::Board);
    }
    let offset = segment.checked_mul(CHUNK).ok_or(Error::Board)?;
    let remaining = total.checked_sub(offset).ok_or(Error::Board)?;
    if chunk.is_empty() || chunk.len() != remaining.min(CHUNK) {
        return Err(Error::Board);
    }
    let mut body = Vec::new();
    qmi::tlv(&mut body, 1, &[1])?;
    qmi::tlv(&mut body, 0x10, &board.to_le_bytes())?;
    // Firmware expects bytes remaining, including this segment (ath12k).
    qmi::tlv(&mut body, 0x11, &(remaining as u32).to_le_bytes())?;
    qmi::tlv(&mut body, 0x12, &(segment as u32).to_le_bytes())?;
    let mut data = Vec::with_capacity(2 + chunk.len());
    data.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
    data.extend_from_slice(chunk);
    qmi::tlv(&mut body, 0x13, &data)?;
    qmi::tlv(&mut body, 0x14, &[u8::from(chunk.len() == remaining)])?;
    qmi::tlv(&mut body, 0x15, &[kind])?;
    Ok(body)
}

/// Called while Arch is available for requested DMA allocations. All mappings
/// remain reserved for boot lifetime even when a subsequent RPC fails.
pub(super) fn initialize<A: crate::Arch, R: Registers>(
    machine: &mut A,
    transport: &mut mhi::Transport<R, Dma>,
    router: &mut qrtr::Router,
    chip: &Chip,
    subsystem: u32,
    stage: &mut &'static str,
    layout: mhi::Layout,
) -> Result<Boot> {
    let mut session = Session {
        transport,
        router,
        client: qmi::Client::new(),
        indications: VecDeque::new(),
        response: None,
    };
    *stage = "WLANFW service discovery";
    let (node, port) = session.discover()?;
    crate::compact_println!("WiFi: WLANFW control service node={} port={}", node, port);
    *stage = "QMI PHY capabilities";
    let mut topology = None;
    if let Some(bytes) = session.optional_request(0x57, &[])? {
        let caps = phy_capabilities(&qmi::Message::parse(&bytes)?)?;
        crate::compact_println!(
            "WiFi: QMI PHY count={:?} board={:?} single-chip MLO={:?}",
            caps.phys,
            caps.board,
            caps.single_chip_mlo.map(u8::from)
        );
        topology = firmware_topology(chip.single_chip_mlo, &caps)?;
    }
    *stage = "QMI indication registration";
    session.request(0x20, &registration()?)?;
    *stage = "QMI host capabilities";
    if let Some(topology) = topology {
        crate::compact_println!(
            "WiFi: QMI firmware topology chip={} group={} links={} peers={}",
            topology.config.chip_id,
            topology.config.group_id,
            topology.links,
            topology.config.peer_limit
        );
    }
    session.request(0x34, &host_capabilities(topology)?)?;
    *stage = "QMI firmware memory request";
    let indication = session.indication(0x35)?;
    let segments = memory_request(&qmi::Message::parse(&indication)?)?;
    let mut memory = Vec::new();
    let mut responses = Vec::new();
    for segment in segments {
        let address = if matches!(segment.kind, 1 | 3 | 4 | 8 | 9) {
            let region = Dma::allocate_aligned(machine, segment.size as usize, chip.dma_bits)
                .ok_or(Error::Memory)?;
            let physical = region.physical();
            crate::compact_println!(
                "WiFi: QMI DMA type={} physical={:016x} bytes={}",
                segment.kind,
                physical,
                segment.size
            );
            memory.push(HostMemory {
                region,
                kind: segment.kind,
                bytes: segment.size as usize,
            });
            physical
        } else {
            // Same unsupported-region convention as ath12k, including BDF.
            0
        };
        responses.push((segment, address));
    }
    let body = memory_response(&responses)?;
    *stage = "QMI firmware memory response";
    session.request(0x36, &body)?;
    *stage = "QMI firmware memory ready";
    session.indication(0x37)?;
    *stage = "QMI target capabilities";
    let reply = session.request(0x24, &[])?;
    let caps = capabilities(&qmi::Message::parse(&reply)?)?;
    *stage = "board bundle loading";
    let path = chip.firmware.rsplit_once('/').ok_or(Error::Firmware)?.0;
    let bundle = firmware::request(&format!("{}/board-2.bin", path), 32 * 1024 * 1024)
        .map_err(|_| Error::Firmware)?;
    let name = format!(
        "bus=pci,vendor={:04x},device={:04x},subsystem-vendor={:04x},subsystem-device={:04x},qmi-chip-id={},qmi-board-id={}",
        chip.pci_id & 0xffff,
        chip.pci_id >> 16,
        subsystem & 0xffff,
        subsystem >> 16,
        caps.chip,
        caps.board
    );
    crate::compact_println!("WiFi: QMI board lookup {}", name.as_str());
    let board = board_entry(&bundle, 0, name.as_bytes())?.ok_or(Error::Board)?;
    let regdb = board_entry(&bundle, 1, name.as_bytes())?.or(board_entry(&bundle, 1, b"bus=pci")?);
    // Do not substitute a different board/subsystem or a guessed RF profile.
    *stage = "QMI regulatory database download";
    let external;
    let regdb = match regdb {
        Some(bytes) => bytes,
        None => {
            external = firmware::request(&format!("{}/regdb.bin", path), MAX_BOARD)
                .map_err(|_| Error::Firmware)?;
            &external
        }
    };
    session.download(caps.board, 4, regdb)?;
    *stage = "QMI board data download";
    let kind = u8::from(board.starts_with(b"\x7fELF"));
    session.download(caps.board, kind, board)?;
    *stage = "M3 firmware DMA staging";
    let m3 = firmware::request(&format!("{}/m3.bin", path), 4 * 1024 * 1024)
        .map_err(|_| Error::Firmware)?;
    if !m3.starts_with(b"\x7fELF") {
        return Err(Error::Firmware);
    }
    let mut region =
        Dma::allocate_aligned(machine, m3.len(), chip.dma_bits).ok_or(Error::Memory)?;
    region.copy_in(0, &m3);
    let mut body = Vec::new();
    qmi::tlv(&mut body, 1, &region.physical().to_le_bytes())?;
    qmi::tlv(&mut body, 2, &(m3.len() as u32).to_le_bytes())?;
    memory.push(HostMemory {
        region,
        kind: 0,
        bytes: m3.len(),
    });
    *stage = "QMI M3 firmware information";
    session.request(0x3c, &body)?;
    *stage = "QMI firmware initialization ready";
    session.indication(0x38)?;
    *stage = "QMI firmware logging";
    if session
        .optional_request(0x2f, &firmware_logging()?)?
        .is_some()
    {
        crate::compact_println!("WiFi: firmware logging requested");
    }
    *stage = "CE DMA allocation";
    let bytes = ce::Engine::<Dma>::required_bytes(chip.ce)?;
    let region = Dma::allocate_aligned(machine, bytes, chip.dma_bits).ok_or(Error::Memory)?;
    let mut ce = ce::Engine::new(chip.ce, region, bytes)?;
    let started = (|| -> Result<()> {
        *stage = "QMI CE pipe configuration";
        session.request(0x23, &wlan_configuration(chip.ce, chip.shadow_targets)?)?;
        *stage = "QMI WLAN mission mode";
        let mut body = Vec::new();
        qmi::tlv(&mut body, 1, &0u32.to_le_bytes())?;
        qmi::tlv(&mut body, 0x10, &[0])?;
        session.request(0x22, &body)?;
        // Mission firmware sets up the CE block; publish host rings afterward,
        // matching ath12k_core_qmi_firmware_ready, then post receive buffers.
        *stage = "CE ring initialization";
        ce.start(&mut session.transport.io)?;
        Ok(())
    })();
    if started.is_err() {
        ce.log_state(&mut session.transport.io);
    }
    started?;
    *stage = "firmware crash dump allocation";
    let bytes = mhi::dump::CrashDump::<Dma>::required_bytes(chip.dump_bytes)?;
    let region = Dma::allocate_aligned(machine, bytes, chip.dma_bits).ok_or(Error::Memory)?;
    let mut dump = mhi::dump::CrashDump::new(region, bytes, chip.dump_bytes)?;
    dump.arm(&mut session.transport.io, layout)?;
    if let Some(read) = &chip.assertion_read
        && caps.version == Some(read.firmware)
    {
        *stage = "QMI read-only assertion diagnostic";
        let result = (|| -> Result<()> {
            let body = diagnostic_request(read.address, read.memory_type, read.bytes)?;
            let reply = session.request_timeout(0x30, &body, 1_000_000_000)?;
            let message = qmi::Message::parse(&reply)?;
            log_diagnostic(read.address, diagnostic_response(&message, read.bytes)?);
            Ok(())
        })();
        if let Err(error) = result {
            let message = error.message();
            crate::compact_println!(
                "WiFi: assertion diagnostic unavailable: {}",
                message.as_str()
            );
        }
    }
    Ok(Boot {
        memory,
        ce,
        dump,
        cmem: caps.cmem,
        topology,
    })
}

#[cfg(test)]
mod tests;
