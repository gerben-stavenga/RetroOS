//! Port-I/O device bus for the interpreter backend.
//!
//! The kernel drives hardware through `arch::inb/inw/outb`; on the interpreter
//! those land here. Devices implement the [`PortIo`] trait and are `register`ed
//! for an inclusive port range, so the hosted `main` composes the platform by
//! hooking ports — a disk image on the ATA ports, a host directory on COM1, the
//! debug console on 0xE9. Ports with no registered device read the ISA "no
//! device" value 0xFF and drop writes.

use crate::hostfs::HostFs;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

const SECTOR: usize = 512;

/// A device that responds to port I/O. `width` is the access size in bytes.
pub trait PortIo {
    fn read(&mut self, port: u16, width: u8) -> u32 {
        let _ = (port, width);
        0xFFFF_FFFF
    }
    fn write(&mut self, port: u16, width: u8, val: u32) {
        let _ = (port, width, val);
    }
}

struct Entry {
    lo: u16,
    hi: u16,
    dev: Box<dyn PortIo>,
}

thread_local! {
    static BUS: RefCell<Vec<Entry>> = const { RefCell::new(Vec::new()) };
}

/// Register `dev` for the inclusive port range `[lo, hi]`. Later registrations
/// shadow earlier ones on overlap.
pub fn register(lo: u16, hi: u16, dev: Box<dyn PortIo>) {
    BUS.with(|b| b.borrow_mut().push(Entry { lo, hi, dev }));
}

pub fn port_in(port: u16, width: u8) -> u32 {
    BUS.with(|b| {
        for e in b.borrow_mut().iter_mut().rev() {
            if e.lo <= port && port <= e.hi {
                return e.dev.read(port, width);
            }
        }
        0xFFFF_FFFF
    })
}

pub fn port_out(port: u16, width: u8, val: u32) {
    BUS.with(|b| {
        for e in b.borrow_mut().iter_mut().rev() {
            if e.lo <= port && port <= e.hi {
                e.dev.write(port, width, val);
                return;
            }
        }
    });
}

// ── Debug console (port 0xE9 → stdout) ──────────────────────────────────────

struct Debugcon {
    /// Optional file sink. When live-rendering the VGA screen owns the terminal,
    /// the 0xE9 stream is routed to a log file instead so the two don't collide.
    sink: Option<std::fs::File>,
}
impl PortIo for Debugcon {
    fn write(&mut self, _port: u16, _width: u8, val: u32) {
        // The kernel's text console mirrors every byte to 0xE9, so this *is* the
        // console output stream.
        match &mut self.sink {
            Some(f) => { let _ = f.write_all(&[val as u8]); }
            None => { let _ = std::io::stdout().write_all(&[val as u8]); }
        }
    }
}

/// Hook the debug console at port 0xE9 to stdout (the console stream).
pub fn register_debugcon() {
    register(0xE9, 0xE9, Box::new(Debugcon { sink: None }));
}

/// Hook the debug console to a file instead of stdout — used with the live VGA
/// console, where the terminal is owned by the screen renderer.
pub fn register_debugcon_file(path: &str) {
    let sink = std::fs::File::create(path).ok();
    register(0xE9, 0xE9, Box::new(Debugcon { sink }));
}

// ── ATA disk (primary controller, LBA28 PIO) ────────────────────────────────

const ATA_BASE: u16 = 0x1F0;
const ATA_DATA: u16 = 0x1F0;
const ATA_SECCOUNT: u16 = 0x1F2;
const ATA_LBA_0_7: u16 = 0x1F3;
const ATA_LBA_8_15: u16 = 0x1F4;
const ATA_LBA_16_23: u16 = 0x1F5;
const ATA_LBA_24_27: u16 = 0x1F6;
const ATA_STATUS_CMD: u16 = 0x1F7;

const ST_DRDY: u32 = 0x40;
const ST_DRQ: u32 = 0x08;
const CMD_READ_SECTORS: u32 = 0x20;
const CMD_WRITE_SECTORS: u32 = 0x30;
const CMD_CACHE_FLUSH: u32 = 0xE7;

struct Ata {
    file: File,
    seccount: u8,
    lba: u32,
    buf: Vec<u8>,
    pos: usize,
    /// True between a WRITE SECTORS command and its buffer draining to the
    /// file: the data port ACCEPTS words instead of yielding them. DRQ means
    /// the same thing either way — "the sector buffer isn't done" — so the
    /// status bit is shared; only the data-port direction flips.
    writing: bool,
}

impl Ata {
    fn new(file: File) -> Ata {
        Ata { file, seccount: 0, lba: 0, buf: Vec::new(), pos: 0, writing: false }
    }

    fn status(&self) -> u32 {
        // Reads/writes are synchronous → never BSY; DRQ while the sector buffer
        // still has data to yield (read) or room to accept (write).
        ST_DRDY | if self.pos < self.buf.len() { ST_DRQ } else { 0 }
    }

    /// Begin a WRITE SECTORS: size the buffer to the request and assert DRQ so
    /// the guest streams `count * 256` words in through the data port.
    fn begin_write(&mut self) {
        let count = if self.seccount == 0 { 256 } else { self.seccount as usize };
        self.buf = vec![0u8; count * SECTOR];
        self.pos = 0;
        self.writing = true;
    }

    /// Accept one data word during a write; flush the whole buffer to the file
    /// once the last word lands (mirrors `read_sectors`' seek+transfer).
    fn write_data_word(&mut self, val: u32) {
        if self.pos + 1 < self.buf.len() {
            self.buf[self.pos] = val as u8;
            self.buf[self.pos + 1] = (val >> 8) as u8;
        }
        self.pos = (self.pos + 2).min(self.buf.len());
        if self.pos >= self.buf.len() && self.writing {
            if self.file.seek(SeekFrom::Start(self.lba as u64 * SECTOR as u64)).is_ok() {
                let _ = self.file.write_all(&self.buf);
                let _ = self.file.flush();
            }
            self.buf.clear();
            self.pos = 0;
            self.writing = false;
        }
    }

    fn read_sectors(&mut self) {
        let count = if self.seccount == 0 { 256 } else { self.seccount as usize };
        let mut buf = vec![0u8; count * SECTOR];
        if self.file.seek(SeekFrom::Start(self.lba as u64 * SECTOR as u64)).is_ok() {
            let mut filled = 0;
            while filled < buf.len() {
                match self.file.read(&mut buf[filled..]) {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(_) => break,
                }
            }
        }
        self.buf = buf;
        self.pos = 0;
    }

    fn data_word(&mut self) -> u32 {
        let lo = self.buf.get(self.pos).copied().unwrap_or(0) as u32;
        let hi = self.buf.get(self.pos + 1).copied().unwrap_or(0) as u32;
        self.pos = (self.pos + 2).min(self.buf.len());
        lo | (hi << 8)
    }
}

impl PortIo for Ata {
    fn read(&mut self, port: u16, _width: u8) -> u32 {
        if port == ATA_DATA {
            self.data_word()
        } else {
            self.status() // status/alt-status and other registers report ready
        }
    }

    fn write(&mut self, port: u16, _width: u8, val: u32) {
        match port {
            ATA_DATA if self.writing => self.write_data_word(val),
            ATA_SECCOUNT => self.seccount = val as u8,
            ATA_LBA_0_7 => self.lba = (self.lba & 0xFFFF_FF00) | (val & 0xFF),
            ATA_LBA_8_15 => self.lba = (self.lba & 0xFFFF_00FF) | ((val & 0xFF) << 8),
            ATA_LBA_16_23 => self.lba = (self.lba & 0xFF00_FFFF) | ((val & 0xFF) << 16),
            ATA_LBA_24_27 => self.lba = (self.lba & 0x00FF_FFFF) | ((val & 0x0F) << 24),
            ATA_STATUS_CMD if val == CMD_READ_SECTORS => self.read_sectors(),
            ATA_STATUS_CMD if val == CMD_WRITE_SECTORS => self.begin_write(),
            ATA_STATUS_CMD if val == CMD_CACHE_FLUSH => {} // synchronous writes: nothing buffered
            _ => {} // features / other commands: no-op
        }
    }
}

/// Hook a host image file onto the primary ATA ports — `hdd::read_sectors`
/// reads it and `hdd::write_sectors` writes it back through the interpreted
/// PIO. Opened read-write so the backing-file overlay persists; falls back to
/// read-only if the image isn't writable (writes then silently no-op, same as
/// a write-protected disk).
pub fn attach_disk(path: &str) -> std::io::Result<()> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .or_else(|_| File::open(path))?;
    register(ATA_BASE, ATA_STATUS_CMD, Box::new(Ata::new(file)));
    Ok(())
}

// ── COM1 16550 UART → native host filesystem ────────────────────────────────

const COM1: u16 = 0x3F8;

struct Uart {
    fs: HostFs,
    tx: Vec<u8>,
    rx: VecDeque<u8>,
    scratch: u8,
    dlab: bool,
}

impl Uart {
    fn new(fs: HostFs) -> Uart {
        Uart { fs, tx: Vec::new(), rx: VecDeque::new(), scratch: 0, dlab: false }
    }

    fn read_reg(&mut self, off: u16) -> u8 {
        match off {
            0 => self.rx.pop_front().unwrap_or(0),                 // RBR (data)
            5 => 0x60 | if self.rx.is_empty() { 0 } else { 0x01 }, // LSR: THRE+TEMT (+DR)
            6 => 0x30,                                             // MSR: CTS+DSR (peer present)
            7 => self.scratch,                                     // scratch (presence probe)
            _ => 0,
        }
    }

    fn write_reg(&mut self, off: u16, val: u8) {
        match off {
            0 if !self.dlab => {
                // The client sends a whole command, then reads the reply, so the
                // command's last byte completes it here and the reply is queued
                // synchronously — no blocking, no external process.
                self.tx.push(val);
                let Uart { fs, tx, rx, .. } = self;
                while let Some((consumed, reply)) = fs.try_command(tx) {
                    tx.drain(..consumed);
                    rx.extend(reply);
                    if tx.is_empty() {
                        break;
                    }
                }
            }
            3 => self.dlab = val & 0x80 != 0, // LCR (DLAB)
            7 => self.scratch = val,
            _ => {} // IER / FCR / MCR / divisor latches: accept & ignore
        }
    }
}

impl PortIo for Uart {
    fn read(&mut self, port: u16, _width: u8) -> u32 {
        self.read_reg(port - COM1) as u32
    }
    fn write(&mut self, port: u16, _width: u8, val: u32) {
        self.write_reg(port - COM1, val as u8);
    }
}

/// Hook a host directory onto COM1 as the kernel's `/host` filesystem.
pub fn attach_hostfs(dir: &str) {
    register(COM1, COM1 + 7, Box::new(Uart::new(HostFs::new(dir))));
}

// ── QEMU fw_cfg (headless program selection) ────────────────────────────────
//
// `kernel::startup` reads `opt/cmdline` (which DOS program to run, then shut
// down) through the QEMU fw_cfg port protocol — the exact path metal takes from
// `-fw_cfg name=opt/cmdline,string=...`. A 16-bit selector write to 0x510 picks
// an item; byte reads from 0x511 stream it out. Selector 0x0000 is the "QEMU"
// signature; 0x0019 is the file directory: a u32 count (big-endian) followed by
// 64-byte entries `{ size:u32 BE, select:u16 BE, reserved:u16, name:[u8;56] }`.
// File items get selectors from 0x0020 up. Serving a small in-memory file set
// lets `retroos-host --cmd "PROG ARGS"` boot straight into one program headless,
// with no keyboard — the device behind the ports differs, `startup()` does not.

const FW_CFG_SEL: u16 = 0x510;
const FW_CFG_DATA: u16 = 0x511;
const FW_CFG_SIG: u16 = 0x0000;
const FW_CFG_FILE_DIR: u16 = 0x0019;
const FW_CFG_FILE_FIRST: u16 = 0x0020;

struct FwCfg {
    files: Vec<(String, Vec<u8>)>,
    sel: u16,
    pos: usize,
}

impl FwCfg {
    /// The byte stream the current selector names (signature / directory / file).
    fn current(&self) -> Vec<u8> {
        match self.sel {
            FW_CFG_SIG => b"QEMU".to_vec(),
            FW_CFG_FILE_DIR => {
                let mut out = (self.files.len() as u32).to_be_bytes().to_vec();
                for (i, (name, data)) in self.files.iter().enumerate() {
                    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
                    out.extend_from_slice(&(FW_CFG_FILE_FIRST + i as u16).to_be_bytes());
                    out.extend_from_slice(&[0, 0]); // reserved
                    let mut field = [0u8; 56];
                    let nb = name.as_bytes();
                    let n = nb.len().min(55);
                    field[..n].copy_from_slice(&nb[..n]);
                    out.extend_from_slice(&field);
                }
                out
            }
            s if s >= FW_CFG_FILE_FIRST => self
                .files
                .get((s - FW_CFG_FILE_FIRST) as usize)
                .map(|(_, d)| d.clone())
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }
}

impl PortIo for FwCfg {
    fn read(&mut self, port: u16, _width: u8) -> u32 {
        if port == FW_CFG_DATA {
            let cur = self.current();
            let b = cur.get(self.pos).copied().unwrap_or(0);
            self.pos = (self.pos + 1).min(cur.len());
            b as u32
        } else {
            0
        }
    }
    fn write(&mut self, port: u16, _width: u8, val: u32) {
        if port == FW_CFG_SEL {
            // The IO-port selector is native byte order (only fw_cfg *data* is
            // big-endian); the kernel writes the host-order selector via `outw`.
            self.sel = val as u16;
            self.pos = 0;
        }
    }
}

// ── RetroOS canonical audio device → WAV file ───────────────────────────────
//
// The kernel's sound layer (`kernel/src/kernel/sound.rs`) canonicalizes every
// PCM source to signed-16 interleaved stereo and streams it here via `arch.outw`
// on a private port window — the audio analogue of the ATA disk: a device below
// the arch boundary, driven through ordinary port I/O, not a bespoke arch call.
// The host side (where `std` lives) writes a RIFF/WAVE file so the produced
// audio can be verified offline (e.g. the `modplay` MOD player).

const AUDIO_SIG: u16 = 0x530; // R: signature; W: sample rate (Hz)
const AUDIO_LEFT: u16 = 0x532; // W: latch left i16
const AUDIO_RIGHT: u16 = 0x534; // W: right i16 + commit the (L,R) frame
const AUDIO_SIGNATURE: u16 = 0x5241; // 'R','A' — matches kernel `sound::SIGNATURE`

/// How often (in frames) to re-patch the WAV header's length fields. Headless
/// runs end via `std::process::exit` (no `Drop`), so we keep the on-disk header
/// valid by rewriting it periodically — at most this many frames of tail are
/// lost if the process is killed between patches (~46 ms at 22 kHz).
const HEADER_PATCH_EVERY: u32 = 1024;

struct WavSink {
    file: File,
    rate: u32,
    frames: u32,
    left: i16,
}

impl WavSink {
    fn new(mut file: File) -> WavSink {
        let _ = file.write_all(&Self::header(0, 22050));
        WavSink { file, rate: 22050, frames: 0, left: 0 }
    }

    /// 44-byte canonical PCM WAVE header (2ch / 16-bit / `rate` Hz, `frames`).
    fn header(frames: u32, rate: u32) -> [u8; 44] {
        let channels: u16 = 2;
        let bits: u16 = 16;
        let block_align: u16 = channels * bits / 8; // 4 bytes/frame
        let byte_rate = rate * block_align as u32;
        let data_bytes = frames * block_align as u32;
        let mut h = [0u8; 44];
        h[0..4].copy_from_slice(b"RIFF");
        h[4..8].copy_from_slice(&(36 + data_bytes).to_le_bytes());
        h[8..12].copy_from_slice(b"WAVE");
        h[12..16].copy_from_slice(b"fmt ");
        h[16..20].copy_from_slice(&16u32.to_le_bytes()); // PCM fmt chunk size
        h[20..22].copy_from_slice(&1u16.to_le_bytes()); // format = PCM
        h[22..24].copy_from_slice(&channels.to_le_bytes());
        h[24..28].copy_from_slice(&rate.to_le_bytes());
        h[28..32].copy_from_slice(&byte_rate.to_le_bytes());
        h[32..34].copy_from_slice(&block_align.to_le_bytes());
        h[34..36].copy_from_slice(&bits.to_le_bytes());
        h[36..40].copy_from_slice(b"data");
        h[40..44].copy_from_slice(&data_bytes.to_le_bytes());
        h
    }

    fn commit_frame(&mut self, right: i16) {
        let mut frame = [0u8; 4];
        frame[0..2].copy_from_slice(&self.left.to_le_bytes());
        frame[2..4].copy_from_slice(&right.to_le_bytes());
        let _ = self.file.write_all(&frame);
        self.frames += 1;
        if self.frames.is_multiple_of(HEADER_PATCH_EVERY) {
            self.patch_header();
        }
    }

    fn patch_header(&mut self) {
        if self.file.seek(SeekFrom::Start(0)).is_ok() {
            let _ = self.file.write_all(&Self::header(self.frames, self.rate));
            let _ = self.file.seek(SeekFrom::End(0));
        }
    }
}

impl PortIo for WavSink {
    fn read(&mut self, port: u16, _width: u8) -> u32 {
        if port == AUDIO_SIG { AUDIO_SIGNATURE as u32 } else { 0xFFFF }
    }
    fn write(&mut self, port: u16, _width: u8, val: u32) {
        match port {
            // Rate change: flush the header at the old rate first, then adopt.
            AUDIO_SIG => {
                self.patch_header();
                self.rate = val & 0xFFFF;
            }
            AUDIO_LEFT => self.left = val as u16 as i16,
            AUDIO_RIGHT => self.commit_frame(val as u16 as i16),
            _ => {}
        }
    }
}

/// Hook a WAV-to-disk sink onto the canonical audio port window — the kernel's
/// `sound::play` streams canonical i16-stereo PCM here for offline verification.
pub fn attach_audio(path: &str) {
    if let Ok(file) = File::create(path) {
        register(AUDIO_SIG, AUDIO_RIGHT, Box::new(WavSink::new(file)));
    }
}

/// Serve a QEMU-style fw_cfg with `opt/cmdline` (and optionally `opt/cwd`) so
/// the kernel boots one program headless and shuts down when it exits.
/// Register the fw_cfg device. Always presents the "QEMU" signature (so the
/// kernel's `is_qemu()` is true — the interpreter has no real VGA raster, so it
/// must fabricate 0x3DA retrace bits etc. the way it does under QEMU). With a
/// `cmdline`, also exposes `opt/cmdline` (+ optional `opt/cwd`) for headless
/// single-program launch; without one it's just the signature + an empty dir.
pub fn attach_fw_cfg(cmdline: Option<&str>, cwd: Option<&str>) {
    let mut files = Vec::new();
    if let Some(c) = cmdline {
        files.push(("opt/cmdline".to_string(), c.as_bytes().to_vec()));
    }
    if let Some(c) = cwd {
        files.push(("opt/cwd".to_string(), c.as_bytes().to_vec()));
    }
    register(FW_CFG_SEL, FW_CFG_DATA, Box::new(FwCfg { files, sel: 0, pos: 0 }));
}
