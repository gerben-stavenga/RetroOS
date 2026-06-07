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

struct Ata {
    file: File,
    seccount: u8,
    lba: u32,
    buf: Vec<u8>,
    pos: usize,
}

impl Ata {
    fn new(file: File) -> Ata {
        Ata { file, seccount: 0, lba: 0, buf: Vec::new(), pos: 0 }
    }

    fn status(&self) -> u32 {
        // Reads are synchronous → never BSY; DRQ while a sector buffer has data.
        ST_DRDY | if self.pos < self.buf.len() { ST_DRQ } else { 0 }
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
            ATA_SECCOUNT => self.seccount = val as u8,
            ATA_LBA_0_7 => self.lba = (self.lba & 0xFFFF_FF00) | (val & 0xFF),
            ATA_LBA_8_15 => self.lba = (self.lba & 0xFFFF_00FF) | ((val & 0xFF) << 8),
            ATA_LBA_16_23 => self.lba = (self.lba & 0xFF00_FFFF) | ((val & 0xFF) << 16),
            ATA_LBA_24_27 => self.lba = (self.lba & 0x00FF_FFFF) | ((val & 0x0F) << 24),
            ATA_STATUS_CMD if val == CMD_READ_SECTORS => self.read_sectors(),
            _ => {} // features / other commands: no-op
        }
    }
}

/// Hook a host image file onto the primary ATA ports — `hdd::read_sectors`
/// reads it through the interpreted PIO.
pub fn attach_disk(path: &str) -> std::io::Result<()> {
    let file = File::open(path)?;
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
// lets `cargo run -- --cmd "PROG ARGS"` boot straight into one program headless,
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
