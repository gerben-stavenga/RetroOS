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

struct Debugcon;
impl PortIo for Debugcon {
    fn write(&mut self, _port: u16, _width: u8, val: u32) {
        // The debug console is the *log* channel → stderr. (The screen/program
        // output goes to stdout via the VGA path; sending 0xE9 there too would
        // duplicate every character.)
        let _ = std::io::stderr().write_all(&[val as u8]);
    }
}

/// Hook the Bochs/QEMU debug console at port 0xE9 to stderr (the log channel).
pub fn register_debugcon() {
    register(0xE9, 0xE9, Box::new(Debugcon));
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
