//! Port-I/O device layer for the interpreter backend.
//!
//! The kernel drives real hardware through `arch::inb/inw/outb` — e.g. the ATA
//! disk in `kernel/src/kernel/hdd.rs` is pure PIO on ports 0x1F0–0x1F7 / 0x3F6.
//! On the interpreter those port calls land here instead of on silicon, so the
//! *same* `kernel::startup()` (mount the disk, read the MBR, …) runs unchanged:
//! the backend difference lives entirely below the arch boundary.
//!
//! The dispatch is generic (a registry of devices keyed by port range) so more
//! devices — fw_cfg, serial — can be added later. Today there is one: a
//! host-file-backed ATA controller installed via `attach_disk`.

use std::cell::RefCell;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

const SECTOR: usize = 512;

// Primary ATA controller ports (LBA28 PIO — the subset hdd.rs uses).
const ATA_BASE: u16 = 0x1F0;
const ATA_DATA: u16 = 0x1F0;
const ATA_SECCOUNT: u16 = 0x1F2;
const ATA_LBA_0_7: u16 = 0x1F3;
const ATA_LBA_8_15: u16 = 0x1F4;
const ATA_LBA_16_23: u16 = 0x1F5;
const ATA_LBA_24_27: u16 = 0x1F6;
const ATA_STATUS_CMD: u16 = 0x1F7;
const ATA_CTRL: u16 = 0x3F6;

const ST_DRDY: u32 = 0x40;
const ST_DRQ: u32 = 0x08;
const CMD_READ_SECTORS: u32 = 0x20;

/// A host-file-backed ATA disk presenting the LBA28 PIO read protocol.
struct Ata {
    file: File,
    seccount: u8,
    lba: u32,
    /// Bytes loaded by the current READ_SECTORS command, drained by DATA reads.
    buf: Vec<u8>,
    pos: usize,
}

impl Ata {
    fn new(file: File) -> Ata {
        Ata { file, seccount: 0, lba: 0, buf: Vec::new(), pos: 0 }
    }

    fn status(&self) -> u32 {
        // Reads are synchronous, so BSY is never set and the kernel's busy-poll
        // loops exit immediately. DRQ is set while a sector buffer has data.
        ST_DRDY | if self.pos < self.buf.len() { ST_DRQ } else { 0 }
    }

    fn out(&mut self, port: u16, val: u32) {
        match port {
            ATA_SECCOUNT => self.seccount = val as u8,
            ATA_LBA_0_7 => self.lba = (self.lba & 0xFFFF_FF00) | (val & 0xFF),
            ATA_LBA_8_15 => self.lba = (self.lba & 0xFFFF_00FF) | ((val & 0xFF) << 8),
            ATA_LBA_16_23 => self.lba = (self.lba & 0xFF00_FFFF) | ((val & 0xFF) << 16),
            ATA_LBA_24_27 => self.lba = (self.lba & 0x00FF_FFFF) | ((val & 0x0F) << 24),
            ATA_STATUS_CMD if val == CMD_READ_SECTORS => self.read_sectors(),
            _ => {} // FEATURES, control (SRST/select), other commands: no-op
        }
    }

    fn read_sectors(&mut self) {
        let count = if self.seccount == 0 { 256 } else { self.seccount as usize };
        let len = count * SECTOR;
        let mut buf = vec![0u8; len];
        // Short reads past end-of-file leave zeros — matches a disk that's
        // larger than the image would, harmless for the in-range reads the FS does.
        if self.file.seek(SeekFrom::Start(self.lba as u64 * SECTOR as u64)).is_ok() {
            let mut filled = 0;
            while filled < len {
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

    /// DATA-port read: next little-endian 16-bit word from the sector buffer.
    fn data_word(&mut self) -> u32 {
        let lo = self.buf.get(self.pos).copied().unwrap_or(0) as u32;
        let hi = self.buf.get(self.pos + 1).copied().unwrap_or(0) as u32;
        self.pos = (self.pos + 2).min(self.buf.len());
        lo | (hi << 8)
    }
}

struct Devices {
    ata: Option<Ata>,
}

thread_local! {
    static DEVICES: RefCell<Devices> = const { RefCell::new(Devices { ata: None }) };
}

/// Attach a host image file as the primary ATA disk. The interpreted `inb/inw/
/// outb` then serve `hdd::read_sectors` from it.
pub fn attach_disk(path: &str) -> std::io::Result<()> {
    let file = File::open(path)?;
    DEVICES.with(|d| d.borrow_mut().ata = Some(Ata::new(file)));
    Ok(())
}

/// Port input (`width` in bytes). Unhandled ports read the ISA "no device" value.
pub fn port_in(port: u16, _width: u8) -> u32 {
    DEVICES.with(|d| {
        let mut d = d.borrow_mut();
        if let Some(ata) = d.ata.as_mut() {
            match port {
                ATA_DATA => return ata.data_word(),
                ATA_STATUS_CMD | ATA_CTRL => return ata.status(),
                p if (ATA_BASE..=ATA_STATUS_CMD).contains(&p) => return ata.status(),
                _ => {}
            }
        }
        0xFFFF_FFFF // absent device: all ones (callers truncate to width)
    })
}

/// Port output (`width` in bytes). Unhandled ports drop the write.
pub fn port_out(port: u16, _width: u8, val: u32) {
    DEVICES.with(|d| {
        let mut d = d.borrow_mut();
        if let Some(ata) = d.ata.as_mut() {
            if (ATA_BASE..=ATA_STATUS_CMD).contains(&port) || port == ATA_CTRL {
                ata.out(port, val);
            }
        }
    });
}
