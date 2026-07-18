//! ATA/IDE PIO disk driver
//!
//! Simple polling-based driver, LBA28 addressing (disks up to 128 GB).
//!
//! One [`AtaDisk`] value per drive: it owns its controller ports and drive
//! select, so a machine with a primary master AND a secondary slave is just
//! two values. The driver's whole job is "is there a drive here, and how do I
//! move sectors to and from it" — which disk is the boot disk, and what lives
//! on it, is decided by `startup`.

use crate::kernel::block::Disk;
use crate::kernel::portio::{inb, insw, outb, outsw};

/// ATA register offsets from base port
mod reg {
    pub const DATA: u16 = 0;           // Read/Write data (16-bit)
    pub const FEATURES: u16 = 1;       // Features register (write)
    pub const SECTOR_COUNT: u16 = 2;   // Number of sectors
    pub const LBA_0_7: u16 = 3;        // LBA bits 0-7
    pub const LBA_8_15: u16 = 4;       // LBA bits 8-15
    pub const LBA_16_23: u16 = 5;      // LBA bits 16-23
    pub const LBA_24_27_FLAGS: u16 = 6; // LBA bits 24-27 + flags
    pub const STATUS: u16 = 7;         // Status register (read)
    pub const COMMAND: u16 = 7;        // Command register (write)
}

/// ATA status register bits
mod status {
    pub const BSY: u8 = 0x80;  // Busy
    pub const DRDY: u8 = 0x40; // Drive ready
    pub const DRQ: u8 = 0x08;  // Data request (ready to transfer)
    pub const ERR: u8 = 0x01;  // Error
}

/// ATA commands
mod cmd {
    pub const READ_SECTORS: u8 = 0x20;
    pub const WRITE_SECTORS: u8 = 0x30;
    pub const CACHE_FLUSH: u8 = 0xE7;
    pub const IDENTIFY: u8 = 0xEC;
}

/// The two legacy ISA channels: (base, control). Every PC has these at fixed
/// ports; anything beyond them is PCI-configured and out of scope here.
pub const CHANNELS: [(u16, u16); 2] = [(0x1F0, 0x3F6), (0x170, 0x376)];

/// The LBA28 addressing ceiling — this driver cannot reach past it.
const LBA28_MAX: u64 = 1 << 28;

/// One ATA drive: a channel plus a master/slave select.
pub struct AtaDisk {
    base: u16,
    /// 0 = master, 1 = slave. Shifted into bit 4 of the drive/head register.
    drive: u8,
    sectors: u64,
    /// Always 4 bytes ("ata0".."ata3"); owned so `name()` can borrow it.
    name: [u8; 4],
}

impl AtaDisk {
    /// Probe one drive. `None` when nothing answers — bounded, so a machine
    /// with no ATA at all (UEFI/NVMe-only, floating bus reading 0xFF) returns
    /// quickly instead of busy-waiting forever like the transfer paths do.
    ///
    /// IDENTIFY is the real presence test, not the status register: an ABSENT
    /// SLAVE answers DRDY because the master drives the bus on its behalf, so
    /// a status check alone invents a phantom disk. A drive that won't
    /// IDENTIFY (no device, or ATAPI, which we don't support) is not a disk.
    pub fn probe(base: u16, ctrl: u16, drive: u8) -> Option<Self> {
        let select = 0xE0 | (drive << 4);

        // Software reset, then select the drive and wait — bounded.
        outb(ctrl, 0x04);
        for _ in 0..4 {
            inb(ctrl);
        }
        outb(ctrl, 0x00);
        outb(base + reg::LBA_24_27_FLAGS, select);

        let mut ready = false;
        for _ in 0..100_000 {
            let s = inb(base + reg::STATUS);
            if s == 0xFF {
                return None; // floating bus — no controller decodes these ports
            }
            if (s & (status::BSY | status::DRDY)) == status::DRDY {
                ready = true;
                break;
            }
        }
        if !ready {
            return None;
        }

        // Channel 0 master is "ata0", channel 0 slave "ata1", and so on.
        let index = if base == CHANNELS[1].0 { 2 } else { 0 } + drive;
        let name = [b'a', b't', b'a', b'0' + index];

        let mut disk = AtaDisk { base, drive, sectors: 0, name };
        disk.sectors = disk.identify_sectors()?;
        Some(disk)
    }

    /// LBA28 capacity from IDENTIFY words 60-61. `None` if the drive errors or
    /// never raises DRQ (bounded wait — a non-existent slave typically hangs
    /// BSY forever, which is exactly what we must not do here).
    fn identify_sectors(&self) -> Option<u64> {
        self.select();
        outb(self.base + reg::SECTOR_COUNT, 0);
        outb(self.base + reg::LBA_0_7, 0);
        outb(self.base + reg::LBA_8_15, 0);
        outb(self.base + reg::LBA_16_23, 0);
        outb(self.base + reg::COMMAND, cmd::IDENTIFY);

        for _ in 0..1_000_000 {
            let s = inb(self.base + reg::STATUS);
            if s == 0 || (s & status::ERR) != 0 {
                return None; // no device, or IDENTIFY unsupported (ATAPI)
            }
            if (s & status::BSY) == 0 && (s & status::DRQ) != 0 {
                let mut words = [0u16; 256];
                insw(self.base + reg::DATA, &mut words);
                let lba28 = ((words[61] as u64) << 16) | words[60] as u64;
                return (lba28 > 0).then_some(lba28);
            }
        }
        None
    }

    fn name(&self) -> &str {
        core::str::from_utf8(&self.name).unwrap_or("ata?")
    }

    /// Point the channel at this drive. Every transfer re-selects, because the
    /// other drive on the same channel may have been used in between — and a
    /// stale select is not benign: waiting on the status register while an
    /// ABSENT drive is selected spins forever on a floating bus.
    ///
    /// The spec wants ~400 ns before the status register is meaningful after a
    /// select; four status reads cover it (each is an ISA cycle).
    fn select(&self) {
        outb(self.base + reg::LBA_24_27_FLAGS, 0xE0 | (self.drive << 4));
        for _ in 0..4 {
            inb(self.base + reg::STATUS);
        }
    }

    /// Wait for the drive to be ready (BSY clear, DRDY set).
    fn wait_ready(&self) {
        loop {
            let s = inb(self.base + reg::STATUS);
            if (s & (status::BSY | status::DRDY)) == status::DRDY {
                break;
            }
        }
    }

    /// Wait for a data request (ready to transfer a sector).
    fn wait_data(&self) {
        loop {
            let s = inb(self.base + reg::STATUS);
            if (s & status::BSY) == 0 && (s & status::DRQ) != 0 {
                break;
            }
        }
    }

    /// Program the taskfile for a `batch`-sector transfer at `lba`.
    ///
    /// Select BEFORE waiting: the channel may still be pointed at the other
    /// drive from a previous probe or transfer, and `wait_ready` against an
    /// absent drive never returns.
    fn issue(&self, lba: u32, batch: u32, command: u8) {
        self.select();
        self.wait_ready();
        outb(self.base + reg::LBA_24_27_FLAGS,
             ((lba >> 24) as u8 & 0x0F) | 0xE0 | (self.drive << 4));
        outb(self.base + reg::FEATURES, 0);
        // A sector count of 0 means 256 — the maximum one command can carry.
        outb(self.base + reg::SECTOR_COUNT, if batch == 256 { 0 } else { batch as u8 });
        outb(self.base + reg::LBA_0_7, lba as u8);
        outb(self.base + reg::LBA_8_15, (lba >> 8) as u8);
        outb(self.base + reg::LBA_16_23, (lba >> 16) as u8);
        outb(self.base + reg::COMMAND, command);
    }
}

impl Disk for AtaDisk {
    fn read(&self, lba: u64, mut buffer: &mut [u8]) -> u32 {
        let count = buffer.len().div_ceil(512) as u32;
        debug_assert!(lba + count as u64 <= LBA28_MAX, "LBA28 overflow");

        let mut remaining = count;
        let mut current = lba as u32;
        while remaining > 0 {
            // One command can carry at most 256 sectors.
            let batch = remaining.min(256);
            self.issue(current, batch, cmd::READ_SECTORS);
            remaining -= batch;
            current += batch;

            // Read each sector in this batch. One `rep insw` per sector, not
            // 256 discrete `in`s: under a hypervisor each `in` is a VM exit,
            // and at 256 of them per sector an 8 KB read cost ~80 ms — long
            // enough to stall the audio pump and coalesce away timer ticks.
            for _ in 0..batch {
                self.wait_data();
                let mut words = [0u16; 256];
                insw(self.base + reg::DATA, &mut words);
                let mut bytes = [0u8; 512];
                for (pair, w) in bytes.chunks_exact_mut(2).zip(words) {
                    pair.copy_from_slice(&w.to_le_bytes());
                }
                let n = buffer.len().min(512);
                buffer[..n].copy_from_slice(&bytes[..n]);
                buffer = &mut buffer[n..];
            }
        }
        count
    }

    /// A short final chunk (buffer not a 512-multiple) is zero-padded to a
    /// full sector, since a sector is the atomic unit of the transfer.
    fn write(&self, lba: u64, mut buffer: &[u8]) -> u32 {
        let count = buffer.len().div_ceil(512) as u32;
        debug_assert!(lba + count as u64 <= LBA28_MAX, "LBA28 overflow");

        let mut remaining = count;
        let mut current = lba as u32;
        while remaining > 0 {
            let batch = remaining.min(256);
            self.issue(current, batch, cmd::WRITE_SECTORS);
            remaining -= batch;
            current += batch;

            // One `rep outsw` per sector — same VM-exit amortization as the
            // read side.
            for _ in 0..batch {
                self.wait_data();
                let mut bytes = [0u8; 512];
                let n = buffer.len().min(512);
                bytes[..n].copy_from_slice(&buffer[..n]); // tail (< 512) stays zero
                buffer = &buffer[n..];

                let mut words = [0u16; 256];
                for (w, pair) in words.iter_mut().zip(bytes.chunks_exact(2)) {
                    *w = u16::from_le_bytes([pair[0], pair[1]]);
                }
                outsw(self.base + reg::DATA, &words);
            }
        }

        // Flush the drive's write cache so the data is durable before we
        // report success.
        self.wait_ready();
        outb(self.base + reg::COMMAND, cmd::CACHE_FLUSH);
        self.wait_ready();

        count
    }

    fn sectors(&self) -> u64 {
        self.sectors
    }

    fn name(&self) -> &str {
        AtaDisk::name(self)
    }
}
