//! ATA/IDE PIO disk driver
//!
//! Simple polling-based driver for reading sectors from the primary ATA disk.
//! Uses LBA28 addressing mode, supporting disks up to 128GB.

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
}

/// ATA commands
mod cmd {
    pub const READ_SECTORS: u8 = 0x20;
    pub const WRITE_SECTORS: u8 = 0x30;
    pub const CACHE_FLUSH: u8 = 0xE7;
}

/// Primary ATA controller base port
const PRIMARY_BASE: u16 = 0x1F0;
const PRIMARY_CTRL: u16 = 0x3F6;

/// Bounded presence probe: is there a primary ATA controller with a ready
/// master drive? Unlike `reset`/`read_sectors` (which busy-wait forever and
/// hang on machines with no ATA at all — UEFI/NVMe-only boxes read 0xFF from
/// the whole port range), this gives up quickly so `block::init` can fall
/// through to NVMe.
pub fn probe() -> bool {
    outb(PRIMARY_CTRL, 0x04);
    for _ in 0..4 { inb(PRIMARY_CTRL); }
    outb(PRIMARY_CTRL, 0x00);
    outb(PRIMARY_BASE + reg::LBA_24_27_FLAGS, 0xE0);
    for _ in 0..100_000 {
        let s = inb(PRIMARY_BASE + reg::STATUS);
        if s == 0xFF {
            return false; // floating bus — no controller decodes these ports
        }
        if (s & (status::BSY | status::DRDY)) == status::DRDY {
            return true;
        }
    }
    false
}

/// Reset the ATA controller and wait for the drive to become ready.
/// Needed after GRUB boot, which may leave the controller idle.
pub fn reset() {
    // Software reset: set SRST bit (bit 2) in Device Control register
    outb(PRIMARY_CTRL, 0x04);
    // Wait a bit (ATA spec says >= 5µs, a few inb delays suffice)
    for _ in 0..4 { inb(PRIMARY_CTRL); }
    // Clear SRST
    outb(PRIMARY_CTRL, 0x00);
    // Select master drive
    outb(PRIMARY_BASE + reg::LBA_24_27_FLAGS, 0xE0);
    // Wait for drive to come ready (BSY clears, DRDY sets)
    for _ in 0..100_000 {
        let s = inb(PRIMARY_BASE + reg::STATUS);
        if (s & (status::BSY | status::DRDY)) == status::DRDY {
            return;
        }
    }
}

/// Wait for disk to be ready (not busy, ready to accept commands)
fn wait_disk_ready(port: u16) {
    // Wait until BSY is clear and DRDY is set
    loop {
        let s = inb(port + reg::STATUS);
        if (s & (status::BSY | status::DRDY)) == status::DRDY {
            break;
        }
    }
}

/// Wait for data request (ready to transfer data)
fn wait_data_ready(port: u16) {
    loop {
        let s = inb(port + reg::STATUS);
        if (s & status::BSY) == 0 && (s & status::DRQ) != 0 {
            break;
        }
    }
}

/// Read sectors from disk using LBA28 addressing
///
/// # Arguments
/// * `lba` - Logical Block Address (sector number, 0-indexed)
/// * `count` - Number of sectors to read (0 means 256)
/// * `buffer` - Destination buffer (must be at least count * 512 bytes)
///
/// # Safety
/// Buffer must be large enough to hold count * 512 bytes
pub fn read_sectors(lba: u32, mut  buffer: &mut [u8]) -> u32 {
    let count = buffer.len().div_ceil(512) as u32;
    debug_assert!(lba + count <= (1 << 28), "LBA28 overflow");

    let port = PRIMARY_BASE;
    let slave = 0u8; // Master drive

    let mut remaining = count;
    let mut current_lba = lba;

    while remaining > 0 {
        // Can only request up to 256 sectors at a time (0 means 256)
        let batch = if remaining > 256 { 256 } else { remaining };
        let sector_count = if batch == 256 { 0u8 } else { batch as u8 };

        wait_disk_ready(port);

        // Set up LBA and flags: bits 24-27 of LBA, LBA mode (0xE0), slave bit
        outb(port + reg::LBA_24_27_FLAGS,
             ((current_lba >> 24) as u8 & 0x0F) | 0xE0 | (slave << 4));
        outb(port + reg::FEATURES, 0);
        outb(port + reg::SECTOR_COUNT, sector_count);
        outb(port + reg::LBA_0_7, current_lba as u8);
        outb(port + reg::LBA_8_15, (current_lba >> 8) as u8);
        outb(port + reg::LBA_16_23, (current_lba >> 16) as u8);
        outb(port + reg::COMMAND, cmd::READ_SECTORS);

        remaining -= batch;
        current_lba += batch;

        // Read each sector in this batch. One `rep insw` per sector, not 256
        // discrete `in`s: under a hypervisor each `in` is a VM exit, and at
        // 256 of them per sector an 8 KB read cost ~80 ms — long enough to
        // stall the audio pump and coalesce away the guest's timer ticks.
        for _ in 0..batch {
            wait_data_ready(port);

            let mut words = [0u16; 256];
            insw(port + reg::DATA, &mut words);
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

/// Write sectors to disk using LBA28 addressing — the write-direction twin of
/// [`read_sectors`], same batching and same `outsw`-per-sector rationale.
///
/// A short final chunk (buffer not a 512-multiple) is zero-padded to a full
/// sector, since a sector is the atomic unit of the transfer. The backing-file
/// overlay always writes block-aligned, so this padding is a safety net, not a
/// hot path.
///
/// # Arguments
/// * `lba` - Logical Block Address (sector number, 0-indexed)
/// * `buffer` - Source bytes; `buffer.len().div_ceil(512)` sectors are written
pub fn write_sectors(lba: u32, mut buffer: &[u8]) -> u32 {
    let count = buffer.len().div_ceil(512) as u32;
    debug_assert!(lba + count <= (1 << 28), "LBA28 overflow");

    let port = PRIMARY_BASE;
    let slave = 0u8; // Master drive

    let mut remaining = count;
    let mut current_lba = lba;

    while remaining > 0 {
        // Can only request up to 256 sectors at a time (0 means 256)
        let batch = if remaining > 256 { 256 } else { remaining };
        let sector_count = if batch == 256 { 0u8 } else { batch as u8 };

        wait_disk_ready(port);

        // Same register programming as the read, only the command differs.
        outb(port + reg::LBA_24_27_FLAGS,
             ((current_lba >> 24) as u8 & 0x0F) | 0xE0 | (slave << 4));
        outb(port + reg::FEATURES, 0);
        outb(port + reg::SECTOR_COUNT, sector_count);
        outb(port + reg::LBA_0_7, current_lba as u8);
        outb(port + reg::LBA_8_15, (current_lba >> 8) as u8);
        outb(port + reg::LBA_16_23, (current_lba >> 16) as u8);
        outb(port + reg::COMMAND, cmd::WRITE_SECTORS);

        remaining -= batch;
        current_lba += batch;

        // One `rep outsw` per sector — the same VM-exit amortization as the
        // read side (256 discrete `out`s per sector would be 256 exits).
        for _ in 0..batch {
            wait_data_ready(port);

            let mut bytes = [0u8; 512];
            let n = buffer.len().min(512);
            bytes[..n].copy_from_slice(&buffer[..n]); // tail (< 512) stays zero
            buffer = &buffer[n..];

            let mut words = [0u16; 256];
            for (w, pair) in words.iter_mut().zip(bytes.chunks_exact(2)) {
                *w = u16::from_le_bytes([pair[0], pair[1]]);
            }
            outsw(port + reg::DATA, &words);
        }
    }

    // Flush the drive's write cache so the data is durable before we report
    // success — the whole point of the backing-file overlay is persistence.
    wait_disk_ready(port);
    outb(port + reg::COMMAND, cmd::CACHE_FLUSH);
    wait_disk_ready(port);

    count
}
