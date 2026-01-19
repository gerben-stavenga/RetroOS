//! ATA/IDE PIO disk driver
//!
//! Simple polling-based driver for reading sectors from the primary ATA disk.
//! Uses LBA28 addressing mode, supporting disks up to 128GB.

use crate::x86::{inb, inw, outb};

/// ATA register offsets from base port
mod reg {
    pub const DATA: u16 = 0;           // Read/Write data (16-bit)
    pub const ERROR: u16 = 1;          // Error register (read)
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
}

/// Primary ATA controller base port
const PRIMARY_BASE: u16 = 0x1F0;

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
pub fn read_sectors(lba: u32, count: u32, buffer: *mut u8) {
    debug_assert!(lba + count <= (1 << 28), "LBA28 overflow");

    let port = PRIMARY_BASE;
    let slave = 0u8; // Master drive

    let mut p = buffer as *mut u16;
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

        // Read each sector in this batch
        for _ in 0..batch {
            wait_data_ready(port);

            // Read 256 words (512 bytes) per sector
            for _ in 0..256 {
                unsafe {
                    *p = inw(port + reg::DATA);
                    p = p.add(1);
                }
            }
        }
    }
}
