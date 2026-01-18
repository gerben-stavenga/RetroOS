//! Kernel startup - TAR filesystem and init loading
//!
//! Reads files from the TAR filesystem on disk and loads init.elf

use crate::{SCRATCH, elf};
use crate::paging2::{LOW_MEM_BASE, PAGE_SIZE};
use crate::println;
use crate::thread;
use crate::x86;
use lib::tar::TarHeader;

/// TAR block size
const BLOCK_SIZE: usize = 512;

/// Disk start sector for TAR filesystem
static mut START_SECTOR: u32 = 0;

/// Current TAR block position
static mut CURRENT_BLOCK: u32 = 0;

/// Initialize the filesystem with the start sector
pub fn init_fs(start_sector: u32) {
    unsafe {
        START_SECTOR = start_sector;
        CURRENT_BLOCK = 0;
    }
}

/// Read sectors from disk via BIOS (using low memory mapping)
fn read_sectors(lba: u32, count: u32, buffer: *mut u8) -> bool {
    // We can only use BIOS from real mode, which we can't do from kernel
    // Instead, we'll use the LOW_MEM_BASE mapping to access data
    // that was already loaded by the bootloader.
    //
    // For now, we assume the entire TAR is already in low memory
    // starting at a known address. This is a simplification.
    //
    // In a real implementation, we'd need a disk driver (IDE/ATA)
    // or store the filesystem in memory during boot.

    // The bootloader loads the TAR at 0x10000 (64KB mark)
    // We can access it via LOW_MEM_BASE + offset
    const TAR_BASE: usize = LOW_MEM_BASE + 0x10000;
    let offset = (lba as usize) * BLOCK_SIZE;
    let size = (count as usize) * BLOCK_SIZE;

    unsafe {
        let src = (TAR_BASE + offset) as *const u8;
        core::ptr::copy_nonoverlapping(src, buffer, size);
    }
    true
}

/// Read TAR blocks
fn read_blocks(count: u32, buffer: *mut u8) -> bool {
    unsafe {
        let result = read_sectors(START_SECTOR + CURRENT_BLOCK, count, buffer);
        if result {
            CURRENT_BLOCK += count;
        }
        result
    }
}

/// Skip TAR blocks
fn skip_blocks(count: u32) {
    unsafe {
        CURRENT_BLOCK += count;
    }
}

/// Seek to a specific block
fn seek_block(block: u32) {
    unsafe {
        CURRENT_BLOCK = block;
    }
}

/// Find a file in the TAR and return its size (or None if not found)
/// Also positions the reader at the file data
pub fn find_file(filename: &[u8]) -> Option<usize> {
    seek_block(0);

    let mut header_buf = [0u8; BLOCK_SIZE];

    loop {
        if !read_blocks(1, header_buf.as_mut_ptr()) {
            return None;
        }

        let header = unsafe { &*(header_buf.as_ptr() as *const TarHeader) };

        // Check for end of archive
        if header.is_end() {
            return None;
        }

        let file_size = header.filesize();
        let data_blocks = header.data_blocks();
        let name = header.filename();

        // Compare filename
        if name == filename {
            return Some(file_size);
        }

        // Skip file data
        skip_blocks(data_blocks);
    }
}

/// Read file data (must be called after find_file positioned us correctly)
pub fn read_file(buffer: *mut u8, size: usize) -> bool {
    let blocks = ((size + BLOCK_SIZE - 1) / BLOCK_SIZE) as u32;
    read_blocks(blocks, buffer)
}

/// Startup: load and run init.elf
pub fn startup(start_sector: u32) -> ! {
    println!("Initializing filesystem at sector {:#x}", start_sector);

    init_fs(start_sector);

    // Find init.elf
    let init_path = b"init.elf";
    println!("Loading init.elf");

    let size = match find_file(init_path) {
        Some(s) => s,
        None => {
            println!("Failed to find init.elf");
            loop {
                x86::cli();
                x86::hlt();
            }
        }
    };

    println!("init.elf size: {:#x}", size);

    // Allocate buffer for ELF (use scratch space in kernel pages)
    // For larger files we'd need proper memory allocation
    let buffer = unsafe { &raw mut SCRATCH }.cast::<u8>();

    if size > PAGE_SIZE {
        println!("init.elf too large for scratch buffer");
        loop {
            x86::cli();
            x86::hlt();
        }
    }

    if !read_file(buffer, size) {
        println!("Failed to read init.elf");
        loop {
            x86::cli();
            x86::hlt();
        }
    }

    // Load ELF into user address space
    let elf_data = unsafe { core::slice::from_raw_parts(buffer, size) };
    let entry = match elf::load_elf(elf_data) {
        Ok(e) => e,
        Err(_) => {
            println!("Failed to load ELF");
            loop {
                x86::cli();
                x86::hlt();
            }
        }
    };

    println!("Entry point: {:#x}", entry);

    // Create init thread
    let page_dir = x86::read_cr3();
    let init_thread = match thread::create_thread(None, page_dir, true) {
        Some(t) => t,
        None => {
            println!("Failed to create init thread");
            loop {
                x86::cli();
                x86::hlt();
            }
        }
    };

    // Initialize as user process
    thread::init_process_thread(init_thread, entry);

    println!("Starting init process...");

    // Switch to init thread (doesn't return)
    thread::exit_to_thread(init_thread);
}
