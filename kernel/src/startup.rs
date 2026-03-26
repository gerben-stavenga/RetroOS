//! Kernel startup - TAR filesystem and init loading
//!
//! Reads files from the TAR filesystem on disk and loads init.elf

extern crate alloc;

use alloc::vec;
use crate::paging2::{KERNEL_BASE, PAGE_TABLE_BASE};
use crate::stacktrace::SymbolData;
use crate::{elf, hdd};
use crate::println;
use crate::thread;
use crate::x86;
use lib::tar::TarHeader;

/// TAR block size (same as disk sector size)
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

/// Read sectors from disk using ATA PIO driver
fn read_sectors(lba: u32, buffer: &mut [u8]) -> u32 {
    hdd::read_sectors(lba, buffer)
}

/// Read TAR blocks
fn read_blocks(buffer: &mut [u8]) {
    unsafe {
        CURRENT_BLOCK += read_sectors(START_SECTOR + CURRENT_BLOCK, buffer);
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
        read_blocks(&mut header_buf);

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
pub fn read_file(buffer: &mut [u8]) {
    read_blocks(buffer);
}

/// TAR entry metadata returned by tar_entry_at_block
pub struct TarEntry {
    pub name: [u8; 100],
    pub name_len: usize,
    pub size: u32,
    pub data_block: u32,
    pub next_block: u32,
}

/// Read a TAR entry at the given block offset without touching CURRENT_BLOCK.
/// Returns None at end-of-archive.
pub fn tar_entry_at_block(block: u32) -> Option<TarEntry> {
    let mut buf = [0u8; BLOCK_SIZE];
    let lba = unsafe { START_SECTOR } + block;
    hdd::read_sectors(lba, &mut buf);
    let header = unsafe { &*(buf.as_ptr() as *const TarHeader) };
    if header.is_end() { return None; }
    let size = header.filesize() as u32;
    let data_blocks = header.data_blocks();
    let name_bytes = header.filename();
    let mut name = [0u8; 100];
    let name_len = name_bytes.len().min(100);
    name[..name_len].copy_from_slice(&name_bytes[..name_len]);
    Some(TarEntry {
        name,
        name_len,
        size,
        data_block: block + 1,
        next_block: block + 1 + data_blocks,
    })
}

/// Read raw sectors at a given TAR data block offset into buffer.
/// Returns number of sectors read.
pub fn read_data_at_block(block: u32, buffer: &mut [u8]) -> u32 {
    let lba = unsafe { START_SECTOR } + block;
    hdd::read_sectors(lba, buffer)
}

/// Startup: load and run init.elf
pub fn startup(start_sector: u32) -> ! {
    println!("Initializing filesystem at sector {:#x}", start_sector);

    init_fs(start_sector);

    // Load symbol table for stack traces
    crate::stacktrace::init_from_tar();

    // Find init.elf
    println!("Loading init.elf");

    let size = match find_file(b"init.elf") {
        Some(s) => s,
        None => panic!("init.elf not found"),
    };

    println!("init.elf size: {:#x}", size);

    let mut elf_buffer = vec![0u8; size];
    read_file(&mut elf_buffer);

    let loaded = match elf::load_elf(&elf_buffer) {
        Ok(e) => e,
        Err(_) => panic!("Failed to load init.elf"),
    };

    let symbols = SymbolData::new(elf_buffer.into_boxed_slice());

    println!("Entry point: {:#x}", loaded.entry);

    // Temporarily map trampoline so copy_trampoline's data is accessible,
    // then clear it — page 0xF is used by VM86 for the environment block.
    crate::paging2::ensure_trampoline_mapped();
    crate::paging2::clear_trampoline();

    // Set up user stack with argc=0 for _start(argc, argv)
    let stack_top = PAGE_TABLE_BASE as u32;
    let stack = stack_top - 12; // [dummy_ret=0] [argc=0] [argv=ptr]
    unsafe {
        *((stack_top - 4) as *mut u32) = stack;  // argv (non-null, never dereferenced since argc=0)
        *((stack_top - 8) as *mut u32) = 0;      // argc
        *((stack_top - 12) as *mut u32) = 0;     // dummy return address
    }
    println!("User stack: {:#x}", stack);

    // Create init thread (0 = use current address space)
    let init_thread = thread::create_thread(None, 0, true)
        .expect("Failed to create init thread");

    init_thread.symbols = symbols;
    thread::init_process_thread(init_thread, loaded.entry as u32, stack);
    println!("Starting init process...");

    // Drop to ring 1 — kernel event loop runs at CPL=1
    crate::descriptors::enter_ring1();
    println!("Running at ring 1");

    // Event loop: execute threads via arch INT, handle returned events
    let tid = init_thread.tid as usize;
    event_loop(tid);
}

/// Ring-1 kernel event loop.
/// Calls arch execute(tid) via INT 0x80. Arch switches to the user thread
/// and returns here when an event occurs (syscall, IRQ, fault).
fn event_loop(first_tid: usize) -> ! {
    let mut tid = first_tid;
    loop {
        let event = arch_execute(tid);
        match event {
            // Syscall: dispatch using the thread's saved state
            48 => {
                let thread = crate::thread::current();
                let result = crate::syscalls::dispatch(&mut thread.cpu_state);
                if let Some(next) = result.switch_to {
                    tid = next;
                }
            }
            // IRQs (32-47): already ACK'd+queued by arch, nothing to do
            32..=47 => {}
            // Everything else: for now just re-execute
            _ => {}
        }
    }
}

/// Call arch execute(tid) via INT 0x80.
/// Returns the interrupt number that caused the return.
#[inline(never)]
fn arch_execute(tid: usize) -> u32 {
    let event: u32;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("eax") crate::traps::arch_call::EXECUTE as u32 => event,
            in("edx") tid as u32,
            out("ecx") _,
            out("ebx") _,
            out("edi") _,
        );
    }
    event
}
