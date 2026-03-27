//! Kernel startup - TAR filesystem and init loading
//!
//! Reads files from the TAR filesystem on disk and loads init.elf

extern crate alloc;

use alloc::vec;
use crate::arch::paging2::PAGE_TABLE_BASE;
use crate::kernel::stacktrace::SymbolData;
use crate::kernel::{elf, hdd};
use crate::println;
use crate::kernel::thread;
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

/// Startup: load and run init.elf, then enter event loop.
/// Called from enter_ring1 — we are already at ring 1.
pub extern "C" fn startup(start_sector: usize) -> ! {
    let start_sector = start_sector as u32;
    println!("Initializing filesystem at sector {:#x}", start_sector);

    init_fs(start_sector);

    // Load symbol table for stack traces
    crate::kernel::stacktrace::init_from_tar();

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

    // Set up user stack with argc=0 for _start(argc, argv)
    let stack_top = PAGE_TABLE_BASE as u32;
    let stack = stack_top - 12; // [dummy_ret=0] [argc=0] [argv=ptr]
    unsafe {
        *((stack_top - 4) as *mut u32) = stack;  // argv (non-null, never dereferenced since argc=0)
        *((stack_top - 8) as *mut u32) = 0;      // argc
        *((stack_top - 12) as *mut u32) = 0;     // dummy return address
    }
    println!("User stack: {:#x}", stack);

    // Create init thread (capture current address space after ELF loaded)
    let mut root = crate::arch::paging2::RootPageTable::empty();
    arch_save_root(&mut root);
    let init_thread = thread::create_thread(None, root, true)
        .expect("Failed to create init thread");

    init_thread.symbols = symbols;
    thread::init_process_thread(init_thread, loaded.entry as u32, stack);
    println!("Starting init process...");

    // Enter event loop (already at ring 1)
    event_loop(init_thread.tid as usize);
}

/// Ring-1 kernel event loop.
/// Calls arch execute() via INT 0x80. Arch switches to the user thread
/// and returns here when an event occurs (syscall, IRQ, fault).
extern "C" fn event_loop(first_tid: usize) -> ! {
    crate::dbg_println!("event_loop entered, tid={}", first_tid);
    let mut tid = first_tid;
    loop {
        let thread = thread::get_thread(tid).expect("Invalid thread in event loop");
        thread::set_current(tid);

        // 1. Sync thread state TO Arch (load hardware context)
        set_arch_user_pages(&thread.root);
        set_arch_user_mode(match thread.mode {
            thread::ThreadMode::Mode16 => 0,
            thread::ThreadMode::Mode32 => 1,
            thread::ThreadMode::Mode64 => 2,
        });
        set_arch_user_regs(&thread.cpu_state);

        // 2. Switch to user mode via Arch primitive
        let (event, extra) = do_arch_execute();

        // 3. Sync thread state FROM Arch (hardware returned an event)
        get_arch_user_regs(&mut thread.cpu_state);
        arch_save_root(&mut thread.root);

        match event {
            // Syscall: dispatch using the thread's saved state
            48 => {
                if let Some(next) = crate::kernel::syscalls::dispatch(&mut thread.cpu_state) {
                    tid = next;
                }
            }
            // IRQs (32-47): drain queued events and deliver to thread
            32..=47 => {
                if thread.mode == thread::ThreadMode::Mode16 {
                    // VM86: deliver pending ticks + drain discrete events
                    // Use raw pointer to split the borrow between thread and cpu_state
                    let tp = thread as *mut thread::Thread;
                    let regs = unsafe { &mut (*tp).cpu_state };
                    let ticks = crate::arch::irq::take_pending_ticks();
                    for _ in 0..ticks {
                        crate::kernel::vm86::deliver_irq(unsafe { &mut *tp }, regs, Some(crate::arch::irq::Irq::Tick));
                    }
                    crate::arch::irq::drain(|evt| {
                        crate::kernel::vm86::deliver_irq(unsafe { &mut *tp }, regs, Some(evt));
                    });
                } else {
                    // Protected mode: feed scancodes to keyboard pipe
                    crate::arch::irq::drain(|evt| {
                        if let crate::arch::irq::Irq::Key(sc) = evt {
                            crate::kernel::keyboard::process_key(sc);
                        }
                    });
                }
                if let Some(next) = thread::schedule() {
                    tid = next;
                }
            }
            // Page fault (14): arch passes fault address in extra (EDX).
            14 => {
                let fault_addr = extra as usize;
                if let Some(next) = thread::signal_thread(thread, fault_addr) {
                    tid = next;
                }
            }
            // Everything else: for now just re-execute
            _ => {}
        }
    }
}

/// Call arch execute() via INT 0x80.
/// Returns (event_number, extra). Extra = fault address for event 14.
#[inline(never)]
fn do_arch_execute() -> (u32, u32) {
    let event: u32;
    let extra: u32;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("eax") crate::arch::traps::arch_call::EXECUTE as u32 => event,
            out("edx") extra,
            out("ecx") _,
            out("ebx") _,
            out("edi") _,
        );
    }
    (event, extra)
}

fn set_arch_user_pages(root: &crate::arch::paging2::RootPageTable) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::SET_USER_PAGES as u32,
            in("edx") root as *const _ as u32,
        );
    }
}

fn set_arch_user_mode(mode: u32) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::SET_USER_MODE as u32,
            in("edx") mode,
        );
    }
}

fn set_arch_user_regs(regs: &crate::Regs) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::SET_USER_REGS as u32,
            in("edx") regs as *const _ as u32,
        );
    }
}

fn get_arch_user_regs(regs: &mut crate::Regs) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::GET_USER_REGS as u32,
            in("edx") regs as *mut _ as u32,
        );
    }
}

/// Fork the current user address space. Fills `out` with the child's root page table.
/// Returns the physical page number of the child's root.
pub fn arch_user_fork(out: &mut crate::arch::paging2::RootPageTable) -> u64 {
    let new_root: u32;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("eax") crate::arch::traps::arch_call::FORK as u32 => new_root,
            in("edx") out as *mut _ as u32,
        );
    }
    new_root as u64
}

pub fn arch_user_clean() {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::CLEAN as u32,
        );
    }
}

pub fn arch_user_map(vpage: usize, ppage: u64) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::MAP as u32,
            in("edx") vpage as u32,
            in("ebx") ppage as u32,
        );
    }
}

/// Set page permissions for a range. flags: bit 0 = writable, bit 1 = executable.
pub fn arch_set_page_flags(start_vpage: usize, count: usize, writable: bool, executable: bool) {
    let flags = (writable as u32) | ((executable as u32) << 1);
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::SET_PAGE_FLAGS as u32,
            in("edx") start_vpage as u32,
            in("ecx") count as u32,
            in("ebx") flags,
        );
    }
}

/// Map first 1MB user-accessible for VM86.
pub fn arch_map_low_mem() {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::MAP_LOW_MEM as u32,
        );
    }
}

/// Free a physical page.
pub fn arch_free_phys_page(phys: u64) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::FREE_PHYS_PAGE as u32,
            in("edx") phys as u32,
        );
    }
}

/// Save current address space root into a RootPageTable.
pub fn arch_save_root(out: &mut crate::arch::paging2::RootPageTable) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::SAVE_ROOT as u32,
            in("edx") out as *mut _ as u32,
        );
    }
}
