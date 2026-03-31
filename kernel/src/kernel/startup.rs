//! Kernel startup - TAR filesystem and init loading
//!
//! Reads files from the TAR filesystem on disk and loads init.elf

extern crate alloc;

use alloc::vec;
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
pub fn startup(start_sector: u32) -> ! {

    crate::kernel::thread::init_threading();

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
    let stack_top = elf::USER_STACK_TOP as u32;
    let stack = stack_top - 12; // [dummy_ret=0] [argc=0] [argv=ptr]
    unsafe {
        *((stack_top - 4) as *mut u32) = stack;  // argv (non-null, never dereferenced since argc=0)
        *((stack_top - 8) as *mut u32) = 0;      // argc
        *((stack_top - 12) as *mut u32) = 0;     // dummy return address
    }
    println!("User stack: {:#x}", stack);

    // Create init thread — root is empty; switch_to captures it when we first switch away
    let init_thread = thread::create_thread(None, crate::RootPageTable::empty(), true)
        .expect("Failed to create init thread");

    init_thread.symbols = symbols;
    println!("Starting init process...");

    // Thread 0 is running — its state goes in REGS, not cpu_state
    unsafe {
        (*(&raw mut crate::arch::traps::REGS)).init_user_process(loaded.entry as u32, stack);
    }

    event_loop(init_thread.tid as usize);
}

/// Ring-1 kernel event loop.
/// EXECUTE swaps kernel↔user regs. SWITCH_TO changes threads (root + mode toggle).
fn event_loop(first_tid: usize) -> ! {
    use crate::arch::traps::REGS;

    crate::dbg_println!("event_loop entered, tid={}", first_tid);
    let mut tid = first_tid;

    // REGS already set up by startup, page tables correct from boot
    thread::set_current(tid);

    loop {
        let thread = thread::get_thread(tid).expect("Invalid thread in event loop");
        let regs = unsafe { &mut *(&raw mut REGS) };
        drain_pending_irqs(thread, regs);

        let (event, extra) = do_arch_execute();

        let thread = thread::get_thread(tid).expect("Invalid thread in event loop");
        let regs = unsafe { &mut *(&raw mut REGS) };

        // Debug: log non-routine DPMI events
        if !(32..=47).contains(&event) {
            if regs.mode() == crate::UserMode::Mode32 && thread.dpmi.is_some() && event != 0x31 {
                crate::dbg_println!("DPMI ev={:#x} CS:EIP={:#06x}:{:#x} SP={:#x}",
                    event, regs.frame.cs as u16, regs.ip32(), regs.sp32() & 0xFFFF);
            } else if regs.mode() == crate::UserMode::VM86 && event != 13 {
                crate::dbg_println!("VM86 ev={:#x} CS:IP={:04x}:{:04x}",
                    event, regs.code_seg(), regs.ip32() as u16);
            }
        }

        let new_tid = match event {
            0x80 => crate::kernel::syscalls::dispatch(regs),
            32..=47 => None,
            13 if regs.mode() == crate::UserMode::VM86 => {
                crate::kernel::vm86::vm86_monitor(regs)
            }
            13 if regs.mode() == crate::UserMode::Mode32 && thread.dpmi.is_some() => {
                crate::kernel::dpmi::dpmi_monitor(thread, regs)
            }
            0x31 if regs.mode() == crate::UserMode::Mode32 && thread.dpmi.is_some() => {
                crate::kernel::dpmi::dpmi_int31(thread, regs)
            }
            14 => thread::signal_thread(thread, extra as usize),
            // DPMI exceptions 0-31 (except #GP and #PF which are handled above):
            // dispatch to client exception handler
            0..=31 if regs.mode() == crate::UserMode::Mode32 && thread.dpmi.is_some() => {
                crate::kernel::dpmi::dispatch_dpmi_exception(thread, regs, event)
            }
            // DPMI software INTs (0x30-0xFF have DPL=3, arrive as direct events)
            0x30..=0xFF if regs.mode() == crate::UserMode::Mode32 && thread.dpmi.is_some() => {
                crate::kernel::dpmi::dpmi_soft_int(thread, regs, event as u8)
            }
            _ if regs.mode() == crate::UserMode::Mode32 && thread.dpmi.is_some() => {
                crate::println!("DPMI: unexpected event {} at CS:EIP={:#06x}:{:#x}",
                    event, regs.frame.cs as u16, regs.ip32());
                Some(thread::exit_thread(-11))
            }
            _ if regs.mode() == crate::UserMode::VM86 => {
                let lin = (regs.code_seg() as u32) * 16 + regs.ip32() as u16 as u32;
                let bytes = unsafe { core::slice::from_raw_parts(lin as *const u8, 8) };
                panic!("VM86: unhandled event {} at {:04x}:{:04x} (lin={:#x}) bytes=[{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}]",
                    event, regs.code_seg(), regs.ip32() as u16, lin,
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7]);
            }
            _ => None,
        };

        if let Some(new_tid) = new_tid {
            if new_tid != tid {
                let (old, new) = thread::get_two_threads(tid, new_tid);
                arch_switch_to(&mut old.cpu_state, &mut old.root, &new.cpu_state, &new.root);
                tid = new_tid;
                thread::set_current(tid);
                // Reload LDT if switching to a DPMI thread
                let new_thread = thread::get_thread(tid).expect("Invalid thread");
                if let Some(ref dpmi) = new_thread.dpmi {
                    let ldt_ptr = dpmi.ldt.as_ptr() as u32;
                    let ldt_limit = (256 * 8 - 1) as u32;
                    arch_load_ldt(ldt_ptr, ldt_limit);
                }
            }
        }
    }
}

fn drain_pending_irqs(thread: &mut thread::Thread, regs: &mut crate::Regs) {
    // Skip VM86 IRQ delivery during DPMI real-mode simulation (INT 31h/0300h).
    // The VM86 mode was set up to run a single real-mode interrupt handler;
    // injecting timer/keyboard IRQs would corrupt the carefully prepared frame.
    let dpmi_rm_call = thread.dpmi.as_ref().map_or(false, |d| d.rm_save.is_some());
    if regs.mode() == crate::UserMode::VM86 && !dpmi_rm_call {
        let tp = thread as *mut thread::Thread;
        let ticks = crate::arch::irq::take_pending_ticks();
        for _ in 0..ticks {
            crate::kernel::vm86::deliver_irq(unsafe { &mut *tp }, regs, Some(crate::arch::irq::Irq::Tick));
        }
        crate::arch::irq::drain(|evt| {
            crate::kernel::vm86::deliver_irq(unsafe { &mut *tp }, regs, Some(evt));
        });
        // Flush: try to deliver pending interrupts blocked by ISR in previous iterations.
        crate::kernel::vm86::deliver_irq(unsafe { &mut *tp }, regs, None);
    } else if regs.mode() == crate::UserMode::Mode32 && thread.dpmi.is_some() {
        // DPMI protected-mode: queue into vpic/vkbd (same devices as VM86),
        // then deliver via PM interrupt vectors instead of IVT.
        let tp = thread as *mut thread::Thread;
        let ticks = crate::arch::irq::take_pending_ticks();
        for _ in 0..ticks {
            let due = unsafe { &mut *tp }.vm86.vpit.take_pending_irqs();
            for _ in 0..due {
                unsafe { &mut *tp }.vm86.vpic.push(0x08);
            }
        }
        crate::arch::irq::drain(|evt| {
            let t = unsafe { &mut *tp };
            match evt {
                crate::arch::irq::Irq::Key(sc) => {
                    t.vm86.vkbd.push(sc);
                    if t.vm86.vpic.isr & 0x02 == 0 && !t.vm86.vpic.has_pending_vec(0x09) {
                        t.vm86.vpic.push(0x09);
                    }
                }
                crate::arch::irq::Irq::Tick => {
                    t.vm86.vpic.push(0x08);
                }
            }
        });
        // Deliver one pending interrupt (same ISR/EOI discipline as VM86)
        // Also respect VIF: don't deliver while client has virtual interrupts disabled
        // (prevents delivery between EOI and IRET in handler)
        let t = unsafe { &mut *tp };
        let vif = t.dpmi.as_ref().map_or(true, |d| d.vif);
        if t.vm86.vpic.isr == 0 && vif {
            if let Some(vec) = t.vm86.vpic.pop() {
                // Clear VIF before entering handler (DPMI spec)
                t.dpmi.as_mut().unwrap().vif = false;
                crate::kernel::dpmi::deliver_hw_irq(t, regs, vec);
            }
        }
    } else {
        crate::arch::irq::drain(|evt| {
            if let crate::arch::irq::Irq::Key(sc) = evt {
                crate::kernel::keyboard::process_key(sc);
            }
        });
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

/// Switch threads: save outgoing regs+root, load incoming regs+root + mode toggle.
pub fn arch_switch_to(
    out_regs: &mut crate::Regs, out_root: &mut crate::RootPageTable,
    in_regs: &crate::Regs, in_root: &crate::RootPageTable,
) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::SWITCH_TO as u32,
            in("edx") out_regs as *mut _ as u32,
            in("ecx") out_root as *mut _ as u32,
            in("ebx") in_regs as *const _ as u32,
            in("edi") in_root as *const _ as u32,
        );
    }
}

/// COW fork the current address space. Fills child root.
/// Caller must save parent root after (fork modifies entries for COW).
pub fn arch_user_fork(child_root: &mut crate::RootPageTable) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::FORK as u32,
            in("edx") child_root as *mut _ as u32,
        );
    }
}

pub fn arch_user_clean() {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::CLEAN as u32,
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



/// Toggle A20 gate for VM86 mode.
pub fn arch_set_a20(enabled: bool, hma: &mut [u64; crate::kernel::vm86::HMA_PAGE_COUNT]) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::SET_A20 as u32,
            in("edx") enabled as u32,
            in("ecx") hma as *mut _ as u32,
        );
    }
}

/// Zero a physical page.
pub fn arch_zero_phys_page(phys: u64) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::ZERO_PHYS_PAGE as u32,
            in("edx") phys as u32,
        );
    }
}

/// Map/unmap an EMS page frame window.
pub fn arch_map_ems_window(base_page: usize, window: usize, phys_pages: Option<&[u64; 4]>) {
    let ptr = match phys_pages {
        Some(p) => p as *const _ as u32,
        None => 0u32,
    };
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::MAP_EMS_WINDOW as u32,
            in("edx") base_page as u32,
            in("ecx") window as u32,
            in("ebx") ptr,
        );
    }
}

/// Enable UMB region (clear page entries for demand paging).
pub fn arch_map_umb(base_page: usize, count: usize) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::MAP_UMB as u32,
            in("edx") base_page as u32,
            in("ecx") count as u32,
        );
    }
}

/// Disable UMB region (restore identity mapping).
pub fn arch_unmap_umb(base_page: usize, count: usize) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::UNMAP_UMB as u32,
            in("edx") base_page as u32,
            in("ecx") count as u32,
        );
    }
}

/// Get the temp-map reserved virtual address (heap must skip this page).
pub fn arch_temp_map_addr() -> usize {
    let addr: u32;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("eax") crate::arch::traps::arch_call::GET_TEMP_MAP_ADDR as u32 => addr,
        );
    }
    addr as usize
}

/// Initialize HMA save area with zero-page entries.
pub fn arch_init_hma(hma: &mut [u64; crate::kernel::vm86::HMA_PAGE_COUNT]) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::INIT_HMA as u32,
            in("edx") hma as *mut _ as u32,
        );
    }
}

/// Activate a root page table (switch CR3).
pub fn arch_activate_root(root: &crate::RootPageTable) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::ACTIVATE_ROOT as u32,
            in("edx") root as *const _ as u32,
        );
    }
}

/// Load LDT: write base+limit into GDT[12] and execute LLDT.
pub fn arch_load_ldt(base: u32, limit: u32) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::LOAD_LDT as u32,
            in("edx") base,
            in("ecx") limit,
        );
    }
}

/// Map a range of physical pages into user virtual space.
pub fn arch_map_phys_range(vpage_start: usize, num_pages: usize, ppage_start: u64) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::MAP_PHYS_RANGE as u32,
            in("edx") vpage_start as u32,
            in("ecx") num_pages as u32,
            in("ebx") ppage_start as u32,
        );
    }
}

/// Flush TLB.
pub fn arch_flush_tlb() {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::FLUSH_TLB as u32,
        );
    }
}

/// Free user pages in current address space (arch CLEAN call).
pub fn arch_free_user_pages() {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::traps::arch_call::CLEAN as u32,
        );
    }
}
