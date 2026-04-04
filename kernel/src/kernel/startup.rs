//! Kernel startup - filesystem mount and DN.COM loader

extern crate alloc;

extern crate ext4_view;

use alloc::vec;
use crate::kernel::{hdd, vfs, tarfs::TarFs, ext4fs::Ext4Fs};
use crate::println;
use crate::kernel::thread;

/// The root filesystem instance (static so it lives forever for &'static dyn)
static mut ROOT_TARFS: TarFs = TarFs::new(0);

/// Ext4 filesystem (heap-allocated at boot, leaked to get &'static)
static mut EXT4_FS: Option<&'static Ext4Fs> = None;

/// Startup: mount filesystem and run DN.COM in a loop.
/// Called from enter_ring1 — we are already at ring 1.
pub fn startup() -> ! {
    use crate::kernel::vm86;

    crate::kernel::thread::init_threading();

    // Reset ATA controller (needed when booted via GRUB)
    hdd::reset();

    // Read MBR sector 0 to get partition table
    let mut mbr = [0u8; 512];
    hdd::read_sectors(0, &mut mbr);

    // Scan MBR partition table: 4 entries at 0x1BE, each 16 bytes
    // Entry: [status, CHS_start(3), type, CHS_end(3), LBA_start(4), LBA_size(4)]
    let mut has_ext4 = false;
    for i in 0..4 {
        let base = 0x1BE + i * 16;
        let ptype = mbr[base + 4];
        let lba = u32::from_le_bytes(mbr[base + 8..base + 12].try_into().unwrap());
        if ptype == 0 { continue; }

        match ptype {
            0xDA => {
                // TAR filesystem
                println!("Partition {}: TAR at sector {:#x}", i, lba);
                unsafe {
                    ROOT_TARFS = TarFs::new(lba);
                }
            }
            0x83 if !has_ext4 => {
                // Linux ext4
                println!("Partition {}: ext4 at sector {:#x}", i, lba);
                match Ext4Fs::new(lba) {
                    Ok(fs) => {
                        let leaked = alloc::boxed::Box::leak(alloc::boxed::Box::new(fs));
                        unsafe { EXT4_FS = Some(leaked); }
                        vfs::mount(b"", leaked);
                        has_ext4 = true;
                        println!("  ext4 mounted as root");
                    }
                    Err(e) => println!("  ext4 mount failed: {}", e),
                }
            }
            _ => {}
        }
    }

    // Mount TAR: at "tar/" if ext4 is root, otherwise as root itself
    let tar_prefix: &[u8] = if has_ext4 { b"tar/" } else { b"" };
    #[allow(static_mut_refs)]
    unsafe { vfs::mount(tar_prefix, &ROOT_TARFS); }

    crate::kernel::stacktrace::init_from_tar();

    // DN.COM path depends on where TAR is mounted
    let dn_path: &[u8] = if has_ext4 { b"tar/DN/DN.COM" } else { b"DN/DN.COM" };

    loop {
        // Open and read DN.COM via VFS
        let fd = vfs::open(dn_path);
        if fd < 0 { panic!("DN.COM not found"); }
        let size = vfs::file_size(fd) as usize;
        let mut buf = vec![0u8; size];
        vfs::read(fd, &mut buf);
        vfs::close(fd);

        let t = thread::create_thread(None, crate::RootPageTable::empty(), true)
            .expect("Failed to create DN thread");
        let tid = t.tid as usize;

        // Set up VM86 address space in the current (boot) page tables.
        // The thread's root stays empty — event_loop captures it on first switch-away.
        arch_map_low_mem();
        vm86::setup_ivt();
        let (cs, ip, ss, sp, end_seg) = vm86::load_com(&buf, dn_path);

        t.mode = thread::ThreadMode::Dos;
        thread::init_process_thread_vm86(t, vm86::COM_SEGMENT, cs, ip, ss, sp);
        t.vm86.heap_seg = end_seg;
        t.vm86.dta = (vm86::COM_SEGMENT as u32) * 16 + 0x80;
        t.cwd_len = 0;

        unsafe { *(&raw mut crate::arch::REGS) = t.cpu_state; }

        println!("Starting DN...");
        event_loop(tid);
    }
}

const ASSERT_ADDR_HASH: bool = true;

/// Ring-1 kernel event loop. Returns when no threads remain.
/// EXECUTE swaps kernel↔user regs. SWITCH_TO changes threads (root + mode toggle).
fn event_loop(first_tid: usize) {
    use crate::arch::REGS;

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


        // F11 hotkey: force round-robin thread cycle
        let new_tid = if new_tid.is_none() && thread::take_switch_request() {
            thread::cycle_next()
        } else {
            new_tid
        };

        if let Some(new_tid) = new_tid {
            if new_tid == 0 { return; } // no threads left — respawn DN
            if new_tid != tid {
                let (old, new) = thread::get_two_threads(tid, new_tid);
                // Save/restore VGA state when switching between VM86 threads
                let old_vm86 = old.cpu_state.mode() == crate::UserMode::VM86;
                let new_vm86 = new.cpu_state.mode() == crate::UserMode::VM86;
                if old_vm86 {
                    old.vm86.vga.ac_flipflop = unsafe { crate::kernel::vm86::VGA_AC_FLIPFLOP };
                    old.vm86.vga.save_from_hardware();
                }
                let mut swap_regs = new.cpu_state;
                let mut swap_root = new.root;
                if ASSERT_ADDR_HASH {
                    let mut hash = new.addr_hash;
                    arch_switch_to(&mut swap_regs, &mut swap_root, &mut hash);
                    old.addr_hash = hash;
                } else {
                    arch_switch_to(&mut swap_regs, &mut swap_root, core::ptr::null_mut());
                }
                old.cpu_state = swap_regs;
                old.root = swap_root;
                if new_vm86 {
                    new.vm86.vga.restore_to_hardware();
                    unsafe { crate::kernel::vm86::VGA_AC_FLIPFLOP = new.vm86.vga.ac_flipflop; }
                }
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

/// F11 scancode (press)
const F11_PRESS: u8 = 0x57;

fn drain_pending_irqs(thread: &mut thread::Thread, regs: &mut crate::Regs) {
    let is_dos = regs.mode() == crate::UserMode::VM86
        || (regs.mode() == crate::UserMode::Mode32 && thread.dpmi.is_some());
    // Skip during DPMI real-mode simulation — injecting IRQs would corrupt the frame.
    let dpmi_rm_call = thread.dpmi.as_ref().map_or(false, |d| d.rm_save.is_some());
    if is_dos && !dpmi_rm_call {
        // QEMU VGA workaround: re-set Odd/Even read mode for text modes.
        if regs.mode() == crate::UserMode::VM86 {
            qemu_vga_workaround(regs);
        }
        // Queue hardware events into virtual PIC/keyboard (shared devices)
        let tp = thread as *mut thread::Thread;
        let ticks = crate::arch::take_pending_ticks();
        for _ in 0..ticks {
            crate::kernel::vm86::queue_irq(unsafe { &mut *tp }, crate::arch::Irq::Tick);
        }
        crate::arch::drain(|evt| {
            if let crate::arch::Irq::Key(F11_PRESS) = evt {
                thread::request_switch();
            } else {
                crate::kernel::vm86::queue_irq(unsafe { &mut *tp }, evt);
            }
        });
        // Deliver one pending interrupt (shared VIF/VIP/ISR discipline)
        crate::kernel::vm86::raise_pending(unsafe { &mut *tp }, regs);
    } else if !is_dos {
        crate::arch::drain(|evt| {
            if let crate::arch::Irq::Key(sc) = evt {
                if sc == F11_PRESS {
                    thread::request_switch();
                } else {
                    crate::kernel::keyboard::process_key(sc);
                }
            }
        });
    }
}

/// QEMU VGA bug workaround: real VGA hardware forces Odd/Even read mode
/// (GC5 bit 4) in text modes. QEMU doesn't, so re-set it on each trap.
fn qemu_vga_workaround(regs: &crate::Regs) {
    unsafe {
        if regs.cs32() < 0xC000 {
            let mode = *(0x449 as *const u8);
            if mode <= 3 || mode == 7 {
                let saved_idx = crate::arch::inb(0x3CE);
                crate::arch::outb(0x3CE, 5);
                let gc5 = crate::arch::inb(0x3CF);
                if gc5 & 0x10 == 0 {
                    crate::arch::outb(0x3CF, gc5 | 0x10);
                }
                crate::arch::outb(0x3CE, saved_idx);
            }
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
            inout("eax") crate::arch::arch_call::EXECUTE as u32 => event,
            out("edx") extra,
            out("ecx") _,
            out("ebx") _,
            out("edi") _,
        );
    }
    (event, extra)
}

/// Switch threads: swap live state with pointed-to state.
/// On entry: ptrs hold incoming state. On exit: ptrs hold saved outgoing state.
/// hash_ptr: null = no hashing. Non-null: on entry = expected hash (0=don't check),
/// on exit = old address space hash.
pub fn arch_switch_to(
    regs: &mut crate::Regs, root: &mut crate::RootPageTable,
    hash_ptr: *mut u64,
) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::SWITCH_TO as u32,
            in("edx") regs as *mut _ as u32,
            in("ecx") root as *mut _ as u32,
            in("ebx") hash_ptr as u32,
        );
    }
}

/// COW fork the current address space. Fills child root.
/// Caller must save parent root after (fork modifies entries for COW).
pub fn arch_user_fork(child_root: &mut crate::RootPageTable) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::FORK as u32,
            in("edx") child_root as *mut _ as u32,
        );
    }
}

pub fn arch_user_clean() {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::CLEAN as u32,
        );
    }
}



/// Set page permissions for a range. flags: bit 0 = writable, bit 1 = executable.
pub fn arch_set_page_flags(start_vpage: usize, count: usize, writable: bool, executable: bool) {
    let flags = (writable as u32) | ((executable as u32) << 1);
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::SET_PAGE_FLAGS as u32,
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
            in("eax") crate::arch::arch_call::MAP_LOW_MEM as u32,
        );
    }
}

/// Free a physical page.
pub fn arch_free_phys_page(phys: u64) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::FREE_PHYS_PAGE as u32,
            in("edx") phys as u32,
        );
    }
}



/// Toggle A20 gate for VM86 mode.
pub fn arch_set_a20(enabled: bool, hma: &mut [u64; crate::kernel::vm86::HMA_PAGE_COUNT]) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::SET_A20 as u32,
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
            in("eax") crate::arch::arch_call::ZERO_PHYS_PAGE as u32,
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
            in("eax") crate::arch::arch_call::MAP_EMS_WINDOW as u32,
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
            in("eax") crate::arch::arch_call::MAP_UMB as u32,
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
            in("eax") crate::arch::arch_call::UNMAP_UMB as u32,
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
            inout("eax") crate::arch::arch_call::GET_TEMP_MAP_ADDR as u32 => addr,
        );
    }
    addr as usize
}

/// Initialize HMA save area with zero-page entries.
pub fn arch_init_hma(hma: &mut [u64; crate::kernel::vm86::HMA_PAGE_COUNT]) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::INIT_HMA as u32,
            in("edx") hma as *mut _ as u32,
        );
    }
}

/// Activate a root page table (switch CR3).
pub fn arch_activate_root(root: &crate::RootPageTable) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::ACTIVATE_ROOT as u32,
            in("edx") root as *const _ as u32,
        );
    }
}

/// Load LDT: write base+limit into GDT[12] and execute LLDT.
pub fn arch_load_ldt(base: u32, limit: u32) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::LOAD_LDT as u32,
            in("edx") base,
            in("ecx") limit,
        );
    }
}

/// Map a range of physical pages into user virtual space.
pub fn arch_map_phys_range(vpage_start: usize, num_pages: usize, ppage_start: u64, flags: u64) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::MAP_PHYS_RANGE as u32,
            in("edx") vpage_start as u32,
            in("ecx") num_pages as u32,
            in("ebx") ppage_start as u32,
            in("edi") flags as u32,
        );
    }
}

/// Flush TLB.
pub fn arch_flush_tlb() {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::FLUSH_TLB as u32,
        );
    }
}

/// Free user pages in current address space (arch CLEAN call).
pub fn arch_free_user_pages() {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::CLEAN as u32,
        );
    }
}
