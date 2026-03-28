//! Arch interrupt dispatch
//!
//! Ring-0 interrupt handler. Zero imports from kernel/ — all policy decisions
//! are returned to the ring-1 kernel as events via the execute() interface.

#![allow(static_mut_refs)]

use crate::arch::irq::handle_irq;
use crate::arch::paging2::{self, Entry, RawPage};
use crate::{println, dbg_println};
use crate::arch::x86;
use crate::Regs;

// =============================================================================
// Arch call interface (ring-1 kernel → ring-0 arch via INT 0x80)
// =============================================================================

// =============================================================================
// Arch state (Ring 0 maintains state for Ring 1 and Ring 3)
// =============================================================================

/// Kernel state (Ring 1): saved registers when blocked in execute()
static mut KERNEL_STATE: Option<Regs> = None;

/// User state storage with padding for VM86 segments
#[repr(C)]
struct StoredUserState {
    regs: Regs,
    /// Space for 4 segments (ES, DS, FS, GS) pushed past Regs in VM86 mode
    vm86_padding: [u32; 4],
}

/// User state (Ring 3): Registers + Pages (root) + Mode
static mut USER_STATE: StoredUserState = StoredUserState {
    regs: Regs::empty(),
    vm86_padding: [0; 4],
};
static mut USER_ROOT: paging2::RootPageTable = paging2::RootPageTable::empty();
static mut USER_MODE: u32 = 1; // 0=VM86, 1=32-bit, 2=64-bit

/// Software VIF/VIP for CPUs without VME (386/486).
/// Saved from user EFLAGS before IRET, restored after trap.
static mut VIF_NO_VME: bool = false;
static mut VIP_NO_VME: bool = false;

/// Arch call numbers (ring-1 kernel → ring-0, via INT 0x80 with EAX=call#)
pub mod arch_call {
    /// Switch to the currently loaded User State
    pub const EXECUTE: u64 = 0x100;
    /// Copy Arch's USER_REGS to Ring 1 buffer (EDX=ptr)
    pub const GET_USER_REGS: u64 = 0x101;
    /// Copy Ring 1 buffer to Arch's USER_REGS (EDX=ptr)
    pub const SET_USER_REGS: u64 = 0x102;
    /// Load new User Pages (root) (EDX=ptr to RootPageTable)
    pub const SET_USER_PAGES: u64 = 0x103;
    /// Set User Mode (EDX: 0=VM86, 1=32, 2=64)
    pub const SET_USER_MODE: u64 = 0x104;
    /// COW fork. EDX=ptr to RootPageTable (filled with child entries).
    /// Returns new root phys in EAX.
    pub const FORK: u64 = 0x105;
    /// Free all current User Pages + flush TLB.
    pub const CLEAN: u64 = 0x106;
    /// Map a user page (EDX=vpage, EBX=phys_page).
    pub const MAP: u64 = 0x107;
    /// Set page flags for a range (EDX=start_vpage, ECX=count, EBX=flags).
    /// flags: bit 0 = writable, bit 1 = executable. Flushes TLB.
    pub const SET_PAGE_FLAGS: u64 = 0x108;
    /// Map first 1MB user-accessible for VM86.
    pub const MAP_LOW_MEM: u64 = 0x109;
    /// Free a physical page (EDX=phys_page_number as u64).
    pub const FREE_PHYS_PAGE: u64 = 0x10A;
    /// Save current address space root into EDX=ptr to RootPageTable.
    pub const SAVE_ROOT: u64 = 0x10B;
    /// Toggle A20 gate. EDX=enabled (0/1), ECX=ptr to [u64; 16] HMA save area.
    pub const SET_A20: u64 = 0x10C;
    /// Zero a physical page. EDX=phys page number.
    pub const ZERO_PHYS_PAGE: u64 = 0x10D;
    /// Map/unmap an EMS window. EDX=base_page, ECX=window(0-3), EBX=ptr to [u64;4] or 0 for unmap.
    pub const MAP_EMS_WINDOW: u64 = 0x10E;
    /// Enable UMB region (clear page entries). EDX=base_page, ECX=count.
    pub const MAP_UMB: u64 = 0x10F;
    /// Disable UMB region (restore identity mapping). EDX=base_page, ECX=count.
    pub const UNMAP_UMB: u64 = 0x110;
    /// Get the temp-map reserved virtual address. Returns in EAX.
    pub const GET_TEMP_MAP_ADDR: u64 = 0x111;
    /// Initialize HMA save area with zero-page entries. EDX=ptr to [u64; 16].
    pub const INIT_HMA: u64 = 0x112;
    /// Activate a root page table (write CR3). EDX=ptr to RootPageTable.
    pub const ACTIVATE_ROOT: u64 = 0x113;
    /// Flush TLB (sync PDPT + re-write CR3).
    pub const FLUSH_TLB: u64 = 0x114;
}

/// Handle INT 0x80 from ring 1: arch primitive dispatch.
fn arch_dispatch(regs: &mut Regs) {
    match regs.rax {
        arch_call::EXECUTE => arch_execute(regs),
        arch_call::GET_USER_REGS => {
            let ptr = regs.rdx as usize as *mut Regs;
            unsafe { *ptr = USER_STATE.regs; }
        }
        arch_call::SET_USER_REGS => {
            let ptr = regs.rdx as usize as *const Regs;
            unsafe { USER_STATE.regs = *ptr; }
        }
        arch_call::SET_USER_PAGES => {
            let ptr = regs.rdx as usize as *const paging2::RootPageTable;
            unsafe { USER_ROOT = *ptr; }
        }
        arch_call::SET_USER_MODE => {
            unsafe { USER_MODE = regs.rdx as u32; }
        }
        arch_call::FORK => {
            let out_ptr = regs.rdx as usize as *mut paging2::RootPageTable;
            let old_root = unsafe { USER_ROOT };
            unsafe { USER_ROOT.activate(); }
            let new_root_phys = paging2::fork_current().expect("Arch: Fork failed (OOM)");
            // Fill in the child's RootPageTable via temp_map (ring 0)
            let mut child_root = paging2::RootPageTable::empty();
            child_root.init_fork(new_root_phys);
            unsafe { *out_ptr = child_root; }
            unsafe { USER_ROOT = old_root; }
            regs.rax = new_root_phys;
        }
        arch_call::CLEAN => {
            paging2::free_user_pages();
        }
        arch_call::MAP => {
            let vpage = regs.rdx as usize;
            let ppage = regs.rbx as u64;
            paging2::map_user_page_phys(vpage, ppage);
        }
        arch_call::SET_PAGE_FLAGS => {
            let start = regs.rdx as usize;
            let count = regs.rcx as usize;
            let flags = regs.rbx as u32;
            let writable = flags & 1 != 0;
            let executable = flags & 2 != 0;
            match paging2::entries() {
                paging2::Entries::E32(e) => {
                    for i in 0..count {
                        set_page_flags_entry(e, (start + i) * paging2::PAGE_SIZE, writable, executable);
                    }
                }
                paging2::Entries::E64(e) => {
                    for i in 0..count {
                        set_page_flags_entry(e, (start + i) * paging2::PAGE_SIZE, writable, executable);
                    }
                }
            }
            paging2::flush_tlb();
        }
        arch_call::MAP_LOW_MEM => {
            paging2::map_low_mem_user();
        }
        arch_call::FREE_PHYS_PAGE => {
            let phys = regs.rdx;
            crate::arch::phys_mm::free_phys_page(phys);
        }
        arch_call::SAVE_ROOT => {
            let out = regs.rdx as usize as *mut paging2::RootPageTable;
            let mut root = paging2::RootPageTable::empty();
            root.init_current();
            unsafe { *out = root; }
        }
        arch_call::SET_A20 => {
            let enabled = regs.rdx != 0;
            let hma = unsafe { &mut *(regs.rcx as usize as *mut [paging2::Entry64; crate::vm86::HMA_PAGE_COUNT]) };
            paging2::set_a20(enabled, hma);
        }
        arch_call::ZERO_PHYS_PAGE => {
            let phys = regs.rdx;
            paging2::temp_map(phys);
            unsafe {
                core::ptr::write_bytes(paging2::temp_map_vaddr() as *mut u8, 0, paging2::PAGE_SIZE);
            }
            paging2::temp_unmap();
        }
        arch_call::MAP_EMS_WINDOW => {
            let base_page = regs.rdx as usize;
            let window = regs.rcx as usize;
            let phys_ptr = regs.rbx as usize;
            let phys_pages = if phys_ptr == 0 {
                None
            } else {
                Some(unsafe { &*(phys_ptr as *const [u64; 4]) })
            };
            paging2::map_ems_window(base_page, window, phys_pages);
        }
        arch_call::MAP_UMB => {
            let base_page = regs.rdx as usize;
            let count = regs.rcx as usize;
            paging2::map_umb(base_page, count);
        }
        arch_call::UNMAP_UMB => {
            let base_page = regs.rdx as usize;
            let count = regs.rcx as usize;
            paging2::unmap_umb(base_page, count);
        }
        arch_call::GET_TEMP_MAP_ADDR => {
            regs.rax = paging2::temp_map_vaddr() as u64;
        }
        arch_call::INIT_HMA => {
            let out = regs.rdx as usize as *mut [u64; crate::vm86::HMA_PAGE_COUNT];
            let zero_page = paging2::physical_page(&crate::ZERO_PAGE as *const _ as usize);
            let zero_entry = paging2::Entry64::new(zero_page, false, true);
            unsafe {
                let arr = &mut *out;
                for slot in arr.iter_mut() {
                    *slot = zero_entry.0;
                }
            }
        }
        arch_call::ACTIVATE_ROOT => {
            let root = unsafe { &*(regs.rdx as usize as *const paging2::RootPageTable) };
            root.activate();
        }
        arch_call::FLUSH_TLB => {
            paging2::flush_tlb();
        }
        _ => panic!("Unknown arch call: {:#x}", regs.rax),
    }
}

// Exit kernel and return to user mode (implemented in entry.asm)
unsafe extern "C" {
    fn exit_kernel(cpu_state: *const Regs, use_long_frame: u32) -> !;
}

/// Arch execute(): perform hardware switch to user mode.
///
/// Uses the USER_REGS, USER_ROOT, and USER_MODE currently stored in arch.
fn arch_execute(regs: &mut Regs) {
    // Save current Ring 1 kernel state
    unsafe { KERNEL_STATE = Some(*regs); }

    let root = unsafe { &mut USER_ROOT };
    let mode = unsafe { USER_MODE };

    // 1. Activate address space (Pages)
    let current_mode = paging2::cpu_mode();
    let want_64 = mode == 2;
    let want_vm86 = mode == 0;

    let need_toggle = match current_mode {
        paging2::CpuMode::Pae => want_64,
        paging2::CpuMode::Compat => want_vm86,
        _ => false,
    };

    if need_toggle {
        root.load_entries();
        paging2::sync_hw_pdpt();
        x86::flush_tlb();
        paging2::ensure_trampoline_mapped();
        crate::arch::descriptors::toggle_mode(paging2::toggle_cr3(want_64));
        paging2::clear_trampoline();
    } else {
        root.activate();
    }

    // 2. Update kernel stack in TSS (so interrupts return to Ring 0)
    let stack_top = unsafe { (crate::ARCH_STACK.as_ptr_range().end) as usize };
    if want_64 || x86::read_cr4() & x86::cr4::PAE != 0 {
        crate::arch::descriptors::set_kernel_stack_64(stack_top as u64);
    } else {
        crate::arch::descriptors::set_kernel_stack(stack_top as u32);
    }

    // 3. IRET to User Mode (Registers)
    let user_regs = unsafe { &mut USER_STATE.regs };
    if want_vm86 {
        // Without VME, save kernel-managed VIF/VIP before IRET (CPU won't preserve them)
        if x86::read_cr4() & x86::cr4::VME == 0 {
            unsafe {
                let flags = user_regs.frame.f64.rflags;
                VIF_NO_VME = flags & (1 << 19) != 0;
                VIP_NO_VME = flags & (1 << 20) != 0;
            }
        }
        // Force IF=1: IRET to VM86 loads all of EFLAGS including IF.
        // Prevent kernel from accidentally disabling hardware interrupts.
        unsafe { user_regs.frame.f64.rflags |= 0x200; }
        // Copy segments from Regs to VM86 "extra" stack area (past end of Regs struct)
        // exit_interrupt_32 expects these 4 segments to be at the end of the stack frame.
        unsafe { vm86_swap_out(user_regs); }
        // Zero internal segments to avoid loading invalid selectors in exit_interrupt_32
        user_regs.ds = 0;
        user_regs.es = 0;
        user_regs.fs = 0;
        user_regs.gs = 0;
    }

    // Kernel stores regs in f64 format. Convert to f32 if CPU uses 32-bit frames.
    let is_long = paging2::cpu_mode() == paging2::CpuMode::Compat;
    if !is_long {
        user_regs.frame_to_32();
    }

    unsafe {
        exit_kernel(user_regs, is_long as u32);
    }
}

/// Return to ring-1 kernel with an event.
/// Saves user regs to USER_STATE if coming from ring 3, restores kernel context, sets EAX = event.
#[allow(static_mut_refs)]
fn return_to_kernel(regs: &mut Regs, event: u64) {
    // Determine if we are returning from a user-mode event or a ring-1 arch call.
    // User-mode events must save their updated state so the kernel can see it.
    let user = raw_code_seg(regs) & 3 == 3 || is_vm86(regs);

    if user {
        unsafe {
            let vm86 = is_vm86(regs);
            if vm86 {
                vm86_swap_in(regs);
            }
            // Normalize to f64 so kernel always sees a uniform format
            if paging2::cpu_mode() != paging2::CpuMode::Compat {
                regs.frame_to_64();
            }
            USER_STATE.regs = *regs;
            // Without VME, restore kernel-managed VIF/VIP (CPU didn't preserve them)
            if vm86 && (x86::read_cr4() & x86::cr4::VME == 0) {
                let flags = &mut USER_STATE.regs.frame.f64.rflags;
                if VIF_NO_VME { *flags |= 1 << 19; } else { *flags &= !(1 << 19); }
                if VIP_NO_VME { *flags |= 1 << 20; } else { *flags &= !(1 << 20); }
            }
        }
    }

    // Restore Ring 1 kernel state with event in EAX, fault addr in EDX
    let mut kregs = unsafe { KERNEL_STATE.take().expect("Arch: KERNEL_STATE is None during return") };
    kregs.rax = event;
    if event == 14 {
        kregs.rdx = x86::read_cr2() as u64;
    }
    *regs = kregs;
}

// =============================================================================
// Interrupt dispatch
// =============================================================================

/// Main interrupt service routine.
///
/// Ring 1 (kernel): IRQ → ACK+queue+return. INT 0x80 → arch call. Trap → panic.
/// Ring 3 (user): save state, return event to ring-1 kernel.
/// Ring 0 (boot): page fault → demand paging. IRQ → ACK+queue. Rest → panic.
#[unsafe(no_mangle)]
pub extern "C" fn isr_handler(regs: *mut Regs) {
    let regs = unsafe { &mut *regs };
    let int_num = regs.int_num;
    let source_ring = raw_code_seg(regs) & 3;
    let vm86 = is_vm86(regs);

    // VM86 segment swap on entry
    if vm86 {
        unsafe { vm86_swap_in(regs); }
    }

    // =========================================================================
    // Ring 1: kernel was interrupted
    // =========================================================================
    if source_ring == 1 {
        match int_num {
            14 => {
                if try_handle_page_fault(regs).is_none() {
                    panic_with_regs("Unhandled page fault in ring-1 kernel", regs);
                }
            }
            32..=47 => handle_irq(regs),
            48 => arch_dispatch(regs),
            _ => panic_with_regs("Unexpected interrupt from ring-1 kernel", regs),
        }
        return;
    }

    // =========================================================================
    // Ring 3 (or VM86): user process was interrupted — return to kernel
    // =========================================================================
    #[allow(static_mut_refs)]
    if (source_ring == 3 || vm86) && unsafe { KERNEL_STATE.is_some() } {
        // ACK hardware IRQs
        if (32..=47).contains(&int_num) {
            handle_irq(regs);
        }

        // Handle page faults at arch level (demand paging / COW)
        if int_num == 14 {
            if let Some(()) = try_handle_page_fault(regs) {
                // Fault resolved, return to user
                if vm86 { unsafe { vm86_swap_out(regs); } }
                return;
            }
        }

        // Return event to ring-1 kernel
        if vm86 { unsafe { vm86_swap_out(regs); } }
        return_to_kernel(regs, int_num);
        return;
    }

    // =========================================================================
    // Ring 0 (boot, before event loop): minimal handling
    // =========================================================================
    match int_num {
        14 => {
            if try_handle_page_fault(regs).is_none() {
                panic_with_regs("Unhandled page fault during boot", regs);
            }
        }
        32..=47 => handle_irq(regs),
        _ => panic_with_regs("Unhandled exception during boot", regs),
    }

    if vm86 { unsafe { vm86_swap_out(regs); } }
}

// =============================================================================
// Page fault handler (arch-level: demand paging + COW)
// =============================================================================

/// Try to handle a page fault. Returns Some(()) if resolved, None if not.
fn try_handle_page_fault(regs: &mut Regs) -> Option<()> {
    use crate::arch::paging2::{KERNEL_BASE, PAGE_TABLE_BASE, page_idx};

    let fault_addr = x86::read_cr2() as usize;
    let error = regs.err_code;
    let present = (error & 1) != 0;
    let write = (error & 2) != 0;
    let user = (error & 4) != 0;
    let instruction_fetch = (error & 0x10) != 0;

    let page_index = page_idx(fault_addr);

    // Null pointer protection (first 64KB and last 64KB)
    // Skip for VM86 (legitimate IVT/BDA access) and supervisor (ring-1 kernel
    // setting up user memory, e.g. PSP/environment for DOS programs)
    const NULL_LIMIT: usize = 0x10000;
    let vm86 = is_vm86(regs);
    if !vm86 && user && (fault_addr < NULL_LIMIT || fault_addr >= (0usize).wrapping_sub(NULL_LIMIT)) {
        return None; // Let kernel handle (segfault or panic)
    }

    // User tried to access kernel memory
    if user && fault_addr >= PAGE_TABLE_BASE {
        return None; // Let kernel handle (segfault)
    }

    // Kernel fault in heap region: demand-page a real writable page
    if !user && fault_addr >= KERNEL_BASE && fault_addr < crate::kernel::heap::HEAP_END {
        let heap_start = crate::kernel::heap::heap_base();
        if fault_addr >= heap_start && !present {
            return Some(demand_page_kernel(fault_addr));
        }
        // Present fault or below heap_base in kernel space is a bug
        return None;
    }

    // Dispatch based on mode
    match paging2::entries() {
        paging2::Entries::E32(e) => {
            if present {
                handle_protection_fault(e, fault_addr, page_index, write, user, instruction_fetch)?;
            } else {
                demand_page(e, page_index, false);
            }
        }
        paging2::Entries::E64(e) => {
            if present {
                handle_protection_fault(e, fault_addr, page_index, write, user, instruction_fetch)?;
            } else {
                demand_page(e, page_index, paging2::nx_enabled());
            }
        }
    }
    Some(())
}

/// Handle protection faults (present page, but access denied)
fn handle_protection_fault<E: paging2::Entry>(
    entries: &mut [E],
    _fault_addr: usize,
    page_index: usize,
    write: bool,
    _user: bool,
    instruction_fetch: bool,
) -> Option<()> {
    if instruction_fetch || !write {
        return None; // Let kernel handle
    }

    // Walk from leaf upward to find the first !hw_writable entry
    let mut idx = page_index;
    loop {
        if entries[idx].present() && !entries[idx].hw_writable() {
            if !entries[idx].writable() {
                return None; // Not COW, let kernel handle
            }
            paging2::cow_entry(entries, idx);
            paging2::flush_tlb();
            return Some(());
        }
        let parent = paging2::parent_index::<E>(idx);
        if parent == idx { break; }
        idx = parent;
    }

    None // Unexpected, let kernel handle
}

/// Set final permissions on a page (for SET_PAGE_FLAGS arch call)
fn set_page_flags_entry<E: paging2::Entry>(entries: &mut [E], vaddr: usize, writable: bool, executable: bool) {
    let page = paging2::page_idx(vaddr);
    if entries[page].present() {
        let phys = entries[page].page();
        let mut entry = E::new(phys, writable, true);
        entry.set_writable(writable);
        entry.set_no_execute(!executable);
        entries[page] = entry;
        x86::invlpg(vaddr & !(paging2::PAGE_SIZE - 1));
    }
}

/// Demand page allocation for not-present pages
fn demand_page<E: paging2::Entry>(
    entries: &mut [E],
    page_index: usize,
    use_nx: bool,
) {
    use crate::arch::paging2::PAGE_TABLE_BASE_IDX;

    let zero_page = paging2::physical_page(&crate::ZERO_PAGE as *const _ as usize);
    let is_user = page_index < paging2::recursive_idx();
    let mut e = E::new(zero_page, false, is_user);
    if use_nx && page_index < PAGE_TABLE_BASE_IDX {
        e.set_no_execute(true);
    }
    entries[page_index] = e;
    paging2::flush_tlb();
}

// =============================================================================
// VM86 segment helpers
// =============================================================================

/// Demand-page a kernel heap page: allocate a real writable physical page.
fn demand_page_kernel(fault_addr: usize) {
    let phys = crate::arch::phys_mm::alloc_phys_page()
        .expect("Arch: OOM during kernel heap demand paging");
    let page_index = paging2::page_idx(fault_addr);
    match paging2::entries() {
        paging2::Entries::E32(e) => {
            e[page_index] = paging2::Entry32::new(phys, true, false);
        }
        paging2::Entries::E64(e) => {
            e[page_index] = paging2::Entry64::new(phys, true, false);
        }
    }
    paging2::flush_tlb();
}

/// Read code segment from raw interrupt frame (ring 0: knows CPU mode).
fn raw_code_seg(regs: &Regs) -> u16 {
    unsafe {
        if paging2::cpu_mode() == paging2::CpuMode::Compat {
            regs.frame.f64.cs as u16
        } else {
            regs.frame.f32.cs as u16
        }
    }
}

const VM_FLAG: u64 = 1 << 17;

fn is_vm86(regs: &Regs) -> bool {
    if paging2::cpu_mode() == paging2::CpuMode::Compat { return false; }
    unsafe { regs.frame.f32.eflags as u64 & VM_FLAG != 0 }
}

unsafe fn vm86_swap_in(regs: &mut Regs) {
    unsafe {
        let extra = (regs as *mut Regs).add(1) as *const u32;
        regs.es = *extra.add(0) as u64;
        regs.ds = *extra.add(1) as u64;
        regs.fs = *extra.add(2) as u64;
        regs.gs = *extra.add(3) as u64;
    }
}

unsafe fn vm86_swap_out(regs: &mut Regs) {
    unsafe {
        let extra = (regs as *mut Regs).add(1) as *mut u32;
        *extra.add(0) = regs.es as u32;
        *extra.add(1) = regs.ds as u32;
        *extra.add(2) = regs.fs as u32;
        *extra.add(3) = regs.gs as u32;
    }
    regs.es = 0;
    regs.ds = 0;
    regs.fs = 0;
    regs.gs = 0;
}

// =============================================================================
// Panic helper (no kernel dependencies)
// =============================================================================

#[track_caller]
fn panic_with_regs(msg: &str, regs: &Regs) -> ! {
    x86::cli();
    println!("{:?}", regs);
    panic!("{}", msg);
}
