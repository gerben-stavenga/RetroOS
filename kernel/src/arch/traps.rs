//! Arch interrupt dispatch
//!
//! Ring-0 interrupt handler. Zero imports from kernel/ — all policy decisions
//! are returned to the ring-1 kernel as events via the execute() interface.

#![allow(static_mut_refs)]

use crate::arch::irq::handle_irq;
use crate::arch::paging2::{self, Entry, RawPage};
use crate::{println, dbg_println};
use crate::arch::x86;
use crate::{Frame32, Frame64, Regs};

// =============================================================================
// Arch call interface (ring-1 kernel → ring-0 arch via INT 0x80)
// =============================================================================

// =============================================================================
// Arch state (Ring 0 maintains state for Ring 1 and Ring 3)
// =============================================================================


/// Full interrupt frame including optional VM86 segments.
/// CPU pushes ES, DS, FS, GS after SS:ESP for VM86 interrupts.
/// TSS ESP0 is set 16 bytes below stack top to always reserve room.
#[repr(C)]
struct FullRegs {
    regs: Regs,
    vm86_es: u32,
    vm86_ds: u32,
    vm86_fs: u32,
    vm86_gs: u32,
}

/// Register swap buffer. Holds user regs when kernel runs.
pub(crate) static mut REGS: Regs = Regs::empty();


/// Arch call numbers (ring-1 kernel → ring-0, via INT 0x80 with EAX=call#)
pub mod arch_call {
    pub const EXECUTE: u64 = 0x100;      // Swap kernel↔user regs
    pub const SWITCH_TO: u64 = 0x101;    // Thread switch: EDX=out_regs, ECX=out_root, EBX=in_regs, ESI=in_root
    pub const FORK: u64 = 0x105;         // COW fork. EDX=out RootPageTable. Returns new root phys in EAX.
    pub const CLEAN: u64 = 0x106;        // Free all user pages + flush TLB
    pub const SET_PAGE_FLAGS: u64 = 0x108; // EDX=start_vpage, ECX=count, EBX=flags (bit0=W, bit1=X)
    pub const MAP_LOW_MEM: u64 = 0x109;  // Map first 1MB user-accessible for VM86
    pub const FREE_PHYS_PAGE: u64 = 0x10A; // EDX=phys_page_number
    pub const SET_A20: u64 = 0x10C;      // EDX=enabled, ECX=HMA save area ptr
    pub const ZERO_PHYS_PAGE: u64 = 0x10D; // EDX=phys page number
    pub const MAP_EMS_WINDOW: u64 = 0x10E; // EDX=base_page, ECX=window, EBX=phys_pages ptr
    pub const MAP_UMB: u64 = 0x10F;      // EDX=base_page, ECX=count
    pub const UNMAP_UMB: u64 = 0x110;    // EDX=base_page, ECX=count
    pub const GET_TEMP_MAP_ADDR: u64 = 0x111; // Returns vaddr in EAX
    pub const INIT_HMA: u64 = 0x112;     // EDX=ptr to HMA save area
    pub const ACTIVATE_ROOT: u64 = 0x113; // EDX=ptr to RootPageTable
    pub const FLUSH_TLB: u64 = 0x114;    // Sync PDPT + re-write CR3
    pub const LOAD_LDT: u64 = 0x115;    // EDX=base, ECX=limit → load LDT
    pub const MAP_PHYS_RANGE: u64 = 0x116; // EDX=vpage_start, ECX=num_pages, EBX=ppage_start
    pub const SET_TLS_ENTRY: u64 = 0x117; // EDX=index(-1=auto), ECX=base, EBX=limit, ESI=flags. Returns index in EAX.
}

fn arch_dispatch(regs: &mut Regs) {
    match regs.rax {
        arch_call::EXECUTE => swap_regs(regs),
        arch_call::SWITCH_TO => arch_switch_to(regs),
        // FORK: EDX=child_root out. COW fork, fill child, free temp page.
        arch_call::FORK => {
            let child_root = regs.rdx as usize as *mut paging2::RootPageTable;
            let new_root_phys = paging2::fork_current().expect("Arch: Fork failed (OOM)");
            let mut cr = paging2::RootPageTable::empty();
            cr.init_fork(new_root_phys);
            crate::arch::phys_mm::free_phys_page(new_root_phys);
            unsafe { *child_root = cr; }
        }
        arch_call::CLEAN => paging2::free_user_pages(),
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
        arch_call::MAP_LOW_MEM => paging2::map_low_mem_user(),
        arch_call::FREE_PHYS_PAGE => { crate::arch::phys_mm::free_phys_page(regs.rdx); }
        arch_call::SET_A20 => {
            let enabled = regs.rdx != 0;
            let hma = unsafe { &mut *(regs.rcx as usize as *mut [paging2::Entry64; crate::vm86::HMA_PAGE_COUNT]) };
            paging2::set_a20(enabled, hma);
        }
        arch_call::ZERO_PHYS_PAGE => {
            paging2::temp_map(regs.rdx);
            unsafe { core::ptr::write_bytes(paging2::temp_map_vaddr() as *mut u8, 0, paging2::PAGE_SIZE); }
            paging2::temp_unmap();
        }
        arch_call::MAP_EMS_WINDOW => {
            let phys_ptr = regs.rbx as usize;
            let phys_pages = if phys_ptr == 0 { None }
                else { Some(unsafe { &*(phys_ptr as *const [u64; 4]) }) };
            paging2::map_ems_window(regs.rdx as usize, regs.rcx as usize, phys_pages);
        }
        arch_call::MAP_UMB => paging2::map_umb(regs.rdx as usize, regs.rcx as usize),
        arch_call::UNMAP_UMB => paging2::unmap_umb(regs.rdx as usize, regs.rcx as usize),
        arch_call::GET_TEMP_MAP_ADDR => { regs.rax = paging2::temp_map_vaddr() as u64; }
        arch_call::INIT_HMA => {
            let out = regs.rdx as usize as *mut [u64; crate::vm86::HMA_PAGE_COUNT];
            let zero_page = paging2::physical_page(&crate::ZERO_PAGE as *const _ as usize);
            let zero_entry = paging2::Entry64::new(zero_page, false, true);
            unsafe { for slot in (*out).iter_mut() { *slot = zero_entry.0; } }
        }
        arch_call::ACTIVATE_ROOT => {
            let root = unsafe { &*(regs.rdx as usize as *const paging2::RootPageTable) };
            root.activate();
        }
        arch_call::FLUSH_TLB => paging2::flush_tlb(),
        arch_call::LOAD_LDT => {
            crate::arch::descriptors::load_ldt(regs.rdx as u32, regs.rcx as u32);
        }
        arch_call::MAP_PHYS_RANGE => {
            let vpage_start = regs.rdx as usize;
            let num_pages = regs.rcx as usize;
            let ppage_start = regs.rbx as u64;
            let flags = regs.rdi;
            for i in 0..num_pages {
                paging2::map_user_page_phys(vpage_start + i, ppage_start + i as u64, flags);
            }
        }
        arch_call::SET_TLS_ENTRY => {
            let index = regs.rdx as i32;
            let base = regs.rcx as u32;
            let limit = regs.rbx as u32;
            let limit_in_pages = regs.rdi != 0;
            regs.rax = crate::arch::descriptors::set_tls_entry(index, base, limit, limit_in_pages) as u64;
        }
        _ => panic!("Unknown arch call: {:#x}", regs.rax),
    }
}

fn toggle_mode_if_needed(regs: &Regs) {
    use crate::UserMode;
    let need_toggle = match (paging2::cpu_mode(), regs.mode()) {
        (paging2::CpuMode::Pae, UserMode::Mode64) => true,
        (paging2::CpuMode::Compat, UserMode::VM86) => true,
        _ => false,
    };
    if need_toggle {
        paging2::sync_hw_pdpt();
        x86::flush_tlb();
        let saved = paging2::ensure_trampoline_mapped();
        let want_64 = regs.mode() == UserMode::Mode64;
        crate::arch::descriptors::toggle_mode(paging2::toggle_cr3(want_64));
        paging2::clear_trampoline(saved);
    }
}

fn swap_regs(regs: &mut Regs) {
    unsafe { core::mem::swap(regs, &mut *(&raw mut REGS)); }
}

/// Switch threads: swap live state with pointed-to state.
/// SWITCH_TO: EDX=regs_ptr, ECX=root_ptr, EBX=hash_ptr (0 = no hashing)
/// On entry: ptrs hold incoming state. On exit: ptrs hold saved outgoing state.
fn arch_switch_to(regs: &mut Regs) {
    let regs_ptr = regs.rdx as u32 as *mut Regs;
    let root_ptr = regs.rcx as u32 as *mut paging2::RootPageTable;
    let hash_ptr = regs.rbx as u32 as *mut u64;

    let expected = if !hash_ptr.is_null() {
        unsafe {
            let exp = *hash_ptr;
            *hash_ptr = paging2::hash_and_record();
            exp
        }
    } else { 0 };

    // Swap regs
    unsafe { core::mem::swap(&mut *regs_ptr, &mut REGS); }

    // Log incoming struct PDE[0] before swap
    let pre_pde0 = unsafe { (*root_ptr).e32[0].0 };

    // Swap root: swap entries in-place, then reload CR3
    unsafe { (&mut *root_ptr).swap_and_activate(); }

    if !hash_ptr.is_null() {
        let new_hash = paging2::hash_and_record();
        if expected != 0 && expected != new_hash {
            crate::println!("\x1b[91mHASH MISMATCH expected {:#018x} got {:#018x}\x1b[0m", expected, new_hash);
            paging2::print_recorded_diff(expected, new_hash);
        }
    }
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
pub extern "C" fn isr_handler(full: *mut FullRegs) {
    static mut VIF: bool = false;
    static mut VIP: bool = false;

    let full = unsafe { &mut *full };

    // Detect ring transition from raw frame before any conversion.
    // 32-bit same-privilege interrupts don't push ESP/SS, so from_32/to_32
    // would read/write beyond the frame. Ring-0 gets its own minimal path.
    let ring_transition = if paging2::cpu_mode() == paging2::CpuMode::Compat {
        full.regs.frame.cs & 3 != 0
    } else {
        let raw = unsafe { (&full.regs.frame as *const Frame64).cast::<Frame32>().read() };
        raw.eflags & VM_FLAG as u32 != 0 || raw.cs & 3 != 0
    };
    if !ring_transition {
        handle_ring0(full.regs.int_num & 0xFF, full.regs.err_code);
        return;
    }

    if paging2::cpu_mode() != paging2::CpuMode::Compat { full.regs.from_32(); }

    // Fix ESP from IRET to 16-bit SS: CPU only loads SP, upper bits are
    // kernel stack residue. Mask to 16 bits based on descriptor B bit.
    if !is_vm86(&full.regs) && full.regs.frame.ss & 4 != 0 {
        let ss = full.regs.frame.ss as u16;
        let ar: u32;
        let ok: u8;
        unsafe {
            core::arch::asm!(
                "lar {ar:e}, {sel:e}",
                "setz {ok}",
                sel = in(reg) ss as u32,
                ar = out(reg) ar,
                ok = out(reg_byte) ok,
            );
        }
        // LAR bit 22 = D/B (Big). If valid and B=0 → 16-bit stack.
        if ok != 0 && ar & (1 << 22) == 0 {
            full.regs.frame.rsp &= 0xFFFF;
        }
    }

    // Ring 3 entry canonicalization: VM86 segments + VIF↔IF swap
    let vm86 = is_vm86(&full.regs);
    let from_ring3 = vm86 || full.regs.frame.cs & 3 == 3;
    if vm86 {
        full.regs.es = full.vm86_es as u64;
        full.regs.ds = full.vm86_ds as u64;
        full.regs.fs = full.vm86_fs as u64;
        full.regs.gs = full.vm86_gs as u64;
    }
    if from_ring3 {
        // VME: hardware maintained VIF/VIP — read into statics
        if vm86 && x86::read_cr4() & x86::cr4::VME != 0 {
            unsafe {
                VIF = full.regs.frame.rflags & (1 << 19) != 0;
                VIP = full.regs.frame.rflags & (1 << 20) != 0;
            }
        }
        unsafe {
            // IF = static_VIF (kernel uses IF as virtual interrupt flag)
            if VIF { full.regs.frame.rflags |= 1 << 9; }
            else { full.regs.frame.rflags &= !(1 << 9); }
            // Restore VIP from static
            if VIP { full.regs.frame.rflags |= 1 << 20; }
            else { full.regs.frame.rflags &= !(1 << 20); }
        }
    }

    isr_handler_inner(&mut full.regs, from_ring3);

    // Mode toggle if output regs need different CPU mode
    toggle_mode_if_needed(&full.regs);

    // Ring 3 exit decanonicalization: VIF↔IF swap + VM86 segments
    let to_ring3 = is_vm86(&full.regs) || full.regs.frame.cs & 3 == 3;
    if to_ring3 {
        // Save virtual state to statics
        unsafe {
            VIF = full.regs.frame.rflags & (1 << 9) != 0;
            VIP = full.regs.frame.rflags & (1 << 20) != 0;
        }
        // VME: write VIF/VIP into EFLAGS for hardware management
        if is_vm86(&full.regs) && x86::read_cr4() & x86::cr4::VME != 0 {
            if unsafe { VIF } { full.regs.frame.rflags |= 1 << 19; }
            else { full.regs.frame.rflags &= !(1 << 19); }
            // VIP already at bit 20
        }
        // Force IF=1 for real interrupt delivery
        full.regs.frame.rflags |= 0x200;
    }
    if is_vm86(&full.regs) {
        full.vm86_es = full.regs.es as u32;
        full.vm86_ds = full.regs.ds as u32;
        full.vm86_fs = full.regs.fs as u32;
        full.vm86_gs = full.regs.gs as u32;
        full.regs.es = 0;
        full.regs.ds = 0;
        full.regs.fs = 0;
        full.regs.gs = 0;
    }

    if paging2::cpu_mode() != paging2::CpuMode::Compat { full.regs.to_32(); }
}

fn isr_handler_inner(regs: &mut Regs, from_ring3: bool) {
    // Mask to undo sign-extension from push imm8 for vectors >= 0x80
    let int_num = regs.int_num & 0xFF;
    regs.int_num = int_num;

    if from_ring3 {
        // User (ring 3 / VM86): handle IRQ, try page fault, return event to kernel
        let legacy_mode = is_vm86(regs) || (regs.frame.cs & 4) != 0;
        if (32..=47).contains(&int_num) { handle_irq(regs); }
        if int_num == 14 && try_handle_page_fault(regs.err_code, legacy_mode).is_some() { return; }
        swap_regs(regs);
        regs.rax = int_num;
        if int_num == 14 { regs.rdx = x86::read_cr2() as u64; }
    } else {
        // Kernel (ring 1): arch calls, page faults, IRQs
        match int_num {
            14 => {
                if try_handle_page_fault(regs.err_code, false).is_none() {
                    panic_with_regs("Unhandled page fault in kernel", regs);
                }
            }
            32..=47 => handle_irq(regs),
            0x80 => arch_dispatch(regs),
            _ => panic_with_regs("Unexpected interrupt in kernel", regs),
        }
    }
}

// =============================================================================
// Page fault handler (arch-level: demand paging + COW)
// =============================================================================

/// Try to handle a page fault. Returns Some(()) if resolved, None if not.
fn try_handle_page_fault(error: u64, legacy_mode: bool) -> Option<()> {
    use crate::arch::paging2::{KERNEL_BASE, PAGE_TABLE_BASE, page_idx};

    let fault_addr = x86::read_cr2() as usize;
    let present = (error & 1) != 0;
    let write = (error & 2) != 0;
    let user = (error & 4) != 0;
    let instruction_fetch = (error & 0x10) != 0;

    let page_index = page_idx(fault_addr);

    // Null pointer protection (first 64KB and last 64KB)
    // Skip for legacy mode (VM86/DPMI: legitimate IVT/BDA/conventional memory access)
    // and supervisor (ring-1 kernel setting up user memory).
    const NULL_LIMIT: usize = 0x10000;
    if !legacy_mode && user && (fault_addr < NULL_LIMIT || fault_addr >= (0usize).wrapping_sub(NULL_LIMIT)) {
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

    // Legacy mode (VM86/DPMI) shares code+data address space, so don't set NX
    let nx = paging2::nx_enabled() && !legacy_mode;
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
                demand_page(e, page_index, nx);
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

    // Walk from leaf upward to find the outermost R/O COW entry.
    // Must COW top-down: only the outermost share_and_copy establishes
    // correct refcounts for the levels below.
    let mut cow_idx = None;
    let mut idx = page_index;
    loop {
        if entries[idx].present() && !entries[idx].hw_writable() {
            if !entries[idx].writable() {
                return None;
            }
            cow_idx = Some(idx);
        }
        let parent = paging2::parent_index::<E>(idx);
        if parent == idx { break; }
        idx = parent;
    }
    if let Some(idx) = cow_idx {
        paging2::cow_entry(entries, idx);
        paging2::flush_tlb();
        return Some(());
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

/// Ring-0 interrupt handler. No frame conversion, no canonicalization.
/// Called before from_32/to_32 since 32-bit same-privilege interrupts
/// don't push ESP/SS.
fn handle_ring0(int_num: u64, error: u64) {
    match int_num {
        14 => {
            if try_handle_page_fault(error, false).is_none() {
                panic!("Unhandled page fault in arch: addr={:#x} err={:#x}", x86::read_cr2(), error);
            }
        }
        32..=47 => {
            let mut regs = Regs::empty();
            regs.int_num = int_num;
            handle_irq(&mut regs);
        }
        _ => panic!("Unhandled exception in arch: int={:#x} err={:#x}", int_num, error),
    }
}

const VM_FLAG: u64 = 1 << 17;

fn is_vm86(regs: &Regs) -> bool {
    regs.mode() == crate::UserMode::VM86
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
