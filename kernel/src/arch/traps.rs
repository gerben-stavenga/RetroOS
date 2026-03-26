//! Arch interrupt dispatch
//!
//! Ring-0 interrupt handler. Zero imports from kernel/ — all policy decisions
//! are returned to the ring-1 kernel as events via the execute() interface.

use crate::arch::irq::handle_irq;
use crate::arch::paging2::{self, RawPage};
use crate::{println, dbg_println};
use crate::arch::x86;
use crate::Regs;

// =============================================================================
// Arch call interface (ring-1 kernel → ring-0 arch via INT 0x80)
// =============================================================================

/// Saved ring-1 kernel context for returning from execute()
#[allow(static_mut_refs)]
static mut KERNEL_REGS: Option<Regs> = None;

/// Saved user regs from last execute() return — kernel reads this
/// to get the user thread's state after an event.
pub static mut USER_REGS: Regs = unsafe { core::mem::zeroed() };

/// Arch call numbers (ring-1 kernel → ring-0, via INT 0x80 with EAX=call#)
pub mod arch_call {
    pub const EXECUTE: u64 = 0x100;
}

/// Handle INT 0x80 from ring 1: arch primitive dispatch.
fn arch_dispatch(regs: &mut Regs) {
    match regs.rax {
        arch_call::EXECUTE => arch_execute(regs),
        _ => panic!("Unknown arch call: {:#x}", regs.rax),
    }
}

// Exit kernel and return to user mode (implemented in entry.asm)
unsafe extern "C" {
    fn exit_kernel(cpu_state: *const Regs, use_long_frame: u32) -> !;
}

/// Arch execute(): save kernel context, switch to user thread.
///
/// The kernel passes a pointer to the user Regs in EDX.
/// Arch loads those regs and IRETs to the user process.
/// When the user produces an event, arch saves user state to USER_REGS
/// and returns to the kernel's execute() call site with the event in EAX.
fn arch_execute(regs: &mut Regs) {
    // Save kernel's return context
    unsafe { KERNEL_REGS = Some(*regs); }

    // Read user regs pointer from EDX
    let user_regs_ptr = regs.rdx as usize as *const Regs;
    let user_regs = unsafe { &*user_regs_ptr };

    // TODO: activate address space, set TSS, mode toggle
    // For now, just IRET to user with the provided regs
    let is_long = user_regs.code_seg() == crate::arch::descriptors::USER_CS64 as u16;
    unsafe {
        exit_kernel(user_regs_ptr, is_long as u32);
    }
}

/// Return to ring-1 kernel with an event.
/// Saves user regs to USER_REGS, restores kernel context, sets EAX = int_num.
#[allow(static_mut_refs)]
fn return_to_kernel(regs: &mut Regs, int_num: u64) {
    // Save user state where kernel can read it
    unsafe { USER_REGS = *regs; }

    // Restore kernel context with event number in EAX
    let mut kregs = unsafe { KERNEL_REGS.take().unwrap() };
    kregs.rax = int_num;
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
    let source_ring = regs.code_seg() & 3;
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
    if (source_ring == 3 || vm86) && unsafe { KERNEL_REGS.is_some() } {
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
    // Skip null check for VM86 (legitimate IVT/BDA access)
    const NULL_LIMIT: usize = 0x10000;
    let vm86 = is_vm86(regs);
    if !vm86 && (fault_addr < NULL_LIMIT || fault_addr >= (0usize).wrapping_sub(NULL_LIMIT)) {
        return None; // Let kernel handle (segfault or panic)
    }

    // User tried to access kernel memory
    if user && fault_addr >= PAGE_TABLE_BASE {
        return None; // Let kernel handle (segfault)
    }

    // Kernel fault in kernel code/data region (not heap) is a bug
    if !user && fault_addr >= KERNEL_BASE {
        return None; // Let kernel handle (panic)
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

const VM_FLAG: u64 = 1 << 17;

fn is_vm86(regs: &Regs) -> bool {
    if Regs::use_f64() { return false; }
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
