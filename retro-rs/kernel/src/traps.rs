//! CPU exception and trap handlers

use crate::irq::handle_irq;
use crate::paging2::{self, Entry, RawPage};
use crate::println;
use crate::x86;
use crate::Regs;

/// Exception names for debugging
const EXCEPTION_NAMES: [&str; 32] = [
    "Divide Error",             // 0
    "Debug",                    // 1
    "NMI",                      // 2
    "Breakpoint",               // 3
    "Overflow",                 // 4
    "Bound Range Exceeded",     // 5
    "Invalid Opcode",           // 6
    "Device Not Available",     // 7
    "Double Fault",             // 8
    "Coprocessor Segment",      // 9
    "Invalid TSS",              // 10
    "Segment Not Present",      // 11
    "Stack-Segment Fault",      // 12
    "General Protection",       // 13
    "Page Fault",               // 14
    "Reserved",                 // 15
    "x87 FPU Error",            // 16
    "Alignment Check",          // 17
    "Machine Check",            // 18
    "SIMD Exception",           // 19
    "Virtualization",           // 20
    "Control Protection",       // 21
    "Reserved",                 // 22
    "Reserved",                 // 23
    "Reserved",                 // 24
    "Reserved",                 // 25
    "Reserved",                 // 26
    "Reserved",                 // 27
    "Hypervisor Injection",     // 28
    "VMM Communication",        // 29
    "Security Exception",       // 30
    "Reserved",                 // 31
];

/// Panic with register dump
fn panic_with_regs(msg: &str, regs: &Regs) -> ! {
    x86::cli();
    println!();
    println!("\x1b[91m!!! KERNEL PANIC !!!\x1b[0m");
    println!("{}", msg);
    println!("{:?}", regs);

    loop {
        x86::cli();
        x86::hlt();
    }
}

/// Handle divide error (int 0)
fn divide_error(regs: &Regs) -> ! {
    panic_with_regs("Divide by zero", regs);
}

/// Handle debug exception (int 1)
fn debug_exception(regs: &Regs) -> ! {
    panic_with_regs("Debug exception", regs);
}

/// Handle NMI (int 2)
fn nmi(_regs: &Regs) -> ! {
    x86::cli();
    println!();
    println!("\x1b[91mNMI: Hardware failure\x1b[0m");
    loop {
        x86::hlt();
    }
}

/// Handle breakpoint (int 3)
fn breakpoint(regs: &mut Regs) {
    println!("Breakpoint at {:#x}", regs.ip());
    // Continue execution
}

/// Handle overflow (int 4)
fn overflow(regs: &Regs) -> ! {
    panic_with_regs("Overflow", regs);
}

/// Handle bound range exceeded (int 5)
fn bound_range(regs: &Regs) -> ! {
    panic_with_regs("Bound range exceeded", regs);
}

/// Handle invalid opcode (int 6)
fn invalid_opcode(regs: &Regs) -> ! {
    panic_with_regs("Invalid opcode", regs);
}

/// Handle device not available (int 7)
fn device_not_available(regs: &Regs) -> ! {
    panic_with_regs("FPU not available", regs);
}

/// Handle double fault (int 8)
fn double_fault(regs: &Regs) -> ! {
    panic_with_regs("Double fault (kernel bug)", regs);
}

/// Handle invalid TSS (int 10)
fn invalid_tss(regs: &Regs) -> ! {
    panic_with_regs("Invalid TSS", regs);
}

/// Handle segment not present (int 11)
fn segment_not_present(regs: &Regs) -> ! {
    panic_with_regs("Segment not present", regs);
}

/// Handle stack segment fault (int 12)
fn stack_segment(regs: &Regs) -> ! {
    panic_with_regs("Stack segment fault", regs);
}

/// Handle general protection fault (int 13)
fn general_protection(regs: &Regs) -> ! {
    println!("GP fault, selector: {:#x}", regs.err_code);
    panic_with_regs("General protection fault", regs);
}

/// Handle page fault (int 14)
///
/// Unified demand paging: all page table levels are allocated on demand.
/// The recursive mapping makes this elegant - every level looks like
/// "a page table for the level below."
///
/// Recursive mapping property (PAE):
/// - PTE for address X is at: PAGE_TABLE_BASE + (X >> 12) * 8
/// - Writing that PTE may fault if the parent level doesn't exist
/// - That fault is handled the same way, climbing up the hierarchy
/// - Recursion terminates at the self-referential PDPT entry (always present)
fn page_fault(regs: &mut Regs) {
    use crate::paging2::{KERNEL_BASE, PAGE_TABLE_BASE, page_idx};

    let fault_addr = x86::read_cr2() as usize;
    let error = regs.err_code;

    // Error code bits:
    // bit 0: 0 = not present, 1 = protection violation
    // bit 1: 0 = read, 1 = write
    // bit 2: 0 = kernel, 1 = user
    // bit 4: 0 = not instruction fetch, 1 = instruction fetch (NX violation)
    let present = (error & 1) != 0;
    let write = (error & 2) != 0;
    let user = (error & 4) != 0;
    let instruction_fetch = (error & 0x10) != 0;

    let page_index = page_idx(fault_addr);

    // Null pointer protection (first 64KB and last 64KB)
    // Catches both null and ~0 (e.g., (char*)-1 or null + negative offset)
    const NULL_LIMIT: usize = 0x10000;
    if fault_addr < NULL_LIMIT || fault_addr >= (0 as usize).wrapping_sub(NULL_LIMIT) {
        if user {
            segv_current_thread(regs, fault_addr);
            return;
        }
        panic_with_regs("Kernel null pointer dereference", regs);
    }

    // User mode tried to access kernel memory (PAGE_TABLE_BASE or above)
    if user && fault_addr >= PAGE_TABLE_BASE {
        segv_current_thread(regs, fault_addr);
        return;
    }

    // Kernel fault in kernel code/data region is a bug
    if !user && fault_addr >= KERNEL_BASE {
        panic_with_regs("Kernel fault in kernel range", regs);
    }

    // Dispatch based on mode, then handle fault
    match paging2::entries() {
        paging2::Entries::Legacy(e) => {
            if present {
                handle_protection_fault(e, regs, fault_addr, page_index, write, user, instruction_fetch);
            } else {
                demand_page(e, page_index, false);
            }
        }
        paging2::Entries::Pae(e) => {
            if present {
                handle_protection_fault(e, regs, fault_addr, page_index, write, user, instruction_fetch);
            } else {
                demand_page(e, page_index, paging2::nx_enabled());
            }
        }
    }
}

/// Handle protection fault for COW resolution (generic)
fn handle_cow_fault<E: paging2::Entry>(
    entries: &mut [E],
    regs: &mut Regs,
    fault_addr: usize,
    page_index: usize,
) {
    use crate::paging2::PAGE_SIZE;
    use crate::phys_mm;

    let phys_page = entries[page_index].page();
    let ref_count = phys_mm::get_ref_count(phys_page);

    if ref_count == 1 {
        // Not shared, just make it writable
        entries[page_index].set_writable(true);
        paging2::flush_tlb();
    } else {
        // Shared, need to copy before writing
        phys_mm::free_phys_page(phys_page);

        // Allocate new page
        let new_page = match phys_mm::alloc_phys_page() {
            Some(p) => p,
            None => panic_with_regs("Out of memory on write fault", regs),
        };

        // Copy the page contents
        let src = (fault_addr & !(PAGE_SIZE - 1)) as *const RawPage;
        unsafe {
            core::ptr::copy_nonoverlapping(src, &raw mut crate::SCRATCH, 1);
        }

        // Update page entry: writable, preserve U bit
        let user = entries[page_index].user();
        entries[page_index] = E::new(new_page, true, user);
        paging2::flush_tlb();

        // Copy back from scratch
        let dst = (fault_addr & !(PAGE_SIZE - 1)) as *mut RawPage;
        unsafe {
            core::ptr::copy_nonoverlapping(&raw const crate::SCRATCH, dst, 1);
        }
    }
}

/// Handle protection faults (present page, but access denied)
fn handle_protection_fault<E: paging2::Entry>(
    entries: &mut [E],
    regs: &mut Regs,
    fault_addr: usize,
    page_index: usize,
    write: bool,
    user: bool,
    instruction_fetch: bool,
) {
    if instruction_fetch {
        // NX violation - tried to execute non-executable page
        if user {
            segv_current_thread(regs, fault_addr);
            return;
        }
        panic_with_regs("Kernel executed non-executable page (NX violation)", regs);
    }

    if !write {
        panic_with_regs("Read fault on present page", regs);
    }

    if !entries[page_index].soft_ro() {
        handle_cow_fault(entries, regs, fault_addr, page_index);
    } else if user {
        segv_current_thread(regs, fault_addr);
    } else {
        panic_with_regs("Kernel write to read-only page", regs);
    }
}

/// Demand page allocation for not-present pages
///
/// All pages start as zero page with readonly=false (default), RW=false.
/// On write, the fault handler allocates a real page and sets RW=true.
/// This handles both user pages and page tables uniformly.
fn demand_page<E: paging2::Entry>(
    entries: &mut [E],
    page_index: usize,
    use_nx: bool,
) {
    use crate::paging2::PAGE_TABLE_BASE_IDX;

    let zero_page = paging2::physical_page(&crate::ZERO_PAGE as *const _ as usize);
    let is_user = page_index < E::USER_ENTRY_LIMIT;
    let mut e = E::new(zero_page, false, is_user);  // RW=false (zero page is read-only)
    // NX for user data pages only (not page tables)
    if use_nx && page_index < PAGE_TABLE_BASE_IDX {
        e.set_no_execute(true);
    }
    entries[page_index] = e;
    paging2::flush_tlb();
}

/// Signal current thread on segmentation fault
fn segv_current_thread(regs: &mut Regs, fault_addr: usize) {
    use crate::thread;

    println!("\x1b[91mSegmentation fault at {:#x} RIP={:#x}\x1b[0m", fault_addr, regs.ip());

    if let Some(thread) = thread::current() {
        thread::signal_thread(thread, fault_addr);
    } else {
        panic_with_regs("Segfault with no current thread", regs);
    }
}

/// Handle x87 FPU error (int 16)
fn fpu_error(regs: &Regs) -> ! {
    panic_with_regs("FPU error", regs);
}

/// Handle alignment check (int 17)
fn alignment_check(regs: &Regs) -> ! {
    panic_with_regs("Alignment check", regs);
}

/// Handle generic/unknown exception
fn generic_exception(regs: &Regs) -> ! {
    let int_num = regs.int_num as usize;
    let name = if int_num < 32 {
        EXCEPTION_NAMES[int_num]
    } else {
        "Unknown"
    };
    println!("Exception: {}", name);
    panic_with_regs("Unhandled exception", regs);
}

/// Handle syscall (int 0x80)
fn syscall(regs: &mut Regs) {
    crate::syscalls::dispatch(regs);
}

/// Main interrupt service routine - dispatches to specific handlers
#[unsafe(no_mangle)]
pub extern "C" fn isr_handler(regs: *mut Regs) {
    let regs = unsafe { &mut *regs };
    let int_num = regs.int_num;

    // Enable interrupts for most handlers (except low stack situation)
    // TODO: Check stack depth
    if int_num != 2 && int_num != 8 {
        x86::sti();
    }

    match int_num {
        0 => divide_error(regs),
        1 => debug_exception(regs),
        2 => nmi(regs),
        3 => breakpoint(regs),
        4 => overflow(regs),
        5 => bound_range(regs),
        6 => invalid_opcode(regs),
        7 => device_not_available(regs),
        8 => double_fault(regs),
        9 => generic_exception(regs), // Coprocessor segment overrun
        10 => invalid_tss(regs),
        11 => segment_not_present(regs),
        12 => stack_segment(regs),
        13 => general_protection(regs),
        14 => page_fault(regs),
        15 => generic_exception(regs), // Reserved
        16 => fpu_error(regs),
        17 => alignment_check(regs),
        18..=31 => generic_exception(regs),

        // IRQs (32-47)
        32..=47 => handle_irq(regs),

        // Syscall (IDT entry 0x80 uses vector 48's handler)
        48 => syscall(regs),

        _ => generic_exception(regs),
    }
}
