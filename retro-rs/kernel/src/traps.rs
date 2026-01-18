//! CPU exception and trap handlers

use crate::irq::handle_irq;
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
    println!("EIP: {:#010x}  CS: {:#06x}", regs.eip, regs.cs);
    println!("Error: {:#010x}  Int: {:#04x}", regs.err_code, regs.int_num);
    println!("EAX: {:#010x}  EBX: {:#010x}  ECX: {:#010x}  EDX: {:#010x}",
             regs.eax, regs.ebx, regs.ecx, regs.edx);

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
    println!("Breakpoint at {:#x}", regs.eip);
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
fn page_fault(regs: &mut Regs) {
    use crate::paging2::{
        self, KERNEL_BASE, NUM_PAGES, PAGE_SIZE, PAGE_TABLE_BASE,
        page_idx, mode, entries_per_page,
    };
    use crate::phys_mm;

    let fault_addr = x86::read_cr2() as usize;
    let error = regs.err_code;

    // Error code bits:
    // bit 0: 0 = not present, 1 = protection violation
    // bit 1: 0 = read, 1 = write
    // bit 2: 0 = kernel, 1 = user
    let present = (error & 1) != 0;
    let write = (error & 2) != 0;
    let user = (error & 4) != 0;

    let page_index = page_idx(fault_addr);

    // Null pointer protection (first 64KB)
    const NULL_LIMIT: usize = 0x10000;
    if fault_addr < NULL_LIMIT {
        if user {
            segv_current_thread(regs, fault_addr);
            return;
        }
        panic_with_regs("Kernel null pointer dereference", regs);
    }

    // User mode tried to access kernel memory
    if user && fault_addr >= KERNEL_BASE {
        segv_current_thread(regs, fault_addr);
        return;
    }

    // Determine if this is a user page
    let entries = entries_per_page(mode());
    let kernel_start_idx = KERNEL_BASE / PAGE_SIZE / entries;
    let is_user_page = page_index < NUM_PAGES - entries + kernel_start_idx;

    if present {
        // Page is present but we got a fault - must be a write to read-only
        if !write {
            panic_with_regs("Read fault on present page", regs);
        }

        if paging2::is_cow(page_index) {
            // Copy-on-write page
            let phys_page = paging2::get_phys_page(page_index);
            let ref_count = phys_mm::get_ref_count(phys_page);

            if ref_count == 1 {
                // Not shared, just make it writable
                paging2::clear_cow(page_index);
                paging2::flush_tlb();
            } else {
                // Shared, need to copy
                phys_mm::free_phys_page(phys_page);

                // Allocate new page
                let new_page = match phys_mm::alloc_phys_page() {
                    Some(p) => p,
                    None => panic_with_regs("Out of memory on COW", regs),
                };

                // Copy the page contents
                let src = (fault_addr & !(PAGE_SIZE - 1)) as *const u8;
                let scratch = unsafe { &raw mut crate::SCRATCH };
                unsafe {
                    core::ptr::copy_nonoverlapping(src, scratch.cast::<u8>(), PAGE_SIZE);
                }

                // Update page entry
                paging2::set_entry(page_index, new_page, true, is_user_page, false);
                paging2::flush_tlb();

                // Copy back from scratch
                let dst = (fault_addr & !(PAGE_SIZE - 1)) as *mut u8;
                unsafe {
                    core::ptr::copy_nonoverlapping(scratch.cast::<u8>(), dst, PAGE_SIZE);
                }
            }
        } else {
            // Write to read-only page (not COW) - segfault
            if user {
                segv_current_thread(regs, fault_addr);
                return;
            }
            panic_with_regs("Kernel write to read-only page", regs);
        }
    } else {
        // Page not present - demand paging with zero page
        let zero_page = paging2::physical_page(&crate::ZERO_PAGE as *const _ as usize);
        paging2::set_entry(page_index, zero_page, false, is_user_page, true);
        paging2::flush_tlb();
    }
}

/// Signal current thread on segmentation fault
fn segv_current_thread(regs: &mut Regs, fault_addr: usize) {
    use crate::thread;

    println!("\x1b[91mSegmentation fault at {:#x} EIP={:#x}\x1b[0m", fault_addr, regs.eip);

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

        // Syscall
        0x80 => syscall(regs),

        _ => generic_exception(regs),
    }
}
