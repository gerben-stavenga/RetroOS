//! CPU exception and trap handlers

use crate::irq::handle_irq;
use crate::paging2::{self, RawPage};
use crate::println;
use crate::syscalls::dispatch;
use crate::thread;
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

/// Panic with register dump and stack trace from the faulting frame
#[track_caller]
fn panic_with_regs(msg: &str, regs: &Regs) -> ! {
    x86::cli();
    println!("{:?}", regs);
    crate::stacktrace::stack_trace_from(regs.rbp as u32);
    panic!("{}", msg);
}

/// Handle divide error (int 0)
fn divide_error(regs: &Regs) -> ! {
    panic_with_regs("Divide by zero", regs);
}

/// Handle debug exception (int 1)
/// In VM86 or user mode, kill the thread instead of panicking.
fn debug_exception(regs: &mut Regs) -> Option<usize> {
    if is_vm86(regs) || regs.code_seg() & 3 != 0 {
        return segv_current_thread(regs, regs.ip() as usize);
    }
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
    println!("Breakpoint at {:04x}:{:#x} tid={}", regs.code_seg(), regs.ip(),
        if thread::is_initialized() { thread::current().tid } else { -1 });
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
/// Returns Some(idx) if a context switch is needed.
fn invalid_opcode(regs: &mut Regs) -> Option<usize> {
    if regs.code_seg() & 3 != 0 || is_vm86(regs) {
        // Debug: check if the ROM page mapping is corrupted
        if is_vm86(regs) {
            let cs = regs.code_seg() as u32;
            let ip = regs.ip() as u32;
            let linear = (cs << 4) + ip;
            let page = linear >> 12;
            // Check what physical page the PTE points to
            use crate::paging2::Entry;
            match crate::paging2::entries() {
                crate::paging2::Entries::E32(e) => {
                    let pte = e[page as usize];
                    println!("UD2: linear={:#x} page={:#x} PTE={:#x} (phys={:#x})",
                        linear, page, pte.raw(), pte.page());
                }
                crate::paging2::Entries::E64(e) => {
                    let pte = e[page as usize];
                    println!("UD2: linear={:#x} page={:#x} PTE={:#x} (phys={:#x})",
                        linear, page, pte.raw(), pte.page());
                }
            }
        }
        return segv_current_thread(regs, regs.ip() as usize);
    }
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
/// For VM86 threads, dispatches to the VM86 monitor instead of panicking.
/// Returns Some(idx) if a context switch is needed.
fn general_protection(regs: &mut Regs) -> Option<usize> {
    if is_vm86(regs) {
        return crate::vm86::vm86_monitor(regs);
    }
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
fn page_fault(regs: &mut Regs) -> Option<usize> {
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
    let access = if instruction_fetch { "fetch" } else if write { "write" } else { "read" };

    let page_index = page_idx(fault_addr);

    // Null pointer protection (first 64KB and last 64KB)
    // Catches both null and ~0 (e.g., (char*)-1 or null + negative offset)
    // Skip for VM86 threads — they legitimately access IVT (0x0000-0x03FF) and BDA
    const NULL_LIMIT: usize = 0x10000;
    let vm86_thread = thread::is_initialized() && thread::current().mode == thread::ThreadMode::Mode16;
    if !vm86_thread && (fault_addr < NULL_LIMIT || fault_addr >= (0 as usize).wrapping_sub(NULL_LIMIT)) {
        if user {
            return segv_current_thread(regs, fault_addr);
        }
        println!("Page fault: {} at {:#x} RIP={:#x}", access, fault_addr, regs.ip());
        panic_with_regs("Kernel null pointer dereference", regs);
    }

    // User mode tried to access kernel memory (PAGE_TABLE_BASE or above)
    if user && fault_addr >= PAGE_TABLE_BASE {
        return segv_current_thread(regs, fault_addr);
    }

    // Kernel fault in kernel code/data region is a bug
    if !user && fault_addr >= KERNEL_BASE {
        // Read all values into locals before any debug output
        let rip = regs.ip();
        let err = error;
        let addr = fault_addr as u64;
        unsafe {
            core::arch::asm!("cli");
            macro_rules! dbg_char {
                ($c:expr) => { core::arch::asm!("out dx, al", in("dx") 0xe9u16, in("al") $c) };
            }
            macro_rules! dbg_hex {
                ($val:expr) => {{
                    let v: u64 = $val;
                    let mut i = 60i32;
                    while i >= 0 {
                        let nib = ((v >> i) & 0xf) as u8;
                        let c = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
                        dbg_char!(c);
                        i -= 4;
                    }
                }};
            }
            dbg_char!(b'K'); dbg_char!(b'F'); dbg_char!(b' ');
            dbg_hex!(addr);
            dbg_char!(b' ');
            dbg_hex!(rip);
            dbg_char!(b' ');
            dbg_hex!(err);
            dbg_char!(b'\n');
            loop { core::arch::asm!("hlt"); }
        }
    }

    // Dispatch based on mode, then handle fault
    match paging2::entries() {
        paging2::Entries::E32(e) => {
            if present {
                return handle_protection_fault(e, regs, fault_addr, page_index, write, user, instruction_fetch);
            } else {
                demand_page(e, page_index, false);
            }
        }
        paging2::Entries::E64(e) => {
            if present {
                return handle_protection_fault(e, regs, fault_addr, page_index, write, user, instruction_fetch);
            } else {
                demand_page(e, page_index, paging2::nx_enabled());
            }
        }
    }
    None
}

/// Handle protection faults (present page, but access denied)
///
/// For write faults, walks up from leaf to root via parent_index(),
/// COWing any shared intermediate levels top-down, then handles the leaf.
/// Works uniformly for all paging depths (2-level, 3-level, 4-level).
fn handle_protection_fault<E: paging2::Entry>(
    entries: &mut [E],
    regs: &mut Regs,
    fault_addr: usize,
    page_index: usize,
    write: bool,
    user: bool,
    instruction_fetch: bool,
) -> Option<usize> {
    if instruction_fetch {
        if user {
            return segv_current_thread(regs, fault_addr);
        }
        panic_with_regs("Kernel executed non-executable page (NX violation)", regs);
    }

    if !write {
        panic_with_regs("Read fault on present page", regs);
    }

    // Walk from leaf upward to find the first !hw_writable entry.
    // Covers both user COW pages and demand-paged kernel page tables.
    // If higher levels are also R/O, the write inside cow_entry
    // will nested-fault and resolve them first.
    let mut idx = page_index;
    loop {
        if entries[idx].present() && !entries[idx].hw_writable() {
            if !entries[idx].writable() {
                if user { return segv_current_thread(regs, fault_addr); }
                panic_with_regs("Kernel write to read-only page", regs);
            }
            paging2::cow_entry(entries, idx);
            paging2::flush_tlb();
            return None;
        }
        let parent = paging2::parent_index::<E>(idx);
        if parent == idx {
            // Reached the recursive entry (fixed point) — stop
            break;
        }
        idx = parent;
    }

    // Protection fault but nothing is R/O — should not happen
    if user { return segv_current_thread(regs, fault_addr); }
    panic_with_regs("Unexpected write protection fault", regs);
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
    let is_user = page_index < paging2::recursive_idx();
    let mut e = E::new(zero_page, false, is_user);  // RW=false (zero page is read-only)
    // NX for user data pages only (not page tables)
    if use_nx && page_index < PAGE_TABLE_BASE_IDX {
        e.set_no_execute(true);
    }
    entries[page_index] = e;
    paging2::flush_tlb();
}

/// Signal current thread on segmentation fault.
/// Returns Some(idx) if a context switch is needed.
fn segv_current_thread(regs: &mut Regs, fault_addr: usize) -> Option<usize> {
    use crate::thread;

    println!("\x1b[91mSegmentation fault at {:#x} RIP={:#x}\x1b[0m", fault_addr, regs.ip());

    let thread = thread::current();
    thread::signal_thread(thread, fault_addr)
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

/// VM86 extra frame: when an interrupt occurs in VM86 mode, the CPU pushes
/// 4 extra segment registers (GS, FS, DS, ES) as u32 above the normal frame.
/// These sit at regs + sizeof(Regs) on the kernel stack.
/// On entry: copy them into regs.es/ds/fs/gs so handlers see real VM86 segments.
/// On exit: copy regs.es/ds/fs/gs back and zero the regs fields so
/// exit_interrupt_32 loads null (safe), and IRET pops real values from the extra frame.
const VM_FLAG: u64 = 1 << 17;

fn is_vm86(regs: &Regs) -> bool {
    // VM86 mode is only possible in PAE mode (Frame32).
    // In Compat mode (Frame64), VM86 cannot be active — skip the check.
    if Regs::use_f64() { return false; }
    unsafe { regs.frame.f32.eflags as u64 & VM_FLAG != 0 }
}

/// Swap VM86 extra segments into Regs on interrupt entry
unsafe fn vm86_swap_in(regs: &mut Regs) {
    unsafe {
        // Extra frame is right above Regs: [ES, DS, FS, GS] as u32
        // Layout at regs+sizeof(Regs): es(u32), ds(u32), fs(u32), gs(u32)
        let extra = (regs as *mut Regs).add(1) as *const u32;
        regs.es = *extra.add(0) as u64;
        regs.ds = *extra.add(1) as u64;
        regs.fs = *extra.add(2) as u64;
        regs.gs = *extra.add(3) as u64;
    }
}

/// Swap VM86 segments back from Regs to extra frame on interrupt exit
unsafe fn vm86_swap_out(regs: &mut Regs) {
    unsafe {
        let extra = (regs as *mut Regs).add(1) as *mut u32;
        *extra.add(0) = regs.es as u32;
        *extra.add(1) = regs.ds as u32;
        *extra.add(2) = regs.fs as u32;
        *extra.add(3) = regs.gs as u32;
    }
    // Zero regs segment fields so exit_interrupt_32 loads null (safe in protected mode)
    regs.es = 0;
    regs.ds = 0;
    regs.fs = 0;
    regs.gs = 0;
}

/// Main interrupt service routine - dispatches to specific handlers.
/// This is the ONLY place that calls switch_to_thread (via exit_kernel).
/// All handlers return normally so RAII works for heap-allocated locals.
#[unsafe(no_mangle)]
pub extern "C" fn isr_handler(regs: *mut Regs) {
    let regs = unsafe { &mut *regs };
    let int_num = regs.int_num;

    // VM86 segment swap on entry
    let vm86 = is_vm86(regs);
    if vm86 {
        unsafe { vm86_swap_in(regs); }
    }

    // Enable interrupts for most handlers (except low stack situation)
    // TODO: Check stack depth
    if int_num != 2 && int_num != 8 {
        x86::sti();
    }

    let switch_to: Option<usize> = match int_num {
        0 => divide_error(regs),
        1 => debug_exception(regs),  // mutable ref needed for VM86/user kill
        2 => nmi(regs),
        3 => { breakpoint(regs); None }
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
        32..=47 => {
            handle_irq(regs);

            let irq = int_num - 32;
            let mut sw = None;

            if thread::is_initialized() {
                // Queue signal on VM86 threads for IVT reflection
                let t = thread::current();
                if t.mode == thread::ThreadMode::Mode16 {
                    t.pending_signals |= 1 << irq;
                }

                // Timer preemption (IRQ 0, every 10ms at 1000 Hz)
                // Only preempt if interrupted from user mode (VM86 or RPL=3).
                // Never preempt kernel code — save_state would capture mid-syscall state.
                if irq == 0 && (vm86 || regs.code_seg() & 3 != 0) && crate::irq::get_ticks() % 10 == 0 {
                    let current = thread::current();
                    thread::save_state(current, regs);
                    current.state = thread::ThreadState::Ready;
                    sw = thread::schedule();
                }
            }
            sw
        }

        // Syscall (IDT entry 0x80 uses vector 48's handler)
        48 => dispatch(regs),

        _ => generic_exception(regs),
    };

    // If a handler requested a context switch, do it here.
    // This is the single exit point — all Rust locals above are dropped by RAII first.
    if let Some(idx) = switch_to {
        // Save current state if not already saved (exit/yield/preempt already saved)
        // For exec, the thread state was already set up by the handler.
        thread::switch_to_thread(idx);
    }

    // VM86: deliver pending signals, then swap segments back
    if vm86 {
        crate::vm86::deliver_pending_signals_inline(regs);
        unsafe { vm86_swap_out(regs); }
    }
}
