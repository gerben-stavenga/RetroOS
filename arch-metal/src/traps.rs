//! Arch interrupt dispatch
//!
//! Ring-0 interrupt handler. Zero imports from kernel/ — all policy decisions
//! are returned to the ring-1 kernel as events via the execute() interface.

#![allow(static_mut_refs)]

#[cfg(not(feature = "kvm"))]
use crate::irq::handle_irq;
use crate::paging2;
use crate::x86;
use arch_abi::{Regs, UserMode};
use arch_abi::entry::{KernelCall, CallOutcome};

// =============================================================================
// Arch call interface (ring-1 kernel → ring-0 arch via INT 0x80)
// =============================================================================

// =============================================================================
// Arch state (Ring 0 maintains state for Ring 1 and Ring 3)
// =============================================================================

/// Parked app frame between kernel calls. During a syscall it holds the
/// kernel continuation while the app frame is on the physical trap stack.
#[cfg(not(feature = "kvm"))]
#[thread_local]
static mut REGS: Regs = Regs::empty();

// While Arch::execute is in flight, point directly at the event loop's
// register object.  The ring-1 entry and ring-3 exit can then exchange their
// physical trap frames with that object instead of bouncing the same 216-byte
// register file through REGS before and after every run.
#[cfg(not(feature = "kvm"))]
#[thread_local]
static mut EXECUTE_REGS: *mut Regs = core::ptr::null_mut();

#[cfg(not(feature = "kvm"))]
pub(crate) fn set_execute_regs(regs: *mut Regs) {
    unsafe {
        // Once execute returns, retain the current app frame for ordinary
        // kernel calls too. The caller-owned register borrow ends here.
        if regs.is_null() && !EXECUTE_REGS.is_null() {
            REGS = *EXECUTE_REGS;
        }
        EXECUTE_REGS = regs;
    }
}


/// Arch call numbers (ring-1 kernel → ring-0, via INT 0x80 with EAX=call#)
pub mod arch_call {
    pub const REARRANGE_MAPPINGS: u64 = 0x133;
    pub const READ_MAPPINGS: u64 = 0x12E;
    pub const REPLACE_MAPPINGS: u64 = 0x12F;
    pub const FILL_MAPPINGS: u64 = 0x130;
    pub const READ_MAPPING_RUN: u64 = 0x131;
    pub const REFRESH_KERNEL: u64 = 0x12C;
    pub const INTERRUPT_PROCESSOR: u64 = 0x12D;
    pub const FRAME_OPERATION: u64 = 0x129; // EDX=frame request
    pub const HIGH_MEMORY: u64 = 0x128; // EDX=request pointer
    pub const EXECUTE: u64 = 0x100;      // Swap kernel↔user regs
    pub const ACTIVATE: u64 = 0x101;     // EDX=in/out page-table root
    pub const CHECK_ADDRESS_SPACE: u64 = 0x132; // EDX=in/out diagnostic hash
    pub const SWITCH_FX: u64 = 0x102;    // Swap live FPU/SSE with EDX save area
    pub const FORK: u64 = 0x105;         // COW fork. EDX=out RootPageTable. Returns new root phys in EAX.
    pub const CLEAN: u64 = 0x106;        // Free all user pages + flush TLB
    pub const LOAD_LDT: u64 = 0x115;    // EDX=base, ECX=limit → load LDT
    pub const MAP_KERNEL_PHYSICAL: u64 = 0x116; // EDX=vpage_start ECX=num_pages EBX=ppage_lo ESI=ppage_hi EDI=flags
    pub const SET_TLS_ENTRY: u64 = 0x117; // EDX=index(-1=auto), ECX=base, EBX=limit, ESI=flags. Returns index in EAX.
    #[allow(dead_code)]
    pub const HASH_PHYS_PAGE: u64 = 0x118; // EDX=phys_page_num. Returns FNV-1a u64 hash of that physical page in EAX.
    pub const SET_DEBUG_WATCH: u64 = 0x119; // EBX=count, EDX/ECX=watched linear addrs
    pub const ISA_UNMASK_IRQ: u64 = 0x11C;         // EDX=irq line — re-unmask a deferred-ack Hw line
    pub const HALT: u64 = 0x11F;              // cli + hlt forever at ring 0 (never returns)
    pub const REMAP_PHYSICAL_APERTURE: u64 = 0x121; // EDX/ECX=physical base low/high
    pub const RELEASE_HEAP: u64 = 0x122; // EDX=heap address, ECX=byte length
    pub const IDLE: u64 = 0x126; // EDX:ECX = maximum wait in nanoseconds
    pub const REPLACE_INTERRUPT_HANDLERS: u64 = 0x124; // EDX=in/out handler pair, ECX=vector
}

#[thread_local]
static DEBUG_WATCH_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[thread_local]
static DEBUG_WATCH_ADDR0: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[thread_local]
static DEBUG_WATCH_ADDR1: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[thread_local]
static DEBUG_WATCH_USER_HITS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[thread_local]
static DEBUG_WATCH_KERNEL_HITS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn debug_watch_value(addr: u32) -> u16 {
    unsafe { core::ptr::read_unaligned(addr as *const u16) }
}

fn debug_watch_trap(regs: &Regs, dr6: u32, kernel: bool) -> bool {
    use core::sync::atomic::Ordering;

    let count = DEBUG_WATCH_COUNT.load(Ordering::Relaxed);
    if count == 0 || dr6 & 0x3 == 0 {
        return false;
    }

    let addr0 = DEBUG_WATCH_ADDR0.load(Ordering::Relaxed);
    let addr1 = DEBUG_WATCH_ADDR1.load(Ordering::Relaxed);
    let value0 = if count >= 1 { debug_watch_value(addr0) } else { 0 };
    let value1 = if count >= 2 { debug_watch_value(addr1) } else { 0 };
    let hits = if kernel {
        DEBUG_WATCH_KERNEL_HITS.fetch_add(1, Ordering::Relaxed) + 1
    } else {
        DEBUG_WATCH_USER_HITS.fetch_add(1, Ordering::Relaxed) + 1
    };

    if hits <= 32 {
        if kernel {
            lib::compact_dbg_println!(
                "[WATCH-K] hit={} dr6={:08X} at {:04X}:{:08X} watch0={:08X}:{:04X} watch1={:08X}:{:04X} AX={:08X} BX={:08X} CX={:08X} DX={:08X} SI={:08X} DI={:08X}",
                hits,
                dr6,
                regs.code_seg(),
                regs.ip32(),
                addr0,
                value0,
                addr1,
                value1,
                regs.rax as u32,
                regs.rbx as u32,
                regs.rcx as u32,
                regs.rdx as u32,
                regs.rsi as u32,
                regs.rdi as u32,
            );
        } else {
            let cs_base = if regs.mode() == arch_abi::UserMode::VM86 {
                (regs.code_seg() as u32) << 4
            } else {
                crate::descriptors::seg_base(regs.code_seg())
            };
            let ip = regs.ip32();
            let lin = cs_base.wrapping_add(ip);
            let bytes = unsafe { core::slice::from_raw_parts(lin as *const u8, 8) };
            let ss_base = if regs.mode() == arch_abi::UserMode::VM86 {
                (regs.stack_seg() as u32) << 4
            } else {
                crate::descriptors::seg_base(regs.stack_seg())
            };
            let bp_addr = ss_base.wrapping_add(regs.rbp as u32);
            let st0 = unsafe { core::ptr::read_unaligned(bp_addr as *const u16) };
            let st1 = unsafe { core::ptr::read_unaligned(bp_addr.wrapping_add(2) as *const u16) };
            let st2 = unsafe { core::ptr::read_unaligned(bp_addr.wrapping_add(4) as *const u16) };
            let st3 = unsafe { core::ptr::read_unaligned(bp_addr.wrapping_add(6) as *const u16) };
            let st4 = unsafe { core::ptr::read_unaligned(bp_addr.wrapping_add(8) as *const u16) };
            let st5 = unsafe { core::ptr::read_unaligned(bp_addr.wrapping_add(10) as *const u16) };
            lib::compact_dbg_println!(
                "[WATCH] hit={} dr6={:08X} after {:04X}:{:08X} next={:02X?} watch0={:08X}:{:04X} watch1={:08X}:{:04X} AX={:08X} BX={:08X} CX={:08X} DX={:08X} SI={:08X} DI={:08X} BP={:08X} DS={:04X} ES={:04X} SS:SP={:04X}:{:08X} stack={:04X} {:04X} {:04X} {:04X} {:04X} {:04X}",
                hits, dr6, regs.code_seg(), ip, bytes, addr0, value0, addr1, value1,
                regs.rax as u32, regs.rbx as u32, regs.rcx as u32, regs.rdx as u32,
                regs.rsi as u32, regs.rdi as u32, regs.rbp as u32,
                regs.ds as u16, regs.es as u16, regs.stack_seg(), regs.sp32(),
                st0, st1, st2, st3, st4, st5,
            );
        }
    }

    unsafe { x86::write_dr6(0); }
    true
}

// Architecture calls include operations with page-sized scratch storage.
// They are a distinct phase of trap handling: do not let fat LTO reserve that
// scratch in the common ISR frame used by every hardware interrupt.
#[inline(never)]
pub(crate) fn arch_dispatch(regs: &mut KernelCall) -> CallOutcome {
    match regs.rax {
        arch_call::REARRANGE_MAPPINGS => crate::mapping::rearrange_mappings(unsafe { &mut *(regs.rdx as *mut crate::mapping::Rearrange) }),
        arch_call::READ_MAPPINGS => crate::mapping::read_mappings(unsafe { &mut *(regs.rdx as *mut crate::mapping::Read) }),
        arch_call::REPLACE_MAPPINGS => crate::mapping::replace_mappings(unsafe { &mut *(regs.rdx as *mut crate::mapping::Replace) }),
        arch_call::FILL_MAPPINGS => crate::mapping::fill_mappings(unsafe { &mut *(regs.rdx as *mut crate::mapping::Fill) }),
        arch_call::READ_MAPPING_RUN => crate::mapping::read_mapping_run(unsafe { &mut *(regs.rdx as *mut crate::mapping::ReadRun) }),
        arch_call::REFRESH_KERNEL => { paging2::refresh_kernel_mappings(); x86::flush_tlb(); }
        #[cfg(not(feature = "kvm"))]
        arch_call::INTERRUPT_PROCESSOR => { crate::irq::interrupt_processor(regs.rdx as u32); }
        arch_call::HIGH_MEMORY => {
            let request = unsafe { &mut *(regs.rdx as u32 as *mut crate::high_paging::Request) };
            request.result = crate::high_paging::request(request);
        }
        #[cfg(not(feature = "kvm"))]
        arch_call::EXECUTE => {
            let max_ns = (regs.rdx as u32 as u64) | ((regs.rcx as u32 as u64) << 32);
            if max_ns == 0 {
                let (event, extra) = arch_abi::KernelEvent::Irq.encode();
                regs.rax = event as u64;
                regs.rdx = extra as u32 as u64;
                regs.rcx = extra >> 32;
            } else {
                super::irq::arm_alarm(Some(super::irq::now(false).saturating_add(max_ns)));
                return CallOutcome::Execute;
            }
        },
        arch_call::ACTIVATE => unsafe {
            (&mut *(regs.rdx as *mut paging2::RootPageTable)).swap_and_activate();
        },
        arch_call::CHECK_ADDRESS_SPACE => {
            let hash = unsafe { &mut *(regs.rdx as *mut u64) };
            let actual = paging2::hash_and_record();
            if *hash != 0 && *hash != actual {
                lib::compact_println!("HASH MISMATCH expected {:#018x} got {:#018x}", *hash, actual);
                paging2::print_recorded_diff(*hash, actual);
            }
            *hash = actual;
        },
        arch_call::SWITCH_FX => {
            let fx = regs.rdx as u32 as *mut crate::x86::FxState;
            let mut tmp = crate::x86::FxState::zeroed();
            tmp.save();
            unsafe { (*fx).restore(); }
            unsafe { *fx = tmp; }
        }
        // FORK: EDX=child_root out. COW fork and fill the caller's root.
        arch_call::FORK => {
            let child_root = regs.rdx as usize as *mut paging2::RootPageTable;
            // Some callers provide uninitialized output storage.  fork_current
            // replaces entries (and releases any displaced mapping), so make
            // the output an empty root before exposing it as a reference.  Do
            // this in place: constructing a RootPageTable value here costs a
            // 3 KiB interrupt-stack temporary after fat LTO.
            unsafe {
                child_root.write_bytes(0, 1);
                paging2::fork_current(&mut *child_root);
            }
        }
        arch_call::CLEAN => paging2::free_user_pages(),
        arch_call::RELEASE_HEAP => paging2::release_heap_pages(regs.rdx as usize, regs.rcx as usize),
        arch_call::LOAD_LDT => {
            crate::descriptors::load_ldt(regs.rdx as u32, regs.rcx as u32);
        }
        arch_call::FRAME_OPERATION => {
            crate::frames::handle(unsafe { &mut *(regs.rdx as *mut crate::frames::Request) });
        }
        arch_call::MAP_KERNEL_PHYSICAL => {
            let vpage_start = regs.rdx as usize;
            let num_pages = regs.rcx as usize;
            // 64-bit physical page: low 32 in EBX, high 32 in ESI (firmware can
            // place an NVMe BAR above 4 GB on a wide-MAXPHYADDR CPU).
            let ppage_start = (regs.rbx as u32 as u64) | ((regs.rsi as u32 as u64) << 32);
            let flags = regs.rdi;
            paging2::map_kernel_physical(vpage_start, num_pages, ppage_start, flags);
        }
        arch_call::REMAP_PHYSICAL_APERTURE => {
            let physical_base = (regs.rdx as u32 as u64)
                | ((regs.rcx as u32 as u64) << 32);
            regs.rax = crate::aperture::remap(physical_base) as u64;
        }
        // HALT: the ring-1 kernel cannot `hlt` (CPL-0-only, #GPs); panic and
        // shutdown funnel here to die quietly at ring 0.
        #[cfg(not(feature = "kvm"))]
        arch_call::IDLE => {
            let max_ns = (regs.rdx as u32 as u64) | ((regs.rcx as u32 as u64) << 32);
            super::irq::idle(max_ns);
        }
        arch_call::HALT => {
            x86::cli();
            loop { x86::hlt(); }
        }
        #[cfg(not(feature = "kvm"))]
        arch_call::ISA_UNMASK_IRQ => {
            crate::irq::isa_unmask_irq(regs.rdx as u8);
        }
        arch_call::SET_TLS_ENTRY => {
            let index = regs.rdx as i32;
            let base = regs.rcx as u32;
            let limit = regs.rbx as u32;
            let limit_in_pages = regs.rdi != 0;
            regs.rax = crate::descriptors::set_tls_entry(index, base, limit, limit_in_pages) as u64;
            // Also write FS_BASE MSR so 32-bit compat mode picks up the
            // correct hidden base (the 32-bit iret path doesn't touch the MSR).
            // CPUs without long mode have no FS_BASE MSR; the GDT suffices.
            if paging2::cpu_supports_long_mode() {
                unsafe { crate::x86::wrmsr(0xC000_0100, base as u64); }
            }
        }
        arch_call::SET_DEBUG_WATCH => {
            unsafe {
                let count = (regs.rbx as u32).min(2);
                DEBUG_WATCH_COUNT.store(count, core::sync::atomic::Ordering::Relaxed);
                DEBUG_WATCH_ADDR0.store(regs.rdx as u32, core::sync::atomic::Ordering::Relaxed);
                DEBUG_WATCH_ADDR1.store(regs.rcx as u32, core::sync::atomic::Ordering::Relaxed);
                DEBUG_WATCH_USER_HITS.store(0, core::sync::atomic::Ordering::Relaxed);
                DEBUG_WATCH_KERNEL_HITS.store(0, core::sync::atomic::Ordering::Relaxed);
                if count != 0 {
                    x86::write_dr0(regs.rdx as u32);
                    if count > 1 {
                        x86::write_dr1(regs.rcx as u32);
                    }
                    x86::write_dr6(0);
                    x86::write_dr7(if count > 1 { 0x0055_0005 } else { 0x0005_0001 });
                } else {
                    x86::write_dr7(0);
                    x86::write_dr6(0);
                }
            }
        }
        arch_call::REPLACE_INTERRUPT_HANDLERS => unsafe {
            let handlers = regs.rdx as *mut arch_abi::InterruptHandlers;
            let previous = crate::descriptors::replace_interrupt_handlers(
                regs.rcx as u8, core::ptr::read(handlers));
            core::ptr::write(handlers, previous);
        },
        _ => lib::compact_panic!("Unknown arch call: {:#x}", regs.rax),
    }
    CallOutcome::Complete
}

#[cfg(not(feature = "kvm"))]
pub(crate) fn dispatch_parked_call() -> CallOutcome {
    let execute = unsafe { EXECUTE_REGS };
    let parked = if execute.is_null() { &raw mut REGS } else { execute };
    let mut call = KernelCall::from_regs(unsafe { &*parked });
    let outcome = arch_dispatch(&mut call);
    call.write_result(unsafe { &mut *parked });
    outcome
}

#[cfg(not(feature = "kvm"))]
pub(crate) fn swap_regs(regs: &mut Regs) {
    let execute = unsafe { EXECUTE_REGS };
    if execute.is_null() {
        let p = &raw mut REGS;
        unsafe { core::ptr::swap(regs, p); }
    } else {
        unsafe { core::ptr::swap(regs, execute); }
    }
}

// =============================================================================
// Interrupt dispatch
// =============================================================================

/// Native interrupt-controller and diagnostic adaptation. Guest dispatch
/// itself returns an outcome and cannot switch to the kernel.
pub(crate) fn guest_trap(regs: &mut Regs) -> arch_abi::trap::Outcome {
    use arch_abi::trap::Outcome;
    if regs.int_num == 1 && debug_watch_trap(regs, unsafe { x86::read_dr6() }, false) {
        return Outcome::Resume;
    }
    #[cfg(not(feature = "kvm"))]
    let interruption = matches!(regs.int_num, 32..=47 | 0xF8..=0xFE);
    #[cfg(feature = "kvm")]
    let interruption = regs.int_num == arch_abi::vm::INTERRUPT_VECTOR as u64;
    if interruption {
        #[cfg(not(feature = "kvm"))]
        handle_irq(regs);
        return Outcome::ReturnToKernel(arch_abi::KernelEvent::Irq);
    }
    if regs.int_num == 10 {
        let carrier_iret = regs.err_code == 0 && regs.flags32() & (1 << 14) != 0;
        if !carrier_iret {
            let cs_base = if regs.mode() == UserMode::VM86 {
                (regs.code_seg() as u32) << 4
            } else {
                crate::descriptors::seg_base(regs.code_seg())
            };
            let lin = cs_base.wrapping_add(regs.ip32());
            let bytes = unsafe { core::slice::from_raw_parts(lin as *const u8, 8) };
            let ss_base = if regs.mode() == UserMode::VM86 {
                (regs.stack_seg() as u32) << 4
            } else {
                crate::descriptors::seg_base(regs.stack_seg())
            };
            let sp = regs.sp32();
            let stack = unsafe { core::slice::from_raw_parts(ss_base.wrapping_add(sp) as *const u32, 6) };
            lib::compact_dbg_println!("#TS at {:04x}:{:#x} err={:#x} bytes={:02x?} SS:ESP={:04x}:{:#x} stack={:08x?}",
                regs.code_seg(), regs.ip32(), regs.err_code, bytes,
                regs.stack_seg(), sp, stack);
        }
    }
    let address = if regs.int_num == 14 { x86::read_cr2_full() } else { 0 };
    arch_abi::trap::handle(&mut crate::backend::Metal, regs, address)
}

impl arch_abi::trap::Machine for crate::backend::Metal {
    fn can_fault(&self) -> bool { crate::memory::can_fault() }
    fn resolve_page_fault(&mut self, regs: &Regs, _address: u64) -> bool {
        let legacy = is_vm86(regs) || regs.frame.cs & 4 != 0;
        try_handle_page_fault(regs.err_code, legacy).is_some()
    }
}

/// Ring-1 (kernel) trap dispatch: arch calls, page faults, IRQs. Anything
/// else from kernel context is a bug.
pub(crate) fn isr_handler_ring1(regs: &mut Regs) {
    match regs.int_num {
        1 => {
            let dr6 = unsafe { x86::read_dr6() };
            if debug_watch_trap(regs, dr6, true) {
                return;
            }
            panic_with_regs("Unexpected debug exception in kernel", regs);
        }
        14 => {
            if !crate::memory::can_fault() || try_handle_page_fault(regs.err_code, false).is_none() {
                panic_with_regs("Unhandled page fault in kernel", regs);
            }
        }
        #[cfg(not(feature = "kvm"))]
        32..=47 | 0xF8..=0xFE => handle_irq(regs),
        0x80 => unreachable!("kernel calls enter through entry::kernel_call"),
        _ => panic_with_regs("Unexpected interrupt in kernel", regs),
    }
}

// =============================================================================
// Page fault handler (arch-level: demand paging + COW)
// =============================================================================

/// Try to handle a page fault. Returns Some(()) if resolved, None if not.
fn try_handle_page_fault(error: u64, legacy_mode: bool) -> Option<()> {
    let _paging = paging2::PagingGuard::lock();
    // Other CPUs can grow the shared kernel heap while this CPU executes
    // userspace. Ownership metadata used below must see those mappings.
    crate::paging2::refresh_kernel_mappings();
    let _reserve = crate::memory::FaultGuard::enter();
    let _sample = crate::exec_profile::FaultSample::start(error & 4 != 0);
    use crate::paging2::{KERNEL_BASE, PAGE_TABLE_BASE, page_idx};

    let full_addr = x86::read_cr2_full();
    if full_addr >= crate::high_paging::START {
        return crate::high_paging::fault(full_addr, error).then_some(());
    }
    // Reject the inaccessible gap rather than truncating to a low address.
    if full_addr > u32::MAX as u64 { return None; }
    let fault_addr = full_addr as usize;
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

    // Kernel-stack-guard hit: the unmapped page directly below KERNEL_STACK.
    // Reaching it means ring-1 kernel stack overflow. (The arch-stack guard
    // is unmapped too but can't be reported here — its overflow #PFs on the
    // already-overflowed ARCH_STACK and triple-faults.)
    {
        let kguard = (&raw const crate::KERNEL_STACK_GUARD) as usize;
        if fault_addr >= kguard && fault_addr < kguard + 4096 {
            lib::compact_panic!("KERNEL STACK OVERFLOW at {:#x} (guard {:#x})", fault_addr, kguard);
        }
    }

    // Kernel memory is backed before use. A newly published shared root
    // may have been missing from this CPU; refresh above makes it visible.
    if !user && fault_addr >= KERNEL_BASE {
        return (!present && paging2::kernel_page_resident(fault_addr)).then_some(());
    }

    // Legacy mode (VM86/DPMI) shares code+data address space, so don't set NX
    let nx = paging2::nx_enabled() && !legacy_mode;
    use paging2::Entry as _;
    match paging2::entries() {
        paging2::Entries::E32(e) => {
            if present {
                handle_protection_fault(e, fault_addr, page_index, write, user, instruction_fetch)?;
            } else if e[page_index].raw() & (paging2::flags::CACHE_DISABLE | paging2::flags::SOFT_RO | paging2::flags::NO_ACCESS) != 0 {
                return None; // present=0 + PCD = emulated MMIO trap — kernel decodes
            } else {
                demand_page(e, page_index, false);
            }
        }
        paging2::Entries::E64(e) => {
            if present {
                handle_protection_fault(e, fault_addr, page_index, write, user, instruction_fetch)?;
            } else if e[page_index].raw() & (paging2::flags::CACHE_DISABLE | paging2::flags::SOFT_RO | paging2::flags::NO_ACCESS) != 0 {
                return None;
            } else {
                demand_page(e, page_index, nx);
            }
        }
    }
    // A first user write used to install a read-only zero page, return to the
    // same instruction, then fault a second time just to make its private copy.
    // Complete that ordinary write fault before returning to user mode.
    if !present && write && user && !legacy_mode {
        match paging2::entries() {
            paging2::Entries::E32(e) => handle_protection_fault(e, fault_addr, page_index, true, true, false)?,
            paging2::Entries::E64(e) => handle_protection_fault(e, fault_addr, page_index, true, true, false)?,
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
        if idx < paging2::PAGE_TABLE_BASE_IDX { x86::invlpg(page_index * paging2::PAGE_SIZE); }
        else { paging2::flush_tlb(); }
        return Some(());
    }

    None // Unexpected, let kernel handle
}


/// Demand page allocation for not-present pages
fn demand_page<E: paging2::Entry>(
    entries: &mut [E],
    page_index: usize,
    use_nx: bool,
) {
    use crate::paging2::PAGE_TABLE_BASE_IDX;

    let zero_page = paging2::physical_page(&crate::ZERO_PAGE as *const _ as usize);
    let is_user = page_index < paging2::recursive_idx();
    let mut e = E::new(zero_page, false, is_user);
    if use_nx && page_index < PAGE_TABLE_BASE_IDX {
        e.set_no_execute(true);
    }
    paging2::replace_mapping(&mut entries[page_index], e);
    if page_index < PAGE_TABLE_BASE_IDX { x86::invlpg(page_index * paging2::PAGE_SIZE); }
    else { paging2::flush_tlb(); }
}

// =============================================================================
// VM86 segment helpers
// =============================================================================

/// Ring-0 interrupt handler. No frame conversion, no canonicalization.
/// Called before from_32/to_32 since 32-bit same-privilege interrupts
/// don't push ESP/SS.
pub(crate) fn handle_ring0(int_num: u64, error: u64, cs: u64, eip: u64) {
    match int_num {
        14 => {
            if !crate::memory::can_fault() || try_handle_page_fault(error, false).is_none() {
                lib::compact_panic!("Unhandled page fault in arch: addr={:#x} err={:#x}", x86::read_cr2(), error);
            }
        }
        #[cfg(not(feature = "kvm"))]
        32..=47 | 0xF8..=0xFE => {
            let mut regs = Regs::empty();
            regs.int_num = int_num;
            handle_irq(&mut regs);
        }
        _ => lib::compact_panic!("Unhandled exception in arch: int={:#x} err={:#x} at {:#06x}:{:#010x}", int_num, error, cs, eip),
    }
}

fn is_vm86(regs: &Regs) -> bool {
    regs.mode() == arch_abi::UserMode::VM86
}

// =============================================================================
// Panic helper (no kernel dependencies)
// =============================================================================

#[track_caller]
fn panic_with_regs(msg: &str, regs: &Regs) -> ! {
    x86::cli();
    lib::compact_println!("{:?}", regs);
    lib::compact_panic!("{}", msg);
}
