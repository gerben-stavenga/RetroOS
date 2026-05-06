//! Arch interrupt dispatch
//!
//! Ring-0 interrupt handler. Zero imports from kernel/ — all policy decisions
//! are returned to the ring-1 kernel as events via the execute() interface.

#![allow(static_mut_refs)]

use crate::arch::irq::handle_irq;
use crate::arch::paging2::{self, Entry};
use crate::println;
use crate::arch::x86;
use crate::{Frame64, Regs};

// =============================================================================
// Arch call interface (ring-1 kernel → ring-0 arch via INT 0x80)
// =============================================================================

// =============================================================================
// Arch state (Ring 0 maintains state for Ring 1 and Ring 3)
// =============================================================================


/// Raw 32-bit register save layout, what `entry_wrapper_32` pushes natively.
/// Total size matches `Regs` (216 bytes) so the two share a common stack slot
/// via `StackFrame`. Layout from low to high address (matches push order):
///   - 4 segment selectors (low offset; pushed last by asm)
///   - 8 GP regs in `pushad` order: edi, esi, ebp, esp_dummy, ebx, edx, ecx, eax
///   - 140 bytes of internal padding (covers the slots `Regs` uses for r8..r15
///     and the high halves of segs/GP)
///   - int_num, err_code (sw-pushed by `int_vector` / `common_dispatch`)
///   - Frame32 IRET payload (eip, cs, eflags [, esp, ss for cross-priv])
///
/// VM86 segs (es, ds, fs, gs) the CPU pushes above the IRET frame for VM86
/// entries are *not* part of `Raw32` — they form the second component of the
/// 32-bit `StackFrame` arm `(Raw32, Vm86Segs)`, valid only when EFLAGS.VM is
/// set on entry/exit.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Raw32 {
    pub gs: u32, pub fs: u32, pub es: u32, pub ds: u32,
    pub edi: u32, pub esi: u32, pub ebp: u32, pub esp_dummy: u32,
    pub ebx: u32, pub edx: u32, pub ecx: u32, pub eax: u32,
    pub _pad: [u8; 140],
    pub int_num: u32, pub err_code: u32,
    pub eip: u32, pub cs: u32, pub eflags: u32, pub esp: u32, pub ss: u32,
}

/// 4 VM86 segment selectors the CPU pushes above the IRET frame on a VM86
/// trap. Bytes are valid only when EFLAGS.VM is set on entry/exit; otherwise
/// kernel-stack residue.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Vm86Segs {
    pub es: u32, pub ds: u32, pub fs: u32, pub gs: u32,
}

/// Stack-side view of a saved interrupt frame. Two arms: `regs` is the
/// canonical 64-bit form (216B); the 32-bit arm is `(Raw32, Vm86Segs)` — the
/// native push slot plus the optional VM86 seg tail. `isr_handler` picks the
/// live arm via `from_64`.
///
/// The 16-byte `Vm86Segs` tail is always safe to read/write: TSS.sp0 is
/// pinned 16 bytes below the kernel stack top (see `arch/boot.rs`), and ring
/// transitions are the only path that lands here, so the spare 16 bytes
/// above the IRET frame always exist. For VM86 entries the CPU pushed real
/// vm86 segs there; for non-VM86 it's spare bytes we can scribble on.
#[repr(C)]
pub union StackFrame {
    pub regs: Regs,
    pub raw32: (Raw32, Vm86Segs),
}

const _: () = assert!(core::mem::size_of::<Regs>() == core::mem::size_of::<Raw32>());

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
    pub const COPY_PAGE_ENTRIES: u64 = 0x10C; // EDX=src_vpage, ECX=dst_vpage, EBX=count — copy entries src→dst
    pub const SWAP_PAGE_ENTRIES: u64 = 0x10E; // EDX=a_vpage, ECX=b_vpage, EBX=count — swap entries a↔b
    pub const UNMAP_RANGE: u64 = 0x10F;  // EDX=vpage_start, ECX=count — clear entries to absent
    pub const FREE_RANGE: u64 = 0x110;   // EDX=vpage_start, ECX=count — free phys + identity-map RO
    pub const LOAD_LDT: u64 = 0x115;    // EDX=base, ECX=limit → load LDT
    pub const MAP_PHYS_RANGE: u64 = 0x116; // EDX=vpage_start, ECX=num_pages, EBX=ppage_start
    pub const SET_TLS_ENTRY: u64 = 0x117; // EDX=index(-1=auto), ECX=base, EBX=limit, ESI=flags. Returns index in EAX.
    pub const HASH_PHYS_PAGE: u64 = 0x118; // EDX=phys_page_num. Returns FNV-1a u64 hash of that physical page in EAX.
}

fn arch_dispatch(regs: &mut Regs) {
    match regs.rax {
        arch_call::EXECUTE => {
            swap_regs(regs);
            regs.frame.rflags &= !(1 << 14); // HACK: strip NT
        }
        arch_call::SWITCH_TO => arch_switch_to(regs),
        // FORK: EDX=child_root out. COW fork, fill child, free temp page.
        arch_call::FORK => {
            let child_root = regs.rdx as usize as *mut paging2::RootPageTable;
            let mut cr = paging2::RootPageTable::empty();
            paging2::fork_current(&mut cr);
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
        arch_call::COPY_PAGE_ENTRIES => {
            paging2::copy_page_entries(regs.rdx as usize, regs.rcx as usize, regs.rbx as usize);
        }
        arch_call::SWAP_PAGE_ENTRIES => {
            paging2::swap_page_entries(regs.rdx as usize, regs.rcx as usize, regs.rbx as usize);
        }
        arch_call::UNMAP_RANGE => paging2::unmap_range(regs.rdx as usize, regs.rcx as usize),
        arch_call::FREE_RANGE => paging2::free_range(regs.rdx as usize, regs.rcx as usize),
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
            // Also write FS_BASE MSR so 32-bit compat mode picks up the
            // correct hidden base (the 32-bit iret path doesn't touch the MSR).
            unsafe { crate::arch::x86::wrmsr(0xC000_0100, base as u64); }
        }
        _ => panic!("Unknown arch call: {:#x}", regs.rax),
    }
}

fn toggle_mode_if_needed(regs: &Regs, is_long: bool) -> bool {
    use crate::UserMode;
    let want_64 = regs.mode() == UserMode::Mode64;
    let is_vm86 = regs.mode() == UserMode::VM86;
    let need_toggle = (!is_long && want_64) || (is_long && is_vm86);
    if !need_toggle {
        return is_long;
    }
    paging2::sync_hw_pdpt();
    x86::flush_tlb();
    let saved = paging2::ensure_trampoline_mapped();
    crate::arch::descriptors::toggle_mode(paging2::toggle_cr3(want_64));
    paging2::clear_trampoline(saved);
    !is_long
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
    let fx_ptr   = regs.rsi as u32 as *mut crate::arch::x86::FxState;

    let expected = if !hash_ptr.is_null() {
        unsafe {
            let exp = *hash_ptr;
            *hash_ptr = paging2::hash_and_record();
            exp
        }
    } else { 0 };

    // Swap x87/SSE state eagerly: save outgoing into a temp, load incoming
    // from the thread's area, then move temp into the thread's area so it
    // holds the outgoing state on return (mirrors the regs swap semantics).
    // Null fx_ptr = skip (used by kernel-only transient swaps that never
    // touch the FPU between entry and exit).
    if !fx_ptr.is_null() {
        let mut tmp = crate::arch::x86::FxState::zeroed();
        tmp.save();
        unsafe { (*fx_ptr).restore(); }
        unsafe { *fx_ptr = tmp; }
    }

    // Swap regs
    unsafe { core::mem::swap(&mut *regs_ptr, &mut REGS); }

    // Log incoming struct PDE[0] before swap
    let _pre_pde0 = unsafe { (*root_ptr).e32[0].0 };

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
///
/// `stack` is the raw saved state on the kernel stack — a `StackFrame` union
/// over the same 216-byte slot. `from_64` tells us which arm holds live data:
/// the 64-bit form pushed by `entry_wrapper_64`, or the 32-bit form pushed by
/// `entry_wrapper_32`. We canonicalize to `Regs` (always the 64-bit form), let
/// the kernel run on it, then denormalize back if exiting to 32-bit user.
///
/// Returns true if the kernel wants to iret to long mode (the 64-bit exit path).
#[unsafe(no_mangle)]
#[allow(private_interfaces)]
pub extern "C" fn isr_handler(stack: *mut StackFrame, from_64: bool) -> bool {
    static mut VIF: bool = false;
    static mut VIP: bool = false;
    // Read just enough raw fields to classify the trap before canonicalizing.
    // Same-priv (ring 0 → ring 0) traps don't push SS/ESP and never reach VM86
    // segs, so canonicalizing would read residue. Cross-priv traps (ring 1
    // kernel or ring 3 user → arch ring 0) get full canonicalization.
    let (vm86, raw_cs, raw_int_num, raw_err_code) = if from_64 {
        // EFLAGS.VM is reserved in long mode -- 64-bit entry is never VM86.
        let r = unsafe { &(*stack).regs };
        (false, r.frame.cs, r.int_num, r.err_code)
    } else {
        let r = unsafe { &(*stack).raw32.0 };
        (r.eflags as u64 & VM_FLAG != 0, r.cs as u64, r.int_num as u64, r.err_code as u64)
    };
    // Mask int_num to 8 bits to undo sign-extension from `push imm8` for
    // vectors >= 0x80. `syscall_entry_64` pushes 256 (out of IDT range) as a
    // sentinel — preserve it so ring3 can route it to `KE::Syscall`.
    let raw_int_num = if raw_int_num == 256 { 256 } else { raw_int_num & 0xFF };

    if !vm86 && (raw_cs & 3) == 0 {  // from ring 0?
        handle_ring0(raw_int_num, raw_err_code);  // No canonicalization because in 32-bit mode doesn't match Regs layout due to missing esp:ss
        return from_64;
    }

    // Canonicalize: write a `Regs` into the stack slot via the union, picking
    // fields conditionally so we never read residue (SS/ESP only valid on
    // ring transition; VM86 segs only valid in VM86).
    let regs = unsafe { &mut (*stack).regs };
    if from_64 {
        // 64-bit user: asm-64 saved FS/GS as selectors only; substitute the
        // FS_BASE / GS_BASE MSRs (what 64-bit code actually uses).
        if regs.frame.cs == 0x33 {
            regs.fs = x86::rdmsr(0xC000_0100);
            regs.gs = x86::rdmsr(0xC000_0101);
        }
        regs.int_num = raw_int_num;
    } else {
        let (r, v) = unsafe { &(*stack).raw32 };
        // VM86 supplies segs in the CPU-pushed `Vm86Segs` tail; non-VM86
        // ring-3 already has the user selectors in `Raw32`'s seg slots.
        let canonical = Regs {
            gs: if vm86 { v.gs as u64 } else { r.gs as u64 },
            fs: if vm86 { v.fs as u64 } else { r.fs as u64 },
            es: if vm86 { v.es as u64 } else { r.es as u64 },
            ds: if vm86 { v.ds as u64 } else { r.ds as u64 },
            r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
            rdi: r.edi as u64,
            rsi: r.esi as u64,
            rbp: r.ebp as u64,
            rsp_dummy: r.esp_dummy as u64,
            rbx: r.ebx as u64,
            rdx: r.edx as u64,
            rcx: r.ecx as u64,
            rax: r.eax as u64,
            int_num: raw_int_num,
            err_code: raw_err_code,
            frame: Frame64 {
                rip: r.eip as u64,
                cs: raw_cs,
                rflags: r.eflags as u64,
                rsp: r.esp as u64,
                ss: r.ss as u64,
            },
        };
        *regs = canonical;
    }

    // 16-bit SS sanity-fix: CPU only loads low 16 bits of SP for B=0 stacks;
    // upper bits are kernel residue.
    if !vm86 && regs.frame.ss & 4 != 0 {
        let ss = regs.frame.ss as u16;
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
        if ok != 0 && ar & (1 << 22) == 0 {
            regs.frame.rsp &= 0xFFFF;
        }
    }

    // Only ring 3 / VM86 needs the full user-emulation cleanup (VIF/VIP swap,
    // VM86 seg promotion). Ring 1 kernel just needs the layout normalized.

    // VIF↔IF entry swap (ring 3 / VM86 only). With VME the hardware maintains
    // VIF/VIP in EFLAGS bits 19/20; otherwise we keep them in statics across
    // the kernel run.
    let from_ring3 = vm86 || (raw_cs & 3) == 3;
    if from_ring3 {
        if vm86 && x86::read_cr4() & x86::cr4::VME != 0 {
            unsafe {
                VIF = regs.frame.rflags & (1 << 19) != 0;
                VIP = regs.frame.rflags & (1 << 20) != 0;
            }
        }
        unsafe {
            if VIF { regs.frame.rflags |= 1 << 9; }
            else   { regs.frame.rflags &= !(1 << 9); }
            if VIP { regs.frame.rflags |= 1 << 20; }
            else   { regs.frame.rflags &= !(1 << 20); }
        }
        isr_handler_ring3(regs);
    } else {
        isr_handler_ring1(regs);
    }

    // Mode-toggle the CPU if the kernel's output mode differs from entry.
    let to_64 = toggle_mode_if_needed(regs, from_64);

    // VIF↔IF exit swap (ring 3 / VM86 only); force real IF=1 so HW IRQs can be
    // delivered to user.
    let to_vm86 = is_vm86(regs);
    let to_ring3 = to_vm86 || (regs.frame.cs & 3) == 3;
    if to_ring3 {
        unsafe {
            VIF = regs.frame.rflags & (1 << 9) != 0;
            VIP = regs.frame.rflags & (1 << 20) != 0;
        }
        if to_vm86 && x86::read_cr4() & x86::cr4::VME != 0 {
            if unsafe { VIF } { regs.frame.rflags |= 1 << 19; }
            else              { regs.frame.rflags &= !(1 << 19); }
        }
        regs.frame.rflags |= 0x200;
    }

    // Denormalize back to the 32-bit push form if exiting to 32-bit/VM86.
    if to_64 {
        // 64-bit user exit: write FS_BASE/GS_BASE MSRs (what asm pops as selectors
        // is meaningless for 64-bit code — null those slots so the asm `mov fs/gs,
        // ax` loads a null selector, harmless in 64-bit mode).
        if regs.frame.cs == 0x33 {
            unsafe {
                x86::wrmsr(0xC000_0100, regs.fs);
                x86::wrmsr(0xC000_0101, regs.gs);
            }
            regs.fs = 0;
            regs.gs = 0;
        }
    } else {
        // Decouple from `regs` before we overwrite the same memory via the
        // union's other arm: shadow it with a value-copy (Regs is Copy).
        let r = *regs;
        // For VM86 exit, the user's segs go into the `Vm86Segs` tail (popped
        // by iret); the kernel-side seg slots in `Raw32` must be NULL because
        // asm's `pop gs/fs/es/ds` in PM ring 0 validates them as descriptors
        // before iret takes over.
        let (gs, fs, es, ds) = if to_vm86 {
            (0, 0, 0, 0)
        } else {
            (r.gs as u32, r.fs as u32, r.es as u32, r.ds as u32)
        };
        let raw32 = Raw32 {
            gs, fs, es, ds,
            edi: r.rdi as u32,
            esi: r.rsi as u32,
            ebp: r.rbp as u32,
            esp_dummy: r.rsp_dummy as u32,
            ebx: r.rbx as u32,
            edx: r.rdx as u32,
            ecx: r.rcx as u32,
            eax: r.rax as u32,
            _pad: [0; 140],
            int_num: r.int_num as u32,
            err_code: r.err_code as u32,
            eip: r.frame.rip as u32,
            cs: r.frame.cs as u32,
            eflags: r.frame.rflags as u32,
            esp: r.frame.rsp as u32,
            ss: r.frame.ss as u32,
        };
        // Unconditionally copy user segs into the Vm86Segs tail: iret only
        // pops it on VM86 exit, and the 16 bytes are the TSS.sp0 reserve
        // (see StackFrame doc) so a stray write is harmless either way.
        let v = Vm86Segs {
            es: r.es as u32, ds: r.ds as u32,
            fs: r.fs as u32, gs: r.gs as u32,
        };
        unsafe { (*stack).raw32 = (raw32, v); }
    }
    to_64
}

/// Ring-3 / VM86 trap dispatch. Classifies the x86 vector into a
/// `KernelEvent` and bubbles it up to the ring-1 kernel via swap_regs;
/// `#GP` runs the sensitive-instruction monitor first, `#PF` and IRQs
/// are handled inline by arch before bubbling.
fn isr_handler_ring3(regs: &mut Regs) {
    use crate::arch::monitor::{monitor, step_virtual_if, KernelEvent as KE, MonitorResult, TF_VIRTUAL_IF_STEPPING};
    use crate::UserMode;
    let int_num = regs.int_num;
    let legacy_mode = is_vm86(regs) || (regs.frame.cs & 4) != 0;
    let kevent: KE = match int_num {
        // #DB: only armed by `step_virtual_if` to single-step PM regions
        // where virtual IF is 0. The hardware just executed one insn under
        // TF; decide what to do about the NEXT one. When TF stepping is
        // disabled, defensively clear TF and resume — nothing in the
        // kernel arms it, but a stale bit in client flags would loop.
        1 => {
            use core::sync::atomic::Ordering;
            let budget = crate::kernel::dos::PM_STEP_BUDGET.load(Ordering::Relaxed);
            if budget > 0 {
                // Log step in PM and VM86 — VM86 logging needed to trace
                // RM execution after a raw PM->RM switch.
                crate::kernel::dos::pm_step_log(regs);
                crate::kernel::dos::PM_STEP_BUDGET.store(budget - 1, Ordering::Relaxed);
                regs.set_flag32(1 << 8); // keep TF on
                return;
            }
            if TF_VIRTUAL_IF_STEPPING {
                let _ = step_virtual_if(regs);
            } else {
                regs.clear_flag32(1 << 8);
            }
            return;
        }
        13 => match monitor(regs) {
            MonitorResult::Resume => {
                // If the monitor just cleared virtual IF in PM (e.g. a CLI),
                // kick off the single-step interpreter so POPF/IRET get
                // intercepted before hardware runs them. Skipped when TF
                // stepping is disabled — DPMI 0.9 §2.13 says POPF/IRET
                // aren't required to affect virtual IF, so spec-conforming
                // clients use CLI/STI/AX=0900-0902 only.
                if TF_VIRTUAL_IF_STEPPING
                    && regs.mode() != UserMode::VM86
                    && regs.flags32() & (1 << 9) == 0
                {
                    let _ = step_virtual_if(regs);
                }
                if regs.flags32() & ((1 << 9) | (1 << 20)) != (1 << 9) | (1 << 20) {
                    return;
                }
                KE::Irq
            }
            MonitorResult::Event(e) => e,
        },
        14 => {
            if try_handle_page_fault(regs.err_code, legacy_mode).is_some() { return; }
            KE::PageFault { addr: x86::read_cr2() as u32 }
        }
        32..=47 => { handle_irq(regs); KE::Irq }
        // Vectors 3/4 (#BP/#OF) are only reachable from user INT3/INTO, so
        // they're soft ints. Other n<32 are genuine CPU exceptions.
        3 | 4 => KE::SoftInt(int_num as u8),
        10 => {
            let cs_base = if regs.mode() == UserMode::VM86 {
                (regs.code_seg() as u32) << 4
            } else {
                crate::arch::monitor::seg_base(regs.code_seg())
            };
            let lin = cs_base.wrapping_add(regs.ip32());
            let bytes = unsafe { core::slice::from_raw_parts(lin as *const u8, 8) };
            let ss_base = if regs.mode() == UserMode::VM86 {
                (regs.stack_seg() as u32) << 4
            } else {
                crate::arch::monitor::seg_base(regs.stack_seg())
            };
            let sp = regs.sp32();
            let stack = unsafe { core::slice::from_raw_parts(ss_base.wrapping_add(sp) as *const u32, 6) };
            crate::dbg_println!("#TS at {:04x}:{:#x} err={:#x} bytes={:02x?} SS:ESP={:04x}:{:#x} stack={:08x?}",
                regs.code_seg(), regs.ip32(), regs.err_code, bytes,
                regs.stack_seg(), sp, stack);
            KE::Exception(int_num as u8)
        }
        0..=31 => KE::Exception(int_num as u8),
        // SYSCALL instruction: `syscall_entry_64` tags it with the synthetic
        // 256, distinct from any IDT vector — keep it before the catch-all so
        // `INT 0x80` (which lands as SoftInt(0x80)) stays a different event.
        256 => KE::Syscall,
        // Direct-IDT soft interrupts: 0x30..=0xFF (plus VM86 INT3/0xCC bypass
        // of VME landing here too).
        _ => KE::SoftInt(int_num as u8),
    };
    swap_regs(regs);
    let (event, extra) = kevent.encode();
    regs.rax = event as u64;
    regs.rdx = extra as u64;
}

/// Ring-1 (kernel) trap dispatch: arch calls, page faults, IRQs. Anything
/// else from kernel context is a bug.
fn isr_handler_ring1(regs: &mut Regs) {
    match regs.int_num {
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

    // Kernel-stack-guard hit: the unmapped page directly below KERNEL_STACK.
    // Reaching it means ring-1 kernel stack overflow. (The arch-stack guard
    // is unmapped too but can't be reported here — its overflow #PFs on the
    // already-overflowed ARCH_STACK and triple-faults.)
    {
        let kguard = (&raw const crate::KERNEL_STACK_GUARD) as usize;
        if fault_addr >= kguard && fault_addr < kguard + 4096 {
            panic!("KERNEL STACK OVERFLOW at {:#x} (guard {:#x})", fault_addr, kguard);
        }
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
