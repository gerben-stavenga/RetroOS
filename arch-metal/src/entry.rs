//! Native entry/return adaptation around canonical trap dispatch.
//! Raw stack conversion is shared with KVM in arch_abi::entry.
#![allow(static_mut_refs)]
use arch_abi::{Regs, entry::StackFrame};
use crate::{paging2, x86};
use crate::traps::{arch_call, handle_ring0, isr_handler_ring1, guest_trap};
const VM_FLAG: u64 = 1 << 17;
fn is_vm86(regs: &Regs) -> bool { regs.mode() == arch_abi::UserMode::VM86 }

fn toggle_mode_if_needed(regs: &Regs, is_long: bool) -> bool {
    use arch_abi::UserMode;
    let want_64 = regs.mode() == UserMode::Mode64;
    let is_vm86 = regs.mode() == UserMode::VM86;
    let need_toggle = (!is_long && want_64) || (is_long && is_vm86);
    if !need_toggle {
        return is_long;
    }
    paging2::sync_hw_pdpt();
    x86::flush_tlb();
    let saved = paging2::ensure_trampoline_mapped();
    crate::descriptors::toggle_mode(paging2::toggle_cr3(want_64));
    paging2::clear_trampoline(saved);
    !is_long
}

/// Main interrupt service routine.
///
/// Ring 1 (kernel): IRQ → ACK+queue+return. INT 0x80 → arch call. Trap → panic.
/// Ring 3 (user): save state, return event to ring-1 kernel.
/// Ring 0 (boot): page fault → demand paging. IRQ → ACK+queue. Rest → panic.
///
/// `stack` is the raw saved state on the kernel stack. `from_64` tells us which
/// union arm holds live data:
/// the 64-bit form pushed by `entry_wrapper_64`, or the 32-bit form pushed by
/// `entry_wrapper_32`. We canonicalize to `Regs` (always the 64-bit form), let
/// the kernel run on it, then denormalize back if exiting to 32-bit user.
///
/// Returns true if the kernel wants to iret to long mode (the 64-bit exit path).
#[unsafe(no_mangle)]
#[allow(private_interfaces)]
pub extern "C" fn isr_handler(stack: *mut StackFrame, from_64: bool) -> bool {
    paging2::refresh_kernel_mappings();
    #[thread_local]
    static mut VIF: bool = false;
    #[thread_local]
    static mut VIP: bool = false;
    #[thread_local]
    static mut USER_TF: bool = false;
    #[thread_local]
    static mut FORCED_TF: bool = false;
    #[thread_local]
    static mut PVI_POLICY: bool = false;
    // This handler is the sole owner of CR4.PVI. Keep its state here so the
    // overwhelmingly common trap path does not execute serializing CR4 reads.
    #[thread_local]
    static mut PVI_ACTIVE: bool = false;
    // Per-thread virtual IOPL (EFLAGS bits 12-13), carried across the iret like
    // VIF/VIP. The run pins the *real* IOPL=1 (so CLI/STI/IN/OUT trap); this
    // stash holds the level the client is *treated* as having, so the dispatch
    // can read the launch policy back. 1 = spec-strict, 2 = learn/tag repair,
    // and 3 = always-step reference mode. The kernel is its single writer.
    #[thread_local]
    static mut VIOPL: u8 = 1;
    // Read just enough raw fields to classify the trap before canonicalizing.
    // Same-priv (ring 0 → ring 0) traps don't push SS/ESP and never reach VM86
    // segs, so canonicalizing would read residue. Cross-priv traps (ring 1
    // kernel or ring 3 user → arch ring 0) get full canonicalization.
    let (vm86, raw_cs, raw_int_num, raw_err_code, raw_eip) = if from_64 {
        // EFLAGS.VM is reserved in long mode -- 64-bit entry is never VM86.
        let r = unsafe { &(*stack).regs };
        (false, r.frame.cs, r.int_num, r.err_code, r.frame.rip)
    } else {
        let r = unsafe { &(*stack).raw32.raw };
        (r.eflags as u64 & VM_FLAG != 0, r.cs as u64, r.int_num as u64, r.err_code as u64, r.eip as u64)
    };
    // Mask int_num to 8 bits to undo sign-extension from `push imm8` for
    // vectors >= 0x80. `syscall_entry_64` pushes 256 (out of IDT range) as a
    // sentinel — preserve it so ring3 can route it to `KE::Syscall`.
    let raw_int_num = if raw_int_num == 256 { 256 } else { raw_int_num & 0xFF };
    // A LAPIC spurious delivery has no in-service interrupt to acknowledge.
    // Resume the untouched frame at any privilege level: no EOI, line mask,
    // device event, or return from execute is needed.
    #[cfg(not(feature = "kvm"))]
    if raw_int_num == u64::from(crate::irq::LAPIC_SPURIOUS_VECTOR) {
        return from_64;
    }
    let from_ring3 = vm86 || (raw_cs & 3) == 3;
    if from_ring3 {
        crate::exec_profile::time(arch_abi::ExecutionProfileStage::Guest);
    }

    if !vm86 && (raw_cs & 3) == 0 {  // from ring 0?
        // An unhandled ring-0 exception is headed for the panic in
        // handle_ring0. The most common cause is the exit path's `iret` /
        // segment pops rejecting a garbage guest frame (#GP at
        // exit_interrupt_32), and that doomed frame still sits just above
        // this trap's CPU-pushed portion — a same-ring trap pushes no
        // SS/ESP, so Raw32's esp/ss slots and the bytes beyond line up
        // with it. Dump the words so the panic names the bad frame.
        if !from_64 && !(raw_int_num == 14 || (32..=47).contains(&raw_int_num)) {
            let p = unsafe { core::ptr::addr_of!((*stack).raw32.raw.esp) };
            lib::compact_println!("ring0 fault: words above the trap frame (iret-target frame):");
            for i in 0..10 {
                lib::compact_println!("  [esp+{:2}] = {:#010x}", i * 4, unsafe { p.add(i).read_volatile() });
            }
        }
        handle_ring0(raw_int_num, raw_err_code, raw_cs, raw_eip);  // No canonicalization because in 32-bit mode doesn't match Regs layout due to missing esp:ss
        return from_64;
    }

    let regs = unsafe { (*stack).canonicalize(from_64) };
    let execute_entry = !from_ring3
        && raw_int_num == 0x80
        && regs.rax == arch_call::EXECUTE;

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

    // The guest's virtual-IF lives in EFLAGS bit 19 (VIF) of the saved frame —
    // the kernel's single virtual-IF home. Bit 9 (IF) is the *real* interrupt
    // flag only, never guest state. VME+VM86 and PVI+PM keep VIF/VIP in the
    // hardware frame. Other guests use the software stash below.
    if from_ring3 {
        let hardware_vif = (vm86 && x86::read_cr4() & x86::cr4::VME != 0)
            || (!vm86 && unsafe { PVI_ACTIVE });
        if !hardware_vif {
            unsafe {
                if VIF { regs.frame.rflags |= 1 << 19; } else { regs.frame.rflags &= !(1 << 19); }
                if VIP { regs.frame.rflags |= 1 << 20; } else { regs.frame.rflags &= !(1 << 20); }
            }
        }
        // Restore the per-thread virtual IOPL: the run pinned real IOPL=1 on
        // exit, so the just-pushed frame reads 1; put the virtual level back in
        // bits 12-13 before the dispatch so `virtual_if_stepping` sees it.
        unsafe { regs.frame.rflags = (regs.frame.rflags & !(3 << 12)) | ((VIOPL as u64) << 12); }
        unsafe {
            regs.set_user_tf(USER_TF);
            regs.set_forced_tf(FORCED_TF);
            regs.set_pvi_policy(PVI_POLICY);
        }
        crate::exec_profile::time(arch_abi::ExecutionProfileStage::Ring0ExitFrameIn);
        if let arch_abi::trap::Outcome::ReturnToKernel(event) = guest_trap(regs) {
            return_to_kernel(regs, event);
        }
        crate::exec_profile::time(arch_abi::ExecutionProfileStage::Ring0ExitDispatch);
    } else {
        if execute_entry {
            crate::exec_profile::time(arch_abi::ExecutionProfileStage::Ring0EnterFrameIn);
        }
        if raw_int_num == 0x80 {
            kernel_call(regs);
        } else {
            isr_handler_ring1(regs);
        }
        if execute_entry {
            crate::exec_profile::time(arch_abi::ExecutionProfileStage::Ring0EnterDispatch);
        }
    }

    // Mode-toggle the CPU if the kernel's output mode differs from entry.
    let to_64 = toggle_mode_if_needed(regs, from_64);

    // Exit to a ring-3/VM86 guest: force real IF=1 (bit 9) so HW IRQs always
    // preempt. VIF/VIP stay in bits 19/20 (the kernel's virtual-IF home).
    let to_vm86 = is_vm86(regs);
    let to_ring3 = to_vm86 || (regs.frame.cs & 3) == 3;
    if to_ring3 {
        // Application policy, not the live vIOPL, owns PVI. A PM IRQ handler
        // temporarily runs with vIOPL=1 and must not toggle PVI inside a repair
        // client. PVI is harmless in VM86 and can remain set across RM calls.
        let pvi_enabled = unsafe { PVI_ACTIVE };
        // VME and PVI arrived together. Probe CR4 only when first enabling
        // PVI; after that PVI_ACTIVE is authoritative because this is the
        // sole code which changes CR4.PVI.
        let use_pvi = regs.pvi_policy()
            && (pvi_enabled || x86::read_cr4() & x86::cr4::VME != 0);
        if use_pvi != pvi_enabled {
            let mut cr4 = x86::read_cr4();
            if use_pvi { cr4 |= x86::cr4::PVI; } else { cr4 &= !x86::cr4::PVI; }
            unsafe { x86::write_cr4(cr4); }
            unsafe { PVI_ACTIVE = use_pvi; }
        }
        let hardware_vif = (to_vm86 && x86::read_cr4() & x86::cr4::VME != 0)
            || (!to_vm86 && use_pvi);
        if !hardware_vif {
            // no-VME / PM: the hardware can't carry VIF/VIP across the iret —
            // bits 19/20 must be 0 or the CPU applies VME virtual-interrupt
            // semantics to the client (the Bochs Doom/Jazz/Duke3D timer-ISR
            // wedge: a stale VIF flips on CLI/STI, the dispatcher's EOI never
            // lands, IRQ0 wedges in-service). So stash them in the statics and
            // clear the bits; the next entry restores them into the frame.
            // VME+VM86 leaves bits 19/20 in the frame for the hardware.
            unsafe {
                VIF = regs.frame.rflags & (1 << 19) != 0;
                VIP = regs.frame.rflags & (1 << 20) != 0;
            }
            regs.frame.rflags &= !((1 << 19) | (1 << 20));
        }
        regs.frame.rflags |= 0x200;
        // Pin IOPL=1 for every ring-3 guest. The whole system runs at IOPL=1:
        // the ring-1 kernel does port I/O directly, while ring-3 guests (VM86
        // and PM/DPMI) sit at CPL(3) > IOPL(1) so every IN/OUT is filtered
        // through the TSS I/O bitmap — open ports (VGA regs, AdLib) pass
        // straight through at full speed, closed ports (0x3DA, PIC, keyboard)
        // trap into the raster emu / vPIC / vkbd. There is no reason for a
        // client to run at IOPL=3: it gains nothing (the bitmap already grants
        // the VGA ports) and loses everything (IOPL=3 bypasses the bitmap, so
        // 0x3DA/0x20/0x60 go direct to the host — the Bochs keyboard/IRQ
        // breakage). IOPL is a preserved flag the guest can't change, so the
        // various cross-mode transitions that copy flags around can leak an
        // IOPL=3 into a client's eflags; normalize it here — the one ring-3
        // exit — rather than in each setter. (Where the 3 originates is still
        // open; see TODO "DPMI client IOPL=3 leak".)
        //
        // vIOPL: stash the virtual IOPL (bits 12-13) for the next entry, THEN
        // pin the real run IOPL=1. This replaces the old unconditional squash —
        // the kernel now owns the virtual IOPL and we carry it across the iret
        // like VIF/VIP, while the client always actually runs at IOPL=1.
        unsafe { VIOPL = ((regs.frame.rflags >> 12) & 3) as u8; }
        unsafe {
            USER_TF = regs.user_tf();
            FORCED_TF = regs.forced_tf();
            PVI_POLICY = regs.pvi_policy();
        }
        regs.frame.rflags &= !(arch_abi::USER_TF_SHADOW
            | arch_abi::FORCED_TF_SHADOW
            | arch_abi::PVI_POLICY_SHADOW);
        regs.frame.rflags = (regs.frame.rflags & !(3 << 12)) | (1 << 12);
    }

    unsafe { (*stack).decanonicalize(to_64); }
    if from_ring3 {
        crate::exec_profile::time(arch_abi::ExecutionProfileStage::Ring0ExitFrameOut);
    } else if execute_entry {
        crate::exec_profile::time(arch_abi::ExecutionProfileStage::Ring0EnterFrameOut);
    }
    to_64
}


/// Native kernel handoff: save the user frame and restore the suspended caller.
#[cfg(not(feature = "kvm"))]
fn return_to_kernel(regs: &mut Regs, event: arch_abi::KernelEvent) {
    crate::irq::arm_alarm(None);
    crate::traps::swap_regs(regs);
    let (event, extra) = event.encode();
    regs.rax = event as u64;
    regs.rdx = extra as u32 as u64;
    regs.rcx = extra >> 32;
}

/// Normalize a metal syscall before dispatch: the physical entry frame is
/// always the app frame while an operation runs. The syscall frame, including
/// its kernel continuation and result registers, stays in separate storage.
#[cfg(not(feature = "kvm"))]
fn kernel_call(frame: &mut Regs) {
    // swap_regs parks the kernel continuation and installs the app frame.
    // The operation reads/writes the parked call, never the app's registers.
    crate::traps::swap_regs(frame);
    if let arch_abi::entry::CallOutcome::Complete = crate::traps::dispatch_parked_call() {
        crate::traps::swap_regs(frame);
    }
    // execute leaves the app frame in place for the assembly IRET epilogue.
}

#[cfg(feature = "kvm")]
fn return_to_kernel(regs: &mut Regs, event: arch_abi::KernelEvent) {
    crate::vm::return_to_kernel(regs, event);
}
#[cfg(feature = "kvm")]
fn kernel_call(frame: &mut Regs) { crate::vm::requests(frame); }
