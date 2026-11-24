//! Native entry/return adaptation around canonical trap dispatch.
//! Raw stack conversion is shared with KVM in arch_abi::entry.
#![allow(static_mut_refs)]
use arch_abi::{Regs, entry::StackFrame};
use arch_abi::eflags::{IF_FLAG, TF_FLAG, NT_FLAG, VM_FLAG, VIF_FLAG, VIP_FLAG, IOPL_MASK, IOPL_SHIFT};
use crate::{descriptors, paging2, x86};
#[cfg(not(feature = "kvm"))]
use crate::traps::return_to_kernel;
#[cfg(feature = "kvm")]
use crate::vm::return_to_kernel;
use crate::traps::{arch_call, handle_ring0, isr_handler_ring1, guest_trap, Outcome};
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
/// Ring 0 (boot): IRQ → ACK+queue. Exceptions, including page faults, panic.
///
/// `stack` is the raw saved state on the kernel stack. `from_64` tells us which
/// union arm holds live data:
/// the 64-bit form pushed by `entry_wrapper_64`, or the 32-bit form pushed by
/// `entry_wrapper_32`. We canonicalize to `Regs` (always the 64-bit form), let
/// the kernel run on it, then denormalize back if exiting to 32-bit user.
///
/// Returns true if the kernel wants to iret to long mode (the 64-bit exit path).
///
/// # Safety
/// Assembly supplies exclusive, initialized storage for the entire `StackFrame`,
/// including the reserved VM86 tail. Unsaved fields contain unspecified values.
/// `from_64` selects the saved layout; core TLS and flat segments are installed.
#[unsafe(no_mangle)]
#[allow(private_interfaces)]
pub unsafe extern "C" fn isr_handler(stack: &mut StackFrame, from_64: bool) -> bool {
    paging2::refresh_kernel_mappings();
    // Hooks handle application traps only. Supervisor faults always retain
    // the normal fatal-fault path. Assembly has already established core TLS.
    let user = unsafe {
        if from_64 { stack.regs.frame.cs & 3 == 3 }
        else { stack.raw32.raw.cs & 3 == 3 || stack.raw32.raw.eflags & VM_FLAG != 0 }
    };
    if user && let Some(hook) = unsafe { ENTRY_HOOK } {
        let handled = unsafe { instruction32(stack, from_64) }.is_some_and(|state| {
            let mut access = NativeTrapAccess(core::cell::OnceCell::new());
            unsafe { (hook.handler)(state, &mut access, hook.regions.map(|region| region.base)) }
        });
        if handled {
            unsafe { prepare_espfix(stack, from_64); }
            return from_64;
        }
    }
    let wide = dispatch(stack, from_64);
    unsafe { prepare_espfix(stack, wide); }
    wide
}

// One fixed buffer, one six-dword slot per core. The shared SS descriptor
// addresses it through SP; no pointers or per-core descriptors are needed.
pub(crate) const ESPFIX_BYTES: usize = 24 * crate::smp::MAX_CORES;
pub(crate) static mut ESPFIX: [[u32; 6]; crate::smp::MAX_CORES] = [[0; 6]; crate::smp::MAX_CORES];
const _: () = assert!(ESPFIX_BYTES <= 65536);
unsafe extern "C" {
    fn espfix_return();
}

// Work on the native tail so handled hooks need not canonicalize registers.
unsafe fn prepare_espfix(stack: &mut StackFrame, long_mode: bool) {
    if long_mode {
        let frame = unsafe { &mut stack.regs.frame };
        if frame.cs & 3 == 0 || frame.cs as u16 == arch_abi::USER_CS64 { return; }
        if frame.ss as u16 == descriptors::ESPFIX_SS {
            // Resume the existing slot by repeating POP ESP.
            frame.rip = espfix_return as *const () as u64;
            frame.rsp = u64::from(crate::smp::current_core_id() * 24);
            return;
        }
        if frame.cs & 3 != 3 || frame.ss as u16 == arch_abi::USER_DS { return; }
        let descriptor = descriptors::read_descriptor(frame.ss as u16);
        if descriptor == 0 || descriptor & (1 << 54) != 0 { return; }
        if descriptors::read_descriptor(frame.cs as u16) & (1 << 53) != 0 { return; }
        let core = crate::smp::current_core_id() as usize;
        let offset = (core * 24) as u32;
        // This core exclusively owns its slot.
        unsafe { (&raw mut ESPFIX).cast::<[u32; 6]>().add(core).write([
            (frame.rsp as u32 & 0xffff0000) | (offset + 4),
            frame.rip as u32, frame.cs as u32, frame.rflags as u32,
            frame.rsp as u32, frame.ss as u32,
        ]); }
        frame.rip = espfix_return as *const () as u64;
        frame.cs = u64::from(descriptors::RING1_CS);
        frame.rflags &= !u64::from(VM_FLAG | NT_FLAG | IF_FLAG | TF_FLAG);
        frame.rsp = u64::from(offset);
        frame.ss = u64::from(descriptors::ESPFIX_SS);
    } else {
        let frame = unsafe { &mut stack.raw32.raw };
        // Ring-0 entries do not save SS:ESP. VM86 restores the whole ESP.
        if frame.eflags & VM_FLAG != 0 || frame.cs & 3 == 0 { return; }
        if frame.ss as u16 == descriptors::ESPFIX_SS {
            // Resume the existing slot by repeating POP ESP.
            frame.eip = espfix_return as *const () as u32;
            frame.esp = crate::smp::current_core_id() * 24;
            return;
        }
        if frame.cs & 3 != 3 || frame.ss as u16 == arch_abi::USER_DS { return; }
        let descriptor = descriptors::read_descriptor(frame.ss as u16);
        if descriptor == 0 || descriptor & (1 << 54) != 0 { return; }
        let core = crate::smp::current_core_id() as usize;
        let offset = (core * 24) as u32;
        // This core exclusively owns its slot.
        unsafe { (&raw mut ESPFIX).cast::<[u32; 6]>().add(core).write([
            (frame.esp & 0xffff0000) | (offset + 4),
            frame.eip, frame.cs, frame.eflags, frame.esp, frame.ss,
        ]); }
        frame.eip = espfix_return as *const () as u32;
        frame.cs = u32::from(descriptors::RING1_CS);
        frame.eflags &= !(VM_FLAG | NT_FLAG | IF_FLAG | TF_FLAG);
        frame.esp = offset;
        frame.ss = u32::from(descriptors::ESPFIX_SS);
    }
}

// Keep the full dispatch's stack frame off the direct-to-IRET path.
#[inline(never)]
fn dispatch(stack: &mut StackFrame, from_64: bool) -> bool {
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
        let r = unsafe { &stack.regs };
        (false, r.frame.cs, r.int_num, r.err_code, r.frame.rip)
    } else {
        let r = unsafe { &stack.raw32.raw };
        (r.eflags & VM_FLAG != 0, r.cs as u64, r.int_num as u64, r.err_code as u64, r.eip as u64)
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
            let p = unsafe { core::ptr::addr_of!(stack.raw32.raw.esp) };
            lib::compact_println!("ring0 fault: words above the trap frame (iret-target frame):");
            for i in 0..10 {
                lib::compact_println!("  [esp+{:2}] = {:#010x}", i * 4, unsafe { p.add(i).read_volatile() });
            }
        }
        handle_ring0(raw_int_num, raw_err_code, raw_cs, raw_eip);  // No canonicalization because in 32-bit mode doesn't match Regs layout due to missing esp:ss
        return from_64;
    }

    let regs = unsafe { stack.canonicalize(from_64) };
    let execute_entry = !from_ring3
        && raw_int_num == 0x80
        && regs.rax == arch_call::EXECUTE;

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
                if VIF { regs.frame.rflags |= u64::from(VIF_FLAG); } else { regs.frame.rflags &= !u64::from(VIF_FLAG); }
                if VIP { regs.frame.rflags |= u64::from(VIP_FLAG); } else { regs.frame.rflags &= !u64::from(VIP_FLAG); }
            }
        }
        // Restore the per-thread virtual IOPL: the run pinned real IOPL=1 on
        // exit, so the just-pushed frame reads 1; put the virtual level back in
        // bits 12-13 before the dispatch so `virtual_if_stepping` sees it.
        unsafe { regs.frame.rflags = (regs.frame.rflags & !u64::from(IOPL_MASK)) | ((VIOPL as u64) << IOPL_SHIFT); }
        unsafe {
            regs.set_user_tf(USER_TF);
            regs.set_forced_tf(FORCED_TF);
            regs.set_pvi_policy(PVI_POLICY);
        }
        crate::exec_profile::time(arch_abi::ExecutionProfileStage::Ring0ExitFrameIn);
        match guest_trap(regs) {
            Outcome::ReturnToKernel(event) => return_to_kernel(regs, event),
            Outcome::Resume if !crate::memory::can_fault() =>
                return_to_kernel(regs, arch_abi::KernelEvent::Irq),
            Outcome::Resume => {},
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
                VIF = regs.frame.rflags & u64::from(VIF_FLAG) != 0;
                VIP = regs.frame.rflags & u64::from(VIP_FLAG) != 0;
            }
            regs.frame.rflags &= !u64::from(VIF_FLAG | VIP_FLAG);
        }
        regs.frame.rflags |= u64::from(IF_FLAG);
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
        unsafe { VIOPL = ((regs.frame.rflags >> IOPL_SHIFT) & 3) as u8; }
        unsafe {
            USER_TF = regs.user_tf();
            FORCED_TF = regs.forced_tf();
            PVI_POLICY = regs.pvi_policy();
        }
        regs.frame.rflags &= !(arch_abi::USER_TF_SHADOW
            | arch_abi::FORCED_TF_SHADOW
            | arch_abi::PVI_POLICY_SHADOW);
        regs.frame.rflags = (regs.frame.rflags & !u64::from(IOPL_MASK)) | (1 << IOPL_SHIFT);
    }

    unsafe { stack.decanonicalize(to_64); }
    if from_ring3 {
        crate::exec_profile::time(arch_abi::ExecutionProfileStage::Ring0ExitFrameOut);
    } else if execute_entry {
        crate::exec_profile::time(arch_abi::ExecutionProfileStage::Ring0EnterFrameOut);
    }
    to_64
}


use arch_abi::entry::{InstructionState, TrapAccess, TrapHook};

#[thread_local]
static mut ENTRY_HOOK: Option<TrapHook> = None;

pub(crate) unsafe fn install_hook(hook: Option<TrapHook>) {
    unsafe { ENTRY_HOOK = hook; }
}

struct NativeTrapAccess(core::cell::OnceCell<crate::paging2::PagingGuard>);
unsafe impl TrapAccess for NativeTrapAccess {
    fn segment(&self, selector: u16) -> (u32, u32, bool) {
        let descriptor = crate::descriptors::read_descriptor(selector);
        let base = ((descriptor >> 16) as u32 & 0xff_ffff) | ((descriptor >> 32) as u32 & 0xff00_0000);
        let limit = (descriptor as u32 & 0xffff) | ((descriptor >> 32) as u32 & 0xf0000);
        let limit = if descriptor & (1 << 55) != 0 { (limit << 12) | 4095 } else { limit };
        (base, limit, selector == 0 || descriptor & (1 << 54) != 0)
    }
    fn resident(&self, address: u32, len: u32, write: bool) -> bool {
        self.0.get_or_init(crate::paging2::PagingGuard::lock);
        crate::mapping::resident(address, len, write)
    }
    fn direct_ram(&self, address: u32, len: u32) -> Option<*const u8> {
        self.resident(address, len, false).then_some(address as *const u8)
    }
    unsafe fn fetched_code(&self, address: u32) -> Option<*const u8> {
        (address < 0xc000_0000).then_some(address as *const u8)
    }
    unsafe fn read(&self, address: u32) -> u8 {
        unsafe { (address as *const u8).read_volatile() }
    }
    unsafe fn write(&mut self, address: u32, byte: u8) {
        unsafe { (address as *mut u8).write_volatile(byte); }
    }
    fn fpu_st0(&self) -> [u8; 10] { crate::x86::fpu_st0() }
    fn fpu_pop(&mut self) { crate::x86::fpu_pop(); }
}

/// Borrow only saved fields, leaving unsaved halves and the expansion gap
/// untouched. Edits directly update the native frame, even on a decline.
///
/// # Safety
/// The frame must be a user entry in the selected layout. Long-mode user code
/// is declined. All returned borrows belong to the supplied frame.
#[inline(always)]
pub(crate) unsafe fn instruction32(stack: &mut StackFrame, wide: bool) -> Option<InstructionState<'_>> {
    // x86 is little-endian. Split each slot into disjoint, lifetime-bound halves.
    #[inline(always)]
    fn halves(slot: &mut u64) -> (&mut u32, &mut u32) {
        let [low, high] = unsafe { &mut *(slot as *mut u64).cast::<[u32; 2]>() };
        (low, high)
    }
    if wide {
        let r = unsafe { &mut stack.regs };
        if r.frame.cs == u64::from(arch_abi::USER_CS64) { return None; }
        let words = [&mut r.rax, &mut r.rcx, &mut r.rdx, &mut r.rbx,
            &mut r.frame.rsp, &mut r.rbp, &mut r.rsi, &mut r.rdi].map(halves);
        let [(ax, ah), (cx, ch), (dx, dh), (bx, bh),
            (sp, sph), (bp, bph), (si, sih), (di, dih)] = words;
        Some(InstructionState {
            gprs: [ax, cx, dx, bx, sp, bp, si, di],
            high: Some([ah, ch, dh, bh, sph, bph, sih, dih]),
            ip: halves(&mut r.frame.rip).0,
            flags: halves(&mut r.frame.rflags).0,
            selectors: [r.es as u16, r.frame.cs as u16, r.frame.ss as u16,
                r.ds as u16, r.fs as u16, r.gs as u16],
            vector: r.int_num, error: r.err_code,
            address: if r.int_num == 14 { crate::x86::read_cr2_full() } else { 0 },
        })
    } else {
        let frame = unsafe { &mut stack.raw32 };
        let r = &mut frame.raw;
        let selectors = if r.eflags & VM_FLAG != 0 {
            let vm = &frame.vm86;
            [vm.es as u16, r.cs as u16, r.ss as u16,
                vm.ds as u16, vm.fs as u16, vm.gs as u16]
        } else {
            [r.es as u16, r.cs as u16, r.ss as u16,
                r.ds as u16, r.fs as u16, r.gs as u16]
        };
        Some(InstructionState {
            gprs: [halves(&mut r.eax).0, halves(&mut r.ecx).0,
                halves(&mut r.edx).0, halves(&mut r.ebx).0, &mut r.esp,
                halves(&mut r.ebp).0, halves(&mut r.esi).0, halves(&mut r.edi).0],
            high: None,
            ip: &mut r.eip, flags: &mut r.eflags, selectors,
            vector: u64::from(r.int_num), error: u64::from(r.err_code),
            address: if r.int_num == 14 { u64::from(crate::x86::read_cr2()) } else { 0 },
        })
    }
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
fn kernel_call(frame: &mut Regs) { crate::vm::requests(frame); }
