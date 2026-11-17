//! The KVM execute loop: enter the guest at CPL3 (flat PM, DPMI PM, or VM86),
//! demux `KVM_EXIT_*` back into `KernelEvent`s.
//!
//! Structure mirrors `cpu.rs::execute` on the TCG engine — same virtual-IF
//! stepping, same demand-#PF/COW resolution without bubbling, same shared
//! monitor on sensitive-#GP — so the kernel sees identical events from both
//! engines. KVM enters the shared assembly return path at CPL0; its IRET
//! restores the user frame. Traps use the same entry assembly as metal and
//! hand the saved frame back to the host through the shim's OUT instruction.

use super::setup::{with, KvmCpu};
use super::entry::{enter, sync_out, sync_out_shim, frame_address, read_frame, SHIM_PORT};
use crate::sysdesc::{KERNEL_CS64, VIF_FLAG, VM_FLAG};
use arch_abi::GuestBytes;
use arch_abi::{KernelEvent, UserMode};
use kvm_bindings::{
    kvm_guest_debug, kvm_guest_debug_arch, KVM_GUESTDBG_ENABLE,
    KVM_GUESTDBG_USE_HW_BP,
};
use kvm_ioctls::VcpuExit;


/// Per-slice transition trace, gated by `RETRO_TRACE` (checked once). Same
/// lens as the TCG engine's.
fn trace_on() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("RETRO_TRACE").is_some())
}

/// Virtual-IF transition trace (`RETRO_STEP_TRACE`).
fn step_trace_on() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("RETRO_STEP_TRACE").is_some())
}

/// Length of the IN/OUT instruction at the interrupted IP (a direct
/// `KVM_EXIT_IO` exits before it retires, so the bytes at CS:IP are the I/O
/// instruction itself). Only the non-string forms are supported: the kernel's
/// io_policy grants scalar register windows, and string I/O on an allowed
/// port would need KVM's deferred emulator completion (SI/DI/CX bookkeeping)
/// that our fresh-entry model deliberately cancels — panic loudly rather
/// than corrupt the guest.
fn io_insn_len(vcpu: &crate::vcpu::Vcpu, port: u16) -> u32 {
    let base = if vcpu.mode() == UserMode::VM86 {
        (vcpu.code_seg() as u32) << 4
    } else {
        crate::desc::seg_base(vcpu.code_seg())
    };
    let mut len: u32 = 0;
    loop {
        let b = crate::backend::Interp.read::<u8>(base.wrapping_add(vcpu.ip32()).wrapping_add(len) as u64);
        match b {
            // Legacy prefixes (operand/address size, rep, lock, seg overrides).
            0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 => len += 1,
            0xE4..=0xE7 => return len + 2, // in/out acc, imm8
            0xEC..=0xEF => return len + 1, // in/out acc, dx
            0x6C..=0x6F => panic!(
                "string I/O on IOPB-allowed port {port:#x} — unsupported; keep the port trapped"
            ),
            _ => panic!(
                "KVM_EXIT_IO on port {port:#x} but no I/O opcode at CS:IP ({b:#04x} at +{len})"
            ),
        }
        assert!(len < 8, "runaway prefix decode at CS:IP");
    }
}

/// Finish KVM's deferred I/O before replacing its machine mode or registers.
/// immediate_exit completes the pending instruction without executing another.
fn complete_io(k: &mut KvmCpu) {
    unsafe {
        // Keep a timer signal from being lost while temporarily forcing exit.
        let mut blocked: libc::sigset_t = core::mem::zeroed();
        let mut previous: libc::sigset_t = core::mem::zeroed();
        libc::sigemptyset(&mut blocked);
        libc::sigaddset(&mut blocked, libc::SIGURG);
        assert_eq!(libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous), 0);
        let pending = k.vcpu.get_kvm_run().immediate_exit;
        k.vcpu.set_kvm_immediate_exit(1);
        let result = k.vcpu.run();
        assert!(matches!(result, Err(e) if e.errno() == libc::EINTR), "I/O completion ran guest code");
        k.vcpu.set_kvm_immediate_exit(pending);
        assert_eq!(libc::pthread_sigmask(libc::SIG_SETMASK, &previous, core::ptr::null_mut()), 0);
    }
}

/// Whether the vcpu is currently executing the trap shim (CPL0). Only the
/// shim ever runs with the flat ring-0 CS.
fn in_shim(k: &KvmCpu) -> bool {
    let sregs = k.vcpu.get_sregs().expect("KVM_GET_SREGS");
    sregs.cs.selector == crate::sysdesc::KERNEL_CS || sregs.cs.selector == KERNEL_CS64
}

fn queued_exception(k: &KvmCpu) -> bool {
    let events = k.vcpu.get_vcpu_events().expect("KVM_GET_VCPU_EVENTS");
    events.exception.injected != 0 || events.exception.pending != 0
}

/// Intercept #DB. The shared IRET loads TF from the user frame, so stepping
/// begins in user code, without KVM single-stepping the return assembly.
fn apply_guest_debug(k: &mut KvmCpu) {
    let control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP;
    if control == k.dbg_control { return; }
    let arch = kvm_guest_debug_arch { debugreg: [0; 8] };
    let dbg = kvm_guest_debug { control, pad: 0, arch };
    k.vcpu.set_guest_debug(&dbg).expect("KVM_SET_GUEST_DEBUG");
    k.dbg_control = control;
}

/// Run the current Vcpu (`REGS`) until the next kernel-visible event.
#[allow(clippy::deref_addrof)] // Form a raw pointer before borrowing the live static.
pub fn execute(max_time: core::time::Duration) -> KernelEvent {
    if max_time.is_zero() { return KernelEvent::Irq; }
    // Forget signals handled before this call. Once execution starts, a new
    // signal must survive guest-state setup and reach KVM_RUN.
    with(|k| k.vcpu.set_kvm_immediate_exit(0));
    let max_ns = max_time.as_nanos().min(u64::MAX as u128) as u64;
    super::setup::arm_alarm(Some(crate::machine::now().saturating_add(max_ns)));
    let event = with(|k| loop {
        // Off-thread VGA snapshot / live terminal paint (CPU thread only).
        crate::screendump::maybe_dump();
        crate::screendump::maybe_render_live();

        // One `&mut Vcpu` for the iteration — the sole unsafe is dereferencing
        // the `static mut REGS`; the monitor, memory reads and enter/sync_out
        // helpers all reborrow it (register access via Deref, memory via GuestBytes).
        let vcpu = unsafe { &mut *(&raw mut crate::vcpu::REGS) };
        let mode = vcpu.mode();

        // Entry projects stepping into the IRET frame, so TF starts at CPL3.
        let stepping = arch_abi::monitor::stepping(&vcpu.regs);

        if trace_on() {
            eprintln!(
                "[kvm] mode={:?} cs={:#06x}:{:#010x} ss={:#06x}:{:#010x} ds={:#06x} flags={:#x} step={}",
                mode, vcpu.code_seg(), vcpu.frame.rip, vcpu.frame.ss as u16, vcpu.frame.rsp,
                vcpu.ds as u16, vcpu.frame.rflags, stepping
            );
        }

        // VIF-drop probe (bring-up diagnostic): a slice that enters with the
        // virtual IF set and comes back with it clear must correspond to a
        // guest CLI (opcode FA at the pre-slice IP, emulated by the monitor).
        // Anything else is the engine losing an interrupt-enable.
        let vif_pre = vcpu.flags32() & VIF_FLAG != 0;
        let pre_cs = vcpu.code_seg();
        let pre_ip = vcpu.ip32();
        let mut shim_vec: Option<(u8, u32)> = None;

        enter(k, vcpu, mode);
        apply_guest_debug(k);

        // The inner run loop: an EINTR (timer kick) or single-step exit can
        // land while the vcpu is INSIDE the trap shim — the CPL3→CPL0
        // delivery happened but the stub's exit `out` hasn't retired. Ring-0
        // shim state must NOT surface as user vcpu (the TCG engine has the
        // identical rule for its trampoline, cpu.rs "trampoline retire"): the
        // interrupted user frame lives on the ring-0 stack and only the stub
        // knows the vector. So: leave the vcpu state untouched and re-run
        // until the stub finishes its exit. (`Kind` exists because `VcpuExit`
        // borrows the vcpu — it must drop before `in_shim` can look at it.)
        enum Kind {
            Intr,
            Shim,
            Io { port: u16, is_in: bool, bytes: usize },
            /// A #DB: either a single-step (BS) from projected TF, or a tagged
            /// POPF/IRET loading TF and trapping one instruction later.
            Debug,
            BadPhys,
            Shutdown,
        }
        let ev = loop {
            let kind = match k.vcpu.run() {
                // Timer kick (or any host signal).
                Err(e) if e.errno() == libc::EINTR => {
                    k.vcpu.set_kvm_immediate_exit(0);
                    Kind::Intr
                },
                Err(e) => panic!("KVM_RUN failed: {e}"),
                Ok(VcpuExit::IoOut(SHIM_PORT, _)) => Kind::Shim,
                // An IOPB-allowed port: hardware ran the access with no #GP —
                // the fast path past the shim + monitor.
                Ok(VcpuExit::IoOut(port, data)) => Kind::Io { port, is_in: false, bytes: data.len() },
                Ok(VcpuExit::IoIn(port, data)) => Kind::Io { port, is_in: true, bytes: data.len() },
                Ok(VcpuExit::Debug(_)) => Kind::Debug,
                // A guest-physical access outside the memory slot: a page
                // table pointing at a nonexistent frame (TCG's MEM_UNMAPPED
                // analogue).
                Ok(VcpuExit::MmioRead(..)) | Ok(VcpuExit::MmioWrite(..)) => Kind::BadPhys,
                // Triple fault et al.
                Ok(VcpuExit::Shutdown) => Kind::Shutdown,
                Ok(VcpuExit::FailEntry(reason, cpu)) => {
                    let sregs = k.vcpu.get_sregs();
                    let regs = k.vcpu.get_regs();
                    panic!(
                        "KVM_EXIT_FAIL_ENTRY (reason={reason:#x}, cpu={cpu}) mode={mode:?} \
                         cs={:#x}:{:#x} regs={regs:#x?} sregs={sregs:#x?}",
                        vcpu.code_seg(),
                        vcpu.frame.rip
                    );
                }
                Ok(other) => panic!("unhandled KVM exit: {other:?}"),
            };
            match kind {
                Kind::Intr | Kind::Debug if in_shim(k) => continue,
                Kind::Intr => {
                    // A host timer can interrupt KVM after a fault is queued
                    // but before its IDT delivery. Let that delivery reach the
                    // shim before scheduling another guest context; otherwise
                    // the queued exception is injected at the new context's IP.
                    if queued_exception(k) {
                        if trace_on() { eprintln!("[kvm] draining queued exception"); }
                        continue;
                    }
                    sync_out(k, vcpu, mode);
                    break Some(KernelEvent::Irq);
                }
                // A #DB retired. Protected-mode source attribution lives in DOS;
                // a VM86 #DB follows the interpreter's separate exception path.
                Kind::Debug => {
                    sync_out(k, vcpu, mode);
                    if mode == UserMode::Mode32 {
                        break Some(KernelEvent::DebugTrap);
                    }
                    break None;
                }
                Kind::Shim => {
                    let kregs = k.vcpu.get_regs().expect("KVM_GET_REGS");
                    let f = read_frame(frame_address(kregs.rsp), mode == UserMode::Mode64);
                    assert!(f.flags32() & (VM_FLAG as u32) != 0 || f.code_seg() & 3 == 3,
                        "fault in shared entry: vector={} cs={:#x} ip={:#x}", f.int_num, f.code_seg(), f.frame.rip);
                    shim_vec = Some((f.int_num as u8, f.err_code as u32));
                    sync_out_shim(vcpu, mode, &f);
                    complete_io(k);
                    break super::trap::handle(k, vcpu);
                }
                // Report the monitor's post-instruction contract. KVM's
                // deferred I/O is completed before another frame is installed;
                // the kernel supplies the IN result in that next frame's EAX.
                Kind::Io { port, is_in, bytes } => {
                    sync_out(k, vcpu, mode);
                    complete_io(k);
                    let len = io_insn_len(vcpu, port);
                    let ip = vcpu.ip32().wrapping_add(len);
                    let wrap16 = mode == UserMode::VM86
                        || !crate::desc::seg_is_32(vcpu.code_seg());
                    vcpu.set_ip32(if wrap16 { ip & 0xFFFF } else { ip });
                    let size = match bytes {
                        1 => arch_abi::IoSize::Byte,
                        2 => arch_abi::IoSize::Word,
                        _ => arch_abi::IoSize::Dword,
                    };
                    break Some(if is_in {
                        KernelEvent::In { port, size }
                    } else {
                        KernelEvent::Out { port, size }
                    });
                }
                Kind::BadPhys | Kind::Shutdown => {
                    sync_out(k, vcpu, mode);
                    break Some(KernelEvent::Fault);
                }
            }
        };

        if step_trace_on() && vif_pre && vcpu.flags32() & VIF_FLAG == 0 {
            let base = if mode == UserMode::VM86 {
                (pre_cs as u32) << 4
            } else {
                crate::desc::seg_base(pre_cs)
            };
            let op = crate::backend::Interp.read::<u8>(base.wrapping_add(pre_ip) as u64);
            eprintln!(
                "[VIF-DROP] mode={mode:?} pre={pre_cs:#06x}:{pre_ip:#010x} op={op:02X} \
                 post={:#06x}:{:#010x} shim={shim_vec:?} ev={ev:?}",
                vcpu.code_seg(), vcpu.ip32()
            );
        }
        if trace_on() {
            eprintln!(
                "   -> cs={:#06x}:{:#010x} ss={:#06x}:{:#010x} ev={ev:?}",
                vcpu.code_seg(), vcpu.frame.rip, vcpu.frame.ss as u16, vcpu.frame.rsp
            );
        }
        match ev {
            Some(e) => return e,
            None => continue,
        }
    });
    super::setup::arm_alarm(None);
    event
}
