//! The KVM execute loop: enter the guest at CPL3 (flat PM, DPMI PM, or VM86),
//! demux `KVM_EXIT_*` back into `KernelEvent`s.
//!
//! Structure mirrors `cpu.rs::execute` on the TCG engine — same virtual-IF
//! stepping, same demand-#PF/COW resolution without bubbling, same shared
//! monitor on sensitive-#GP — so the kernel sees identical events from both
//! engines. Where TCG needed the CPL0 `iretd` trampoline (Unicorn can't be
//! told "you are at CPL3"), KVM simply accepts CS.RPL=3 segment state; where
//! TCG surfaced traps as hooks, KVM vectors them through the in-guest shim
//! (`shim.rs`) and exits on its magic OUT.

use super::setup::{with, KvmCpu};
use super::shim::{read_frame, ShimFrame, SHIM_PORT};
use crate::sysdesc::{
    if_to_vif, sys_ptr, vif_to_if, write_tables, GDT_ADDR, GDT_BYTES, IDT_ADDR, IOPL_MASK,
    LDT_ADDR, LDT_SEL, NT_FLAG, TF_FLAG, TSS_ADDR, TSS_SEL, VIF_FLAG, VM_FLAG,
};
use crate::vcpu;
use crate::view::InterpView;
use arch_abi::monitor::MonitorResult;
use arch_abi::{KernelEvent, Regs, UserMode};
use kvm_bindings::{kvm_guest_debug, kvm_regs, kvm_segment, KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP};
use kvm_ioctls::VcpuExit;

/// Per-slice transition trace, gated by `RETRO_TRACE` (checked once). Same
/// lens as the TCG engine's.
fn trace_on() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("RETRO_TRACE").is_some())
}

/// A null/unusable segment cache.
fn null_seg() -> kvm_segment {
    kvm_segment { unusable: 1, ..Default::default() }
}

/// VM86 segment cache: the strict shape VMX entry checks demand in v86 mode.
fn v86_seg(sel: u16) -> kvm_segment {
    kvm_segment {
        base: (sel as u64) << 4,
        limit: 0xFFFF,
        selector: sel,
        type_: 3,
        present: 1,
        dpl: 3,
        db: 0,
        s: 1,
        l: 0,
        g: 0,
        avl: 0,
        unusable: 0,
        padding: 0,
    }
}

/// Decode a protected-mode selector into a segment cache by reading the raw
/// descriptor out of the SYS-window GDT/LDT image `write_tables` just wrote —
/// the same bytes the guest CPU itself walks on a segment load, so the cache
/// and a subsequent in-guest reload can't diverge.
fn decode_sel(sel: u16) -> kvm_segment {
    if sel & !0x3 == 0 {
        return null_seg();
    }
    let index = (sel >> 3) as u64;
    let raw = {
        let p = if sel & 4 != 0 {
            sys_ptr(LDT_ADDR + index * 8)
        } else {
            sys_ptr(GDT_ADDR + index * 8)
        };
        let mut b = [0u8; 8];
        unsafe { core::ptr::copy_nonoverlapping(p, b.as_mut_ptr(), 8) };
        u64::from_le_bytes(b)
    };
    let base = ((raw >> 16) & 0xFFFF) | (((raw >> 32) & 0xFF) << 16) | (((raw >> 56) & 0xFF) << 24);
    let limit_raw = ((raw & 0xFFFF) | (((raw >> 48) & 0xF) << 16)) as u32;
    let g = ((raw >> 55) & 1) as u8;
    let limit = if g != 0 { (limit_raw << 12) | 0xFFF } else { limit_raw };
    let access = ((raw >> 40) & 0xFF) as u8;
    let present = (access >> 7) & 1;
    kvm_segment {
        base,
        limit,
        selector: sel,
        type_: access & 0xF,
        present,
        dpl: (access >> 5) & 3,
        db: ((raw >> 54) & 1) as u8,
        s: (access >> 4) & 1,
        l: ((raw >> 53) & 1) as u8,
        g,
        avl: ((raw >> 52) & 1) as u8,
        unusable: 1 - present,
        padding: 0,
    }
}

/// Build sregs + regs from the kernel's `Regs` and enter-able mode, then load
/// them into the vcpu. Unconditional per entry (like the TCG trampoline, which
/// also rewrites everything) — and `KVM_SET_SREGS` resets the vcpu's MMU
/// context, which is exactly the TLB flush the kernel's host-side page-table
/// edits require before re-entry.
fn enter(k: &mut KvmCpu, r: &Regs, mode: UserMode) {
    let ldt_limit = write_tables();

    let mut sregs = k.sregs0;
    sregs.cr0 = 0x8000_0033; // PG | NE | ET | MP | PE (NE: VMX fixed-1; WP off like a 486)
    sregs.cr3 = crate::paging::frame_phys(crate::paging::active_pd()) as u64;
    sregs.cr4 = 0x600; // OSFXSR | OSXMMEXCPT (SSE, like metal/TCG); VME=0 — sensitive ops must #GP
    sregs.efer = 0;
    sregs.gdt.base = GDT_ADDR;
    sregs.gdt.limit = (GDT_BYTES - 1) as u16;
    sregs.idt.base = IDT_ADDR;
    sregs.idt.limit = 0x7FF;
    sregs.tr = kvm_segment {
        base: TSS_ADDR,
        limit: 0x1FF,
        selector: TSS_SEL,
        type_: 11, // busy 32-bit TSS (VM entry requires busy)
        present: 1,
        s: 0,
        ..Default::default()
    };
    sregs.ldt = if ldt_limit == 0 {
        kvm_segment { unusable: 1, ..Default::default() }
    } else {
        kvm_segment {
            base: LDT_ADDR,
            limit: ldt_limit,
            selector: LDT_SEL,
            type_: 2,
            present: 1,
            s: 0,
            ..Default::default()
        }
    };

    let mut regs = kvm_regs {
        rax: r.rax,
        rbx: r.rbx,
        rcx: r.rcx,
        rdx: r.rdx,
        rsi: r.rsi,
        rdi: r.rdi,
        rbp: r.rbp,
        rsp: r.frame.rsp,
        rip: r.frame.rip,
        ..Default::default()
    };

    match mode {
        UserMode::VM86 => {
            // VM86 runs paged at CPL3/IOPL=1, exactly like the TCG engine and
            // metal: every IOPL-sensitive op (CLI/STI/PUSHF/POPF/IRET/INT n)
            // #GPs into the shared monitor, which owns the virtual IF.
            sregs.cs = v86_seg(r.code_seg());
            sregs.ss = v86_seg(r.stack_seg());
            sregs.es = v86_seg(r.es as u16);
            sregs.ds = v86_seg(r.ds as u16);
            sregs.fs = v86_seg(r.fs as u16);
            sregs.gs = v86_seg(r.gs as u16);
            regs.rip = (r.ip32() & 0xFFFF) as u64;
            regs.rsp = (r.sp32() & 0xFFFF) as u64;
            regs.rflags = vif_to_if(
                (r.flags32() & !(IOPL_MASK as u32) & !NT_FLAG) | (VM_FLAG as u32) | (1 << 12) | 2,
            ) as u64;
        }
        UserMode::Mode32 => {
            // CPL=3, IOPL=1 — CLI/STI #GP into the monitor; POPF/IRET silently
            // drop IF at CPL>IOPL, caught by the virtual-IF single-stepping in
            // `execute` (KVM_GUESTDBG single-step, not guest TF).
            sregs.cs = decode_sel(r.code_seg());
            sregs.ss = decode_sel(r.stack_seg());
            sregs.ds = decode_sel(r.ds as u16);
            sregs.es = decode_sel(r.es as u16);
            sregs.fs = decode_sel(r.fs as u16);
            sregs.gs = decode_sel(r.gs as u16);
            regs.rflags = vif_to_if(
                (r.flags32() & !(VM_FLAG as u32) & !(IOPL_MASK as u32) & !NT_FLAG & !TF_FLAG)
                    | (1 << 12)
                    | 2,
            ) as u64;
        }
        UserMode::Mode64 => {
            // 64-bit guests aren't run natively yet (the hosted machine model
            // is 32-bit non-PAE); run flat-32 at CPL3 like the TCG engine
            // (smoke paths only).
            use arch_abi::{USER_CS, USER_DS};
            sregs.cs = decode_sel(USER_CS);
            sregs.ss = decode_sel(USER_DS);
            sregs.ds = decode_sel(USER_DS);
            sregs.es = decode_sel(USER_DS);
            sregs.fs = decode_sel(USER_DS);
            sregs.gs = decode_sel(USER_DS);
            regs.rflags = ((r.frame.rflags as u32 & !(IOPL_MASK as u32)) | (1 << 12) | 2) as u64;
        }
    }

    k.vcpu.set_sregs(&sregs).expect("KVM_SET_SREGS");
    k.vcpu.set_regs(&regs).expect("KVM_SET_REGS");
}

/// Read guest state back into `Regs` after an exit that did NOT go through the
/// shim (timer EINTR, single-step debug exit): the interrupted user state is
/// live in the vcpu registers.
fn sync_out(k: &KvmCpu, r: &mut Regs, mode: UserMode) {
    let regs = k.vcpu.get_regs().expect("KVM_GET_REGS");
    let sregs = k.vcpu.get_sregs().expect("KVM_GET_SREGS");
    r.rax = regs.rax;
    r.rbx = regs.rbx;
    r.rcx = regs.rcx;
    r.rdx = regs.rdx;
    r.rsi = regs.rsi;
    r.rdi = regs.rdi;
    r.rbp = regs.rbp;
    r.frame.rsp = regs.rsp;
    r.frame.rip = regs.rip;
    store_segs_flags(
        r,
        mode,
        regs.rflags as u32,
        [
            sregs.cs.selector as u32,
            sregs.ss.selector as u32,
            sregs.ds.selector as u32,
            sregs.es.selector as u32,
            sregs.fs.selector as u32,
            sregs.gs.selector as u32,
        ],
    );
}

/// Read guest state back into `Regs` after a shim exit: GPRs are live in the
/// vcpu (the stubs clobber nothing — `out imm8, al` only reads AL), the
/// interrupted frame comes off the ring-0 stack.
fn sync_out_shim(k: &KvmCpu, r: &mut Regs, mode: UserMode, f: &ShimFrame) {
    let regs = k.vcpu.get_regs().expect("KVM_GET_REGS");
    r.rax = regs.rax;
    r.rbx = regs.rbx;
    r.rcx = regs.rcx;
    r.rdx = regs.rdx;
    r.rsi = regs.rsi;
    r.rdi = regs.rdi;
    r.rbp = regs.rbp;
    r.frame.rsp = f.esp as u64;
    r.frame.rip = f.eip as u64;
    let segs = if f.eflags & (VM_FLAG as u32) != 0 {
        // VM86: interrupt delivery nulled the live data segments; the user's
        // are on the stack (ES DS FS GS).
        [f.cs, f.ss, f.vm86_segs[1], f.vm86_segs[0], f.vm86_segs[2], f.vm86_segs[3]]
    } else {
        // PM: interrupt gates leave data segments holding the user selectors.
        let sregs = k.vcpu.get_sregs().expect("KVM_GET_SREGS");
        [
            f.cs,
            f.ss,
            sregs.ds.selector as u32,
            sregs.es.selector as u32,
            sregs.fs.selector as u32,
            sregs.gs.selector as u32,
        ]
    };
    store_segs_flags(r, mode, f.eflags, segs);
}

/// The exit-side EFLAGS/segment normalization — identical to the TCG engine's
/// `store_regs`: IF mirrored into VIF (real IF forced 1), IOPL normalized to 1,
/// TF stripped, VM re-asserted for VM86; SP/IP masked to 16 bits when SS/CS is
/// a 16-bit segment.
fn store_segs_flags(r: &mut Regs, mode: UserMode, eflags: u32, segs: [u32; 6]) {
    let [cs, ss, ds, es, fs, gs] = segs;
    match mode {
        UserMode::VM86 => {
            r.set_cs32(cs);
            r.set_ss32(ss);
            r.ds = ds as u64;
            r.es = es as u64;
            r.fs = fs as u64;
            r.gs = gs as u64;
            let fl = if_to_vif(eflags) as u64;
            r.frame.rflags = (fl & !IOPL_MASK) | VM_FLAG | (1 << 12);
        }
        UserMode::Mode32 => {
            r.set_cs32(cs);
            r.set_ss32(ss);
            r.ds = ds as u64;
            r.es = es as u64;
            r.fs = fs as u64;
            r.gs = gs as u64;
            let fl = if_to_vif(eflags) as u64;
            r.frame.rflags = (fl & !IOPL_MASK & !(TF_FLAG as u64)) | (1 << 12);
            if !crate::desc::seg_is_32(ss as u16) {
                r.frame.rsp &= 0xFFFF;
            }
            if !crate::desc::seg_is_32(cs as u16) {
                r.frame.rip &= 0xFFFF;
            }
        }
        UserMode::Mode64 => {
            r.frame.rflags = eflags as u64;
        }
    }
}

/// Whether the vcpu is currently executing the trap shim (CPL0). Only the
/// shim ever runs with the flat ring-0 CS.
fn in_shim(k: &KvmCpu) -> bool {
    let sregs = k.vcpu.get_sregs().expect("KVM_GET_SREGS");
    sregs.cs.selector == crate::sysdesc::KERNEL_CS
}

/// Arm/disarm hardware single-step (the virtual-IF stepping driver). Only
/// ioctls on a state change.
fn set_single_step(k: &mut KvmCpu, on: bool) {
    if k.single_step == on {
        return;
    }
    let control = if on { KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP } else { 0 };
    let dbg = kvm_guest_debug { control, pad: 0, ..Default::default() };
    k.vcpu.set_guest_debug(&dbg).expect("KVM_SET_GUEST_DEBUG");
    k.single_step = on;
}

/// Run the current Vcpu (`REGS`) until the next kernel-visible event.
pub fn execute() -> KernelEvent {
    with(|k| loop {
        // Off-thread VGA snapshot / live terminal paint (CPU thread only).
        crate::screendump::maybe_dump();
        crate::screendump::maybe_render_live();

        let p = &raw mut vcpu::REGS;
        let regs = unsafe { &mut (*p).regs };
        let mode = regs.mode();

        // Virtual-IF stepping: while a PM client's virtual IF is off, emulate
        // the IF-touching opcodes in software; hardware runs only one
        // non-sensitive instruction at a time (KVM single-step).
        let mut stepping = false;
        if mode == UserMode::Mode32 && regs.flags32() & VIF_FLAG == 0 {
            let mut view = InterpView { space: unsafe { &mut (*p).space } };
            if let MonitorResult::Event(ev) = arch_abi::monitor::step_virtual_if(regs, &mut view) {
                return ev;
            }
            stepping = regs.flags32() & VIF_FLAG == 0;
        }
        set_single_step(k, stepping);

        // The INTR-line check (the TCG block hook's analogue): hand the slice
        // to the kernel when an IRQ is deliverable.
        if crate::machine::irq_line() && regs.flags32() & VIF_FLAG != 0 {
            return KernelEvent::Irq;
        }

        if trace_on() {
            eprintln!(
                "[kvm] mode={:?} cs={:#06x}:{:#010x} ss={:#06x}:{:#010x} ds={:#06x} flags={:#x} step={}",
                mode, regs.code_seg(), regs.frame.rip, regs.frame.ss as u16, regs.frame.rsp,
                regs.ds as u16, regs.frame.rflags, stepping
            );
        }

        enter(k, regs, mode);

        // The inner run loop: an EINTR (timer kick) or single-step exit can
        // land while the vcpu is INSIDE the trap shim — the CPL3→CPL0
        // delivery happened but the stub's exit `out` hasn't retired. Ring-0
        // shim state must NOT surface as user regs (the TCG engine has the
        // identical rule for its trampoline, cpu.rs "trampoline retire"): the
        // interrupted user frame lives on the ring-0 stack and only the stub
        // knows the vector. So: leave the vcpu state untouched and re-run
        // until the stub finishes its exit. (`Kind` exists because `VcpuExit`
        // borrows the vcpu — it must drop before `in_shim` can look at it.)
        enum Kind {
            Intr,
            Shim,
            Debug,
            BadPhys,
            Shutdown,
        }
        let ev = loop {
            let kind = match k.vcpu.run() {
                // Timer kick (or any host signal).
                Err(e) if e.errno() == libc::EINTR => Kind::Intr,
                Err(e) => panic!("KVM_RUN failed: {e}"),
                Ok(VcpuExit::IoOut(SHIM_PORT, _)) => Kind::Shim,
                Ok(VcpuExit::IoOut(port, _)) | Ok(VcpuExit::IoIn(port, _)) => {
                    // Unreachable while the IOPB is all-deny (guest I/O #GPs
                    // into the monitor instead); becomes the M4 fast path.
                    panic!("unexpected direct KVM_EXIT_IO on port {port:#x}");
                }
                Ok(VcpuExit::Debug(_)) => Kind::Debug,
                // A guest-physical access outside the memory slot: a page
                // table pointing at a nonexistent frame (TCG's MEM_UNMAPPED
                // analogue).
                Ok(VcpuExit::MmioRead(..)) | Ok(VcpuExit::MmioWrite(..)) => Kind::BadPhys,
                // Triple fault et al.
                Ok(VcpuExit::Shutdown) => Kind::Shutdown,
                Ok(VcpuExit::FailEntry(reason, cpu)) => {
                    let sregs = k.vcpu.get_sregs();
                    panic!(
                        "KVM_EXIT_FAIL_ENTRY (reason={reason:#x}, cpu={cpu}) mode={mode:?} \
                         cs={:#x}:{:#x} sregs={sregs:#x?}",
                        regs.code_seg(),
                        regs.frame.rip
                    );
                }
                Ok(other) => panic!("unhandled KVM exit: {other:?}"),
            };
            match kind {
                Kind::Intr | Kind::Debug if in_shim(k) => continue,
                Kind::Intr => {
                    sync_out(k, regs, mode);
                    break Some(KernelEvent::Irq);
                }
                // The single stepped instruction retired; loop so
                // step_virtual_if re-checks the next one.
                Kind::Debug => {
                    sync_out(k, regs, mode);
                    break None;
                }
                Kind::Shim => {
                    let kregs = k.vcpu.get_regs().expect("KVM_GET_REGS");
                    let f = read_frame(kregs.rsp);
                    sync_out_shim(k, regs, mode, &f);
                    break dispatch_shim(k, regs, mode, &f);
                }
                Kind::BadPhys | Kind::Shutdown => {
                    sync_out(k, regs, mode);
                    break Some(KernelEvent::Fault);
                }
            }
        };

        if trace_on() {
            eprintln!(
                "   -> cs={:#06x}:{:#010x} ss={:#06x}:{:#010x} ev={ev:?}",
                regs.code_seg(), regs.frame.rip, regs.frame.ss as u16, regs.frame.rsp
            );
        }
        match ev {
            Some(e) => return e,
            None => continue,
        }
    })
}

/// Route a shim-vectored trap: resolve engine-internal ones (demand paging,
/// COW, sensitive-#GP, VM86 IVT reflection) and bubble the rest as typed
/// events — the same dispatch ladder as `cpu.rs` lines 442-546.
fn dispatch_shim(
    _k: &mut KvmCpu,
    regs: &mut Regs,
    mode: UserMode,
    f: &ShimFrame,
) -> Option<KernelEvent> {
    let p = &raw mut vcpu::REGS;
    let n = f.vector;

    // #PF: the paging backend's own business. Absent VA → demand-commit;
    // present VA → a write to a read-only page (COW to privatise, else
    // genuine). Only an unresolvable fault bubbles (SEGV).
    if n == 14 {
        let cr2 = {
            let sregs = _k.vcpu.get_sregs().expect("KVM_GET_SREGS");
            sregs.cr2 as u32
        };
        let resolved = if crate::paging::space_translate(cr2).is_none() {
            crate::paging::space_demand(cr2)
        } else {
            crate::paging::space_cow_fault(cr2)
        };
        if resolved {
            return None; // re-enter at the faulting IP (SET_SREGS reflushes the TLB)
        }
        regs.err_code = f.err_code as u64;
        return Some(KernelEvent::PageFault { addr: cr2 });
    }

    // #GP: the shared monitor — the same decoder arch-metal runs on its real
    // #GP, on EVERY #GP regardless of error code (like metal, unlike TCG,
    // whose intr hook reports software INTs out-of-band): a PM `INT n` at a
    // DPL-0 gate faults with err = n<<3|2 and must still decode to
    // `SoftInt(n)` — DOS/4GW's `INT 21h` startup is the reproducer. `Resume`
    // re-enters the client; `Event` bubbles; `Fault` (a non-sensitive opcode,
    // e.g. a selector-load fault) is a genuine #GP, typed Exception(13) below
    // with the error code preserved.
    if n == 13 {
        let mut view = InterpView { space: unsafe { &mut (*p).space } };
        match arch_abi::monitor::monitor(regs, &mut view) {
            MonitorResult::Resume => return None,
            MonitorResult::Event(KernelEvent::Fault) => {} // genuine #GP
            MonitorResult::Event(ev) => return Some(ev),
        }
    }

    if mode == UserMode::VM86 {
        // Genuine VM86 CPU exception the redirection bitmap does not trap
        // (e.g. #DE, #UD): reflect to the guest's real-mode IVT and keep
        // running — host-side, replacing TCG's in-hook `reflect_vm86_inline`.
        // #GP (13) must bubble, never reflect (see the TCG intr hook: at
        // IOPL=1 the monitor owns it; IVT[0Dh] is a guest disk/UMB handler).
        if n != 3 && n != 4 && n != 13 && !crate::desc::int_intercepted(n) {
            let mut view = InterpView { space: unsafe { &mut (*p).space } };
            arch_abi::monitor::sw_reflect_vm86_int(regs, &mut view, n);
            return None;
        }
        // Residual VM86 traps: trapped vectors and the DPL=3 gates.
        return Some(KernelEvent::SoftInt(n));
    }

    // Protected mode. The DPL=3 gates (3, 4, 0x30..=0xFF) are only reachable
    // by a software `INT n` — a CPU fault never carries those vectors and IRQs
    // are never injected — so the vector alone says SoftInt. (`INT n` at a
    // DPL=0 gate raised #GP(n<<3|2) instead, typed Exception(13) below, same
    // as metal.)
    if n == 3 || n == 4 || n >= 0x30 {
        return Some(KernelEvent::SoftInt(n));
    }
    regs.err_code = f.err_code as u64;
    Some(KernelEvent::Exception(n))
}
