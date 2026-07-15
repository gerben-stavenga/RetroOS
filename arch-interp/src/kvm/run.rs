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
use super::shim::{read_frame, read_frame64, ShimFrame, ShimFrame64, SHIM_PORT};
use crate::sysdesc::{
    if_to_vif, sys_ptr, vif_to_if, ensure_tables, GDT_ADDR, GDT_BYTES, IDT64_ADDR, IDT_ADDR,
    IOPL_MASK, KERNEL_CS64, LDT_ADDR, LDT_SEL, NT_FLAG, TF_FLAG, TSS64_ADDR, TSS64_SEL, TSS_ADDR,
    TSS_SEL, VIF_FLAG, VM_FLAG,
};
use arch_abi::monitor::MonitorResult;
use arch_abi::GuestBytes;
use arch_abi::{KernelEvent, Regs, UserMode};
use kvm_bindings::{
    kvm_guest_debug, kvm_guest_debug_arch, kvm_regs, kvm_segment, KVM_GUESTDBG_ENABLE,
    KVM_GUESTDBG_SINGLESTEP, KVM_GUESTDBG_USE_HW_BP,
};
use kvm_ioctls::VcpuExit;
use std::cell::Cell;

/// The virtual-IF exit-breakpoint set the monitor wants armed (`MAX_EXEC_BP`
/// addresses), recorded here and programmed into DR0-3 at the next guest entry.
///
/// Recorded rather than programmed on the spot because
/// `Arch::set_exec_breakpoints` is called from *inside* the monitor, which runs
/// inside `with()`'s borrow of the vcpu — re-entering it would double-borrow.
/// (The TCG engine records for the same reason; see `cpu.rs::sync_exec_bps`.)
type BpSet = ([u32; arch_abi::MAX_EXEC_BP], usize);
thread_local! {
    static WANT_BPS: Cell<BpSet> = const { Cell::new(([0; arch_abi::MAX_EXEC_BP], 0)) };
}

/// Record the exit-breakpoint set (`Arch::set_exec_breakpoints`). Always
/// succeeds: DR0-3 are real here (`KVM_GUESTDBG_USE_HW_BP`), so a `Repair`
/// client runs its critical sections free, exactly as on metal.
pub fn set_exec_breakpoints(addrs: &[u32]) -> bool {
    let mut set: BpSet = ([0; arch_abi::MAX_EXEC_BP], addrs.len().min(arch_abi::MAX_EXEC_BP));
    set.0[..set.1].copy_from_slice(&addrs[..set.1]);
    WANT_BPS.with(|w| w.set(set));
    true
}

/// Per-slice transition trace, gated by `RETRO_TRACE` (checked once). Same
/// lens as the TCG engine's.
fn trace_on() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("RETRO_TRACE").is_some())
}

/// Virtual-IF stepping trace (`RETRO_STEP_TRACE`): one line per stepped
/// instruction — the lens that caught the stale single-step anchor (see
/// `set_single_step`).
fn step_trace_on() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("RETRO_STEP_TRACE").is_some())
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
    let ldt_limit = ensure_tables();

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
        r8: r.r8,
        r9: r.r9,
        r10: r.r10,
        r11: r.r11,
        r12: r.r12,
        r13: r.r13,
        r14: r.r14,
        r15: r.r15,
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
            // Real long mode: CR3 = the 4-level twin of the active space
            // (rebuilt lazily on page-table change), PAE + EFER.LME|LMA, flat
            // 64-bit CPL3 CS with flat data SS/DS/ES. FS/GS carry the 64-bit
            // BASES from `Regs.fs/gs` — the metal convention (entry.asm
            // rdmsr/wrmsr's them; arch_prctl stores there). Traps vector
            // through the long-mode IDT onto the shared stubs at TSS64.rsp0.
            // EFER.SCE stays 0: `syscall` #UDs and `dispatch_shim64` decodes
            // it into KernelEvent::Syscall — no LSTAR/STAR machinery.
            use arch_abi::{USER_CS64, USER_DS};
            sregs.cr3 = crate::paging::frame_phys(crate::paging::active_pml4()) as u64;
            sregs.cr4 |= 1 << 5; // PAE
            sregs.efer = (1 << 8) | (1 << 10); // LME | LMA
            sregs.idt.base = IDT64_ADDR;
            sregs.idt.limit = 0xFFF;
            sregs.tr = kvm_segment {
                base: TSS64_ADDR,
                limit: 0xFFF,
                selector: TSS64_SEL,
                type_: 11, // busy 64-bit TSS (VM entry requires busy)
                present: 1,
                s: 0,
                ..Default::default()
            };
            sregs.ldt = kvm_segment { unusable: 1, ..Default::default() };
            sregs.cs = decode_sel(USER_CS64); // L=1 descriptor from the GDT image
            sregs.ss = decode_sel(USER_DS);
            sregs.ds = decode_sel(USER_DS);
            sregs.es = decode_sel(USER_DS);
            let mut fs = decode_sel(USER_DS);
            fs.base = r.fs;
            let mut gs = decode_sel(USER_DS);
            gs.base = r.gs;
            sregs.fs = fs;
            sregs.gs = gs;
            regs.rflags = (vif_to_if(
                r.flags32() & !(VM_FLAG as u32) & !(IOPL_MASK as u32) & !NT_FLAG & !TF_FLAG,
            ) | 2) as u64;
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
    copy_gprs(r, &regs);
    r.frame.rsp = regs.rsp;
    r.frame.rip = regs.rip;
    if mode == UserMode::Mode64 {
        // FS/GS hold the 64-bit bases in Mode64 (metal's convention).
        r.fs = sregs.fs.base;
        r.gs = sregs.gs.base;
    }
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

/// The GPR copy shared by every sync-out flavor (r8-r15 exist in all modes —
/// 32-bit guests simply can't touch them, so the values round-trip).
fn copy_gprs(r: &mut Regs, regs: &kvm_regs) {
    r.rax = regs.rax;
    r.rbx = regs.rbx;
    r.rcx = regs.rcx;
    r.rdx = regs.rdx;
    r.rsi = regs.rsi;
    r.rdi = regs.rdi;
    r.rbp = regs.rbp;
    r.r8 = regs.r8;
    r.r9 = regs.r9;
    r.r10 = regs.r10;
    r.r11 = regs.r11;
    r.r12 = regs.r12;
    r.r13 = regs.r13;
    r.r14 = regs.r14;
    r.r15 = regs.r15;
}

/// Read guest state back into `Regs` after a 64-bit shim exit: GPRs live in
/// the vcpu, the interrupted frame off TSS64.rsp0. CS/SS selectors in `Regs`
/// stay untouched — `frame.cs == USER_CS64` is the kernel's Mode64
/// fingerprint and 64-bit gates don't reload data segments.
fn sync_out_shim64(k: &KvmCpu, r: &mut Regs, f: &ShimFrame64) {
    let regs = k.vcpu.get_regs().expect("KVM_GET_REGS");
    let sregs = k.vcpu.get_sregs().expect("KVM_GET_SREGS");
    copy_gprs(r, &regs);
    r.frame.rsp = f.rsp;
    r.frame.rip = f.rip;
    r.fs = sregs.fs.base;
    r.gs = sregs.gs.base;
    r.frame.rflags =
        (if_to_vif(f.rflags as u32) as u64) & !IOPL_MASK & !(TF_FLAG as u64);
}

/// Read guest state back into `Regs` after a shim exit: GPRs are live in the
/// vcpu (the stubs clobber nothing — `out imm8, al` only reads AL), the
/// interrupted frame comes off the ring-0 stack.
fn sync_out_shim(k: &KvmCpu, r: &mut Regs, mode: UserMode, f: &ShimFrame) {
    let regs = k.vcpu.get_regs().expect("KVM_GET_REGS");
    copy_gprs(r, &regs);
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
            // Preserve the *virtual* IOPL exactly like the Mode32 arm below:
            // hardcoding 1 here erased the iopl3 launch policy on the first
            // VM86 slice exit — DOS4GW clients start in VM86, so by the time
            // they switched to PM the stepping gate always read vIOPL=1 and
            // KVM silently dropped their POPF/IRET IF-restores (DOOM hung at
            // I_StartupTimer with VIF=0). The guest-visible IOPL in `eflags`
            // is a VME artifact, never trusted (see set_vm86_flags).
            let viopl = r.frame.rflags & IOPL_MASK as u64;
            r.frame.rflags = (fl & !IOPL_MASK) | VM_FLAG | viopl;
        }
        UserMode::Mode32 => {
            r.set_cs32(cs);
            r.set_ss32(ss);
            r.ds = ds as u64;
            r.es = es as u64;
            r.fs = fs as u64;
            r.gs = gs as u64;
            let fl = if_to_vif(eflags) as u64;
            // Preserve the guest's *virtual* IOPL (bits 12-13): the vcpu runs at
            // real IOPL=1 (enter forces it, so CLI/STI trap), but the vIOPL rides
            // in the saved flags — it is the thread's `IfMode` — exactly as metal
            // stashes it. Forcing it to 1 here would erase the policy and make
            // every client an `Iopl1` one.
            //
            // TF likewise comes from the saved flags, not from the guest: KVM
            // strips TF out of RFLAGS while GUESTDBG_SINGLESTEP is on
            // (`kvm_get_rflags`), so the CPU cannot tell us whether a step is
            // still pending. The monitor owns that bit; carry it across the run.
            let viopl = r.frame.rflags & IOPL_MASK as u64;
            let tf = r.frame.rflags & TF_FLAG as u64;
            r.frame.rflags = (fl & !IOPL_MASK & !(TF_FLAG as u64)) | viopl | tf;
            if !crate::desc::seg_is_32(ss as u16) {
                r.frame.rsp &= 0xFFFF;
            }
            if !crate::desc::seg_is_32(cs as u16) {
                r.frame.rip &= 0xFFFF;
            }
        }
        UserMode::Mode64 => {
            // Mirror IF into VIF like the other arms (enter projects it back);
            // CS/SS selectors stay as the kernel set them (USER_CS64 is the
            // Mode64 fingerprint `Regs::mode()` keys on).
            r.frame.rflags =
                (if_to_vif(eflags) as u64) & !IOPL_MASK & !(TF_FLAG as u64);
        }
    }
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
        let b = crate::backend::Interp.read::<u8>(base.wrapping_add(vcpu.ip32()).wrapping_add(len) as usize);
        match b {
            // Legacy prefixes (operand/address size, rep, lock, seg overrides).
            0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 => len += 1,
            0xE4 | 0xE5 | 0xE6 | 0xE7 => return len + 2, // in/out acc, imm8
            0xEC | 0xED | 0xEE | 0xEF => return len + 1, // in/out acc, dx
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

/// Whether the vcpu is currently executing the trap shim (CPL0). Only the
/// shim ever runs with the flat ring-0 CS.
fn in_shim(k: &KvmCpu) -> bool {
    let sregs = k.vcpu.get_sregs().expect("KVM_GET_SREGS");
    sregs.cs.selector == crate::sysdesc::KERNEL_CS || sregs.cs.selector == KERNEL_CS64
}

/// Program the guest-debug state for this entry: hardware single-step (the
/// virtual-IF stepping driver) plus DR0-3 (the learned virtual-IF exit
/// breakpoints). One ioctl carries both — they are the same register file.
///
/// MUST be called AFTER the entry `KVM_SET_REGS`, and re-issued on every
/// stepped entry even if already armed: KVM anchors the single-step TF to the
/// RIP current at KVM_SET_GUEST_DEBUG time (`vcpu->arch.singlestep_rip`) and
/// only folds TF into RFLAGS while the vcpu still sits at that RIP. Arming
/// before SET_REGS (or reusing a stale arm after the monitor emulated an
/// instruction and moved IP host-side) leaves TF unset — the guest FREE-RUNS
/// through the VIF=0 stretch, hardware silently drops the POPF/IRET IF
/// restore, and the client hangs with its virtual IF stuck off (Raptor's
/// tick-wait loop was the reproducer).
fn apply_guest_debug(k: &mut KvmCpu, step: bool) {
    let want = WANT_BPS.with(|w| w.get());
    // Stepping must re-anchor on every entry (above). Otherwise only a change
    // needs an ioctl — including the last one that turned stepping off. A
    // client running free with its interrupts on takes no ioctl at all.
    if !step && !k.single_step && want == k.armed {
        return;
    }
    // USE_HW_BP stays set even with nothing armed, and an empty set is disarmed
    // by writing DR7=0 — never by dropping guest debug. Two reasons, and the
    // second one bites:
    //  * KVM only *intercepts* #DB while guest_debug has SINGLESTEP or
    //    USE_HW_BP. Without it a #DB is injected into the guest instead — the
    //    DPMI client's own vector 1 — which is not ours to hand it.
    //  * Handing the DR file back does not reliably clear the breakpoints that
    //    were in it. Disabling on an empty set (`arm()` legitimately asks for
    //    one: a window whose every exit is an STI needs no breakpoint at all)
    //    left DOOM's learned POPF address armed in hardware but no longer
    //    intercepted, so the next pass through it raised a #DB straight into
    //    DOS/4GW: "exception 01h (debug exception) at 1DF:0065FE4E".
    let mut control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP;
    if step {
        control |= KVM_GUESTDBG_SINGLESTEP;
    }
    // DR7: Ln (local enable) per armed slot; RW=00 / LEN=00 is an execute
    // breakpoint, so the high half stays zero. Bit 10 reads as one on real
    // hardware. Nothing armed ⇒ DR7 = 0 ⇒ no breakpoint can fire.
    let mut arch = kvm_guest_debug_arch { debugreg: [0; 8] };
    let mut dr7: u64 = if want.1 > 0 { 1 << 10 } else { 0 };
    for (i, &addr) in want.0[..want.1].iter().enumerate() {
        arch.debugreg[i] = addr as u64;
        dr7 |= 1 << (2 * i);
    }
    arch.debugreg[7] = dr7;
    let dbg = kvm_guest_debug { control, pad: 0, arch };
    k.vcpu.set_guest_debug(&dbg).expect("KVM_SET_GUEST_DEBUG");
    k.single_step = step;
    k.armed = want;
}

/// Run the current Vcpu (`REGS`) until the next kernel-visible event.
pub fn execute() -> KernelEvent {
    with(|k| loop {
        // Off-thread VGA snapshot / live terminal paint (CPU thread only).
        crate::screendump::maybe_dump();
        crate::screendump::maybe_render_live();

        // One `&mut Vcpu` for the iteration — the sole unsafe is dereferencing
        // the `static mut REGS`; the monitor, memory reads and enter/sync_out
        // helpers all reborrow it (register access via Deref, memory via GuestBytes).
        let vcpu = unsafe { &mut *(&raw mut crate::vcpu::REGS) };
        let mode = vcpu.mode();

        // Virtual-IF stepping: the monitor owns TF — it sets it when it wants
        // hardware to retire exactly one instruction, and only ever leaves it
        // set on a NON-sensitive one. Re-peek here because the kernel may have
        // moved IP since (an injected ISR frame): emulate any leading
        // IF-touching opcode in software, so hardware — whose POPF/IRET
        // silently drops IF at CPL>IOPL — never sees one.
        //
        // Which windows step at all is the client's `IfMode`, decided in the
        // shared gate, not here: `Iopl1` never steps (DPMI 0.9 §2.13 — a
        // conforming client re-enables via CLI/STI/AX=0900-0902, which fault on
        // their own), `Repair` steps only until it has learned the window's
        // exits and then runs free on DR0-3, `Iopl3` steps every window.
        if mode == UserMode::Mode32 && arch_abi::monitor::stepping(&vcpu.regs) {
            let (scs, sip) = (vcpu.code_seg(), vcpu.ip32());
            let r = arch_abi::monitor::db_gate(&mut crate::backend::Interp, &mut vcpu.regs, false);
            if step_trace_on() {
                let op = crate::backend::Interp.read::<u8>(crate::desc::seg_base(scs).wrapping_add(sip) as usize);
                eprintln!(
                    "[step] {scs:#06x}:{sip:#010x} op={op:02X} -> ip={:#010x} vif={} r={}",
                    vcpu.ip32(),
                    (vcpu.flags32() & VIF_FLAG != 0) as u8,
                    match &r { MonitorResult::Resume => "resume", MonitorResult::Event(_) => "event" }
                );
            }
            if let MonitorResult::Event(ev) = r {
                return ev;
            }
        }
        // TF is not handed to the CPU (KVM strips it from guest RFLAGS under
        // GUESTDBG_SINGLESTEP); it is the flag that says "step this entry".
        let stepping = arch_abi::monitor::stepping(&vcpu.regs);

        // The INTR-line check (the TCG block hook's analogue): hand the slice
        // to the kernel when an IRQ is deliverable.
        if crate::machine::irq_line() && vcpu.flags32() & VIF_FLAG != 0 {
            return KernelEvent::Irq;
        }

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
        // After SET_REGS, never before — see apply_guest_debug.
        apply_guest_debug(k, stepping);

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
            /// A #DB. `bp` = DR6 B0..B3: one of the armed virtual-IF exit
            /// breakpoints, as opposed to the single-step trap (BS).
            Debug { bp: bool },
            BadPhys,
            Shutdown,
        }
        let ev = loop {
            let kind = match k.vcpu.run() {
                // Timer kick (or any host signal).
                Err(e) if e.errno() == libc::EINTR => Kind::Intr,
                Err(e) => panic!("KVM_RUN failed: {e}"),
                Ok(VcpuExit::IoOut(SHIM_PORT, _)) => Kind::Shim,
                // An IOPB-allowed port: hardware ran the access with no #GP —
                // the fast path past the shim + monitor.
                Ok(VcpuExit::IoOut(port, data)) => Kind::Io { port, is_in: false, bytes: data.len() },
                Ok(VcpuExit::IoIn(port, data)) => Kind::Io { port, is_in: true, bytes: data.len() },
                Ok(VcpuExit::Debug(d)) => Kind::Debug { bp: d.dr6 & 0xF != 0 },
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
                        vcpu.code_seg(),
                        vcpu.frame.rip
                    );
                }
                Ok(other) => panic!("unhandled KVM exit: {other:?}"),
            };
            match kind {
                Kind::Intr | Kind::Debug { .. } if in_shim(k) => continue,
                Kind::Intr => {
                    sync_out(k, vcpu, mode);
                    break Some(KernelEvent::Irq);
                }
                // An armed exit breakpoint: an execute breakpoint is a FAULT, so
                // the instruction under it has NOT run. The gate emulates it,
                // which closes the window and restores virtual IF with no
                // stepping at all — the whole point of `IfMode::Repair`, and
                // bit-for-bit what metal's DR6 B0..B3 path does.
                Kind::Debug { bp: true } => {
                    sync_out(k, vcpu, mode);
                    match arch_abi::monitor::db_gate(&mut crate::backend::Interp, &mut vcpu.regs, true) {
                        MonitorResult::Event(ev) => break Some(ev),
                        MonitorResult::Resume => break None, // re-enter at the (emulated) IP
                    }
                }
                // The single stepped instruction retired: re-check the next
                // one IN PLACE. The vcpu's live state already equals `vcpu`
                // after the sync, so as long as the monitor only peeks (a
                // non-sensitive next opcode), the re-step needs no SET_SREGS,
                // no table rewrite, no SET_REGS — just a re-anchored
                // KVM_SET_GUEST_DEBUG and another KVM_RUN. Without this fast
                // path every stepped instruction pays the full entry cost
                // (including the GDT/LDT copy) and CLI-heavy games crawl.
                Kind::Debug { bp: false } => {
                    sync_out(k, vcpu, mode);
                    if stepping && mode == UserMode::Mode32 && arch_abi::monitor::stepping(&vcpu.regs) {
                        let (scs, sip) = (vcpu.code_seg(), vcpu.ip32());
                        let snap_fl = vcpu.flags32() & !TF_FLAG;
                        let r = arch_abi::monitor::db_gate(&mut crate::backend::Interp, &mut vcpu.regs, false);
                        if step_trace_on() {
                            eprintln!(
                                "[step] {scs:#06x}:{sip:#010x} (fast) -> ip={:#010x} vif={} r={}",
                                vcpu.ip32(),
                                (vcpu.flags32() & VIF_FLAG != 0) as u8,
                                match &r { MonitorResult::Resume => "resume", MonitorResult::Event(_) => "event" }
                            );
                        }
                        match r {
                            MonitorResult::Event(ev) => break Some(ev),
                            MonitorResult::Resume => {
                                if vcpu.ip32() == sip && vcpu.flags32() & !TF_FLAG == snap_fl {
                                    // Next opcode is non-sensitive: step it on
                                    // the live vcpu state.
                                    apply_guest_debug(k, true); // re-anchor at the new RIP
                                    continue;
                                }
                                // The monitor emulated an instruction (IP or
                                // flags moved host-side): full re-entry.
                                break None;
                            }
                        }
                    }
                    break None;
                }
                Kind::Shim => {
                    let kregs = k.vcpu.get_regs().expect("KVM_GET_REGS");
                    if mode == UserMode::Mode64 {
                        let f = read_frame64(kregs.rsp);
                        shim_vec = Some((f.vector, f.err_code));
                        sync_out_shim64(k, vcpu, &f);
                        break dispatch_shim64(k, vcpu, &f);
                    }
                    let f = read_frame(kregs.rsp);
                    shim_vec = Some((f.vector, f.err_code));
                    sync_out_shim(k, vcpu, mode, &f);
                    break dispatch_shim(k, vcpu, mode, &f);
                }
                // A direct exit happens BEFORE the instruction retires (rip
                // advance / IN writeback are deferred to the next KVM_RUN).
                // Complete it ourselves — advance IP past the instruction, so
                // the event surfaces with the monitor's exact contract (IP
                // advanced; OUT value in / IN result expected in EAX). Our
                // rip rewrite makes KVM's own stale completion self-cancel
                // (its linear-rip guard no longer matches), so the kernel's
                // IN answer in EAX survives re-entry.
                Kind::Io { port, is_in, bytes } => {
                    sync_out(k, vcpu, mode);
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
            let op = crate::backend::Interp.read::<u8>(base.wrapping_add(pre_ip) as usize);
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
    })
}

/// Route a 64-bit shim-vectored trap. Leaner than the 32-bit ladder: no VM86,
/// no monitor (it decodes 32-bit code) — just demand-#PF/COW resolution, the
/// `syscall`-as-#UD synthesis, and typed events for the rest.
fn dispatch_shim64(
    k: &mut KvmCpu,
    vcpu: &mut crate::vcpu::Vcpu,
    f: &ShimFrame64,
) -> Option<KernelEvent> {
    let n = f.vector;

    // #PF: resolve against the 2-level source tree (demand-commit / COW); the
    // twin refreshes on re-entry via the generation bump the fix caused.
    if n == 14 {
        let cr2 = k.vcpu.get_sregs().expect("KVM_GET_SREGS").cr2;
        let resolved = cr2 <= u32::MAX as u64 && {
            let a = cr2 as u32;
            if crate::paging::space_translate(a).is_none() {
                crate::paging::space_demand(a)
            } else {
                crate::paging::space_cow_fault(a)
            }
        };
        if resolved {
            return None; // re-enter at the faulting RIP (SET_SREGS reflushes)
        }
        vcpu.err_code = f.err_code as u64;
        // The loader keeps 64-bit user VAs below 4 GiB, so a wider CR2 is
        // already a wild access — the u32 truncation only affects the SEGV
        // diagnostic, not the verdict.
        return Some(KernelEvent::PageFault { addr: cr2 as u32 });
    }

    // `syscall` with EFER.SCE=0 raises #UD: decode 0F 05 at the faulting RIP
    // and synthesize the typed event (the monitor idiom, one opcode wide).
    // rcx/r11 get the architected SYSCALL clobber values for ABI fidelity.
    if n == 6 {
        let rip = vcpu.frame.rip;
        let b0: u8 = crate::backend::Interp.read(rip as usize);
        let b1: u8 = crate::backend::Interp.read(rip as usize + 1);
        if (b0, b1) == (0x0F, 0x05) {
            vcpu.frame.rip = rip.wrapping_add(2);
            vcpu.rcx = vcpu.frame.rip;
            vcpu.r11 = vcpu.frame.rflags;
            return Some(KernelEvent::Syscall);
        }
    }

    // DPL=3 gates (3, 4, 0x30..=0xFF) are only reachable by `INT n` — INT 0x80
    // from 64-bit code lands here as SoftInt(0x80), same as everywhere else.
    if n == 3 || n == 4 || n >= 0x30 {
        return Some(KernelEvent::SoftInt(n));
    }
    vcpu.err_code = f.err_code as u64;
    Some(KernelEvent::Exception(n))
}

/// Route a shim-vectored trap: resolve engine-internal ones (demand paging,
/// COW, sensitive-#GP, VM86 IVT reflection) and bubble the rest as typed
/// events — the same dispatch ladder as `cpu.rs` lines 442-546.
fn dispatch_shim(
    _k: &mut KvmCpu,
    vcpu: &mut crate::vcpu::Vcpu,
    mode: UserMode,
    f: &ShimFrame,
) -> Option<KernelEvent> {
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
        vcpu.err_code = f.err_code as u64;
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
        // Where the faulting instruction lives, and whether virtual IF was on
        // before it ran: a 1 -> 0 transition is the site that OPENS an
        // interrupts-off window, which is what the gate keys its learned exit
        // breakpoints on.
        let entry_ip = vcpu.ip32();
        let vif_was_on = vcpu.flags32() & VIF_FLAG != 0;
        match arch_abi::monitor::monitor(&mut crate::backend::Interp, &mut vcpu.regs) {
            MonitorResult::Resume => {
                // Hand the window to the virtual-IF gate: it either arms this
                // site's learned exits (DR0-3, next entry) and lets the client
                // run at full speed, or falls back to stepping to learn them.
                arch_abi::monitor::gp_gate(&mut crate::backend::Interp, &mut vcpu.regs, entry_ip, vif_was_on);
                return None;
            }
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
            arch_abi::monitor::sw_reflect_vm86_int(&mut vcpu.regs, &mut crate::backend::Interp, n);
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
    vcpu.err_code = f.err_code as u64;
    Some(KernelEvent::Exception(n))
}
