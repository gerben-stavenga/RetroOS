//! KVM handoff for the shared x86 entry assembly.
//! `entry.asm` saves the same frame as metal, calls a tiny OUT handler, and
//! exposes its saved frame to the host for canonicalization. Guest resume
//! restores a canonical frame through the same assembly IRET path as metal.

use crate::sysdesc::{
    if_to_vif, sys_ptr, vif_to_if, ensure_tables, GDT_ADDR, GDT_BYTES, IDT64_ADDR, IDT_ADDR,
    IOPL_MASK, KERNEL_CS64, LDT_ADDR, LDT_SEL, NT_FLAG, TF_FLAG, TSS64_ADDR, TSS64_SEL, TSS_ADDR,
    TSS_SEL, VM_FLAG, KERNEL_CS, KERNEL_DS, RING0_SP_TOP, STUB_ADDR,
};
use super::setup::KvmCpu;
use arch_abi::{Regs, UserMode, FORCED_TF_SHADOW, USER_TF_SHADOW};
use kvm_bindings::{kvm_regs, kvm_segment};

/// The magic port the stubs exit through (`KVM_EXIT_IO`).
pub(crate) const SHIM_PORT: u16 = 0xF4;

const ENTRY: &[u8] = include_bytes!(env!("KVM_ENTRY_IMAGE"));

/// cdecl handler arguments: return address, StackFrame pointer, from_64.
pub(crate) fn frame_address(rsp: u64) -> u64 {
    unsafe { sys_ptr(rsp + 4).cast::<u32>().read_unaligned() as u64 }
}

pub(crate) fn read_frame(address: u64, wide: bool) -> arch_abi::Regs {
    // A 32-bit entry stack is only dword-aligned. Copy into host-aligned
    // storage before using the shared Rust frame representation.
    let mut frame = unsafe {
        sys_ptr(address).cast::<arch_abi::entry::StackFrame>().read_unaligned()
    };
    unsafe { *frame.canonicalize(wide) }
}

/// Materialize the return frame on the supervisor stack. This is also the
/// first-entry path: the host installs only the machine mode and ring-0
/// instruction/stack pointers; assembly restores all user state.
pub(crate) fn prepare_return(regs: arch_abi::Regs, wide: bool) -> (u64, u64) {
    use arch_abi::entry::StackFrame;
    let mut frame: StackFrame = unsafe { core::mem::zeroed() };
    frame.regs = regs;
    unsafe { frame.decanonicalize(wide); }
    let sp = RING0_SP_TOP - core::mem::size_of::<StackFrame>() as u64;
    unsafe { sys_ptr(sp).cast::<StackFrame>().write_unaligned(frame); }
    let offset = if wide { 12 } else { 8 };
    let ip = u32::from_le_bytes(ENTRY[offset..offset + 4].try_into().unwrap()) as u64;
    (ip, sp)
}

/// Write one 32-bit interrupt gate (type 0xE): offset split low/high around
/// selector + access byte. IF is cleared on delivery, so the stubs run with
/// interrupts off on their private stack.
fn idt_gate(offset: u32, dpl: u8) -> u64 {
    (offset as u64 & 0xFFFF)
        | ((KERNEL_CS as u64) << 16)
        | (0x8Eu64 | ((dpl as u64) << 5)) << 40
        | ((offset as u64 >> 16) << 48)
}

/// Write one 64-bit interrupt gate (16 bytes, type 0xE): same shape as the
/// legacy gate plus offset[63:32]; IST=0 → CPL3→0 delivery switches to
/// TSS64.rsp0.
fn idt_gate64(offset: u64, dpl: u8) -> [u8; 16] {
    let low = (offset & 0xFFFF)
        | ((KERNEL_CS64 as u64) << 16)
        | (0x8Eu64 | ((dpl as u64) << 5)) << 40
        | (((offset >> 16) & 0xFFFF) << 48);
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&low.to_le_bytes());
    b[8..12].copy_from_slice(&((offset >> 32) as u32).to_le_bytes());
    b
}

/// Build the IDT, the per-vector stubs, and the TSS in the SYS-window frames.
/// Static content — written once at engine setup (the frames are shared by
/// every address space).
pub(crate) fn write_shim() {
    assert!(ENTRY.len() <= 4096, "shared entry image exceeds its supervisor page");
    unsafe { core::ptr::copy_nonoverlapping(ENTRY.as_ptr(), sys_ptr(STUB_ADDR), ENTRY.len()); }
    let vectors = u32::from_le_bytes(ENTRY[..4].try_into().unwrap());
    // The same 8-byte vector table serves both IDTs, exactly as on metal.
    let idt = sys_ptr(IDT_ADDR);
    for n in 0..256usize {
        let dpl = if n == 3 || n == 4 || n >= 0x30 { 3 } else { 0 };
        let gate = idt_gate(vectors + (n as u32) * 8, dpl);
        unsafe {
            core::ptr::copy_nonoverlapping(gate.to_le_bytes().as_ptr(), idt.add(n * 8), 8);
        }
    }

    // Long-mode IDT uses the shared table; its dispatch selects the
    // 64-bit register-save path before calling the OUT handler.
    let idt64 = sys_ptr(IDT64_ADDR);
    for n in 0..256usize {
        let dpl = if n == 3 || n == 4 || n >= 0x30 { 3 } else { 0 };
        let gate = idt_gate64(vectors as u64 + (n as u64) * 8, dpl);
        unsafe {
            core::ptr::copy_nonoverlapping(gate.as_ptr(), idt64.add(n * 16), 16);
        }
    }

    // TSS64: rsp0 (u64 at offset 4) + the same all-deny IOPB story as the
    // 32-bit TSS below. Long-mode CPL3→0 delivery takes the stack from here.
    let tss64 = sys_ptr(TSS64_ADDR);
    unsafe {
        core::ptr::write_bytes(tss64, 0, 0x1000);
        core::ptr::copy_nonoverlapping(
            RING0_SP_TOP.to_le_bytes().as_ptr(),
            tss64.add(0x04),
            8,
        );
        core::ptr::copy_nonoverlapping(0x88u16.to_le_bytes().as_ptr(), tss64.add(0x66), 2);
        core::ptr::write_bytes(tss64.add(0x88), 0xFF, 0x1000 - 0x88);
    }

    // TSS: only ss0/esp0 (the CPL3→CPL0 stack switch) and the IOPB matter.
    // iopb_offset = 0x88; bitmap all-1s = every port denied → IN/OUT at
    // CPL3/IOPL1 #GPs into the shared monitor, identical to the TCG engine and
    // the metal default. The per-entry policy clears permitted bits.
    let tss = sys_ptr(TSS_ADDR);
    unsafe {
        core::ptr::write_bytes(tss, 0, 0x1000);
        let w32 = |off: usize, v: u32| {
            core::ptr::copy_nonoverlapping(v.to_le_bytes().as_ptr(), tss.add(off), 4)
        };
        w32(0x04, RING0_SP_TOP as u32); // esp0
        w32(0x08, KERNEL_DS as u32); // ss0
        // iopb_offset (u16 at 0x66); redirection bitmap unused (CR4.VME=0).
        core::ptr::copy_nonoverlapping(0x88u16.to_le_bytes().as_ptr(), tss.add(0x66), 2);
        // All-deny IOPB filling the REST OF THE PAGE, not just the policy
        // window: a zero byte inside the TSS limit reads as "allowed", so any
        // unwritten byte between the bitmap and the limit would silently open
        // the ports it covers (0x3E8.. would have been allowed by the zeroed
        // page tail).
        core::ptr::write_bytes(tss.add(0x88), 0xFF, 0x1000 - 0x88);
    }
}

/// The IOPB policy window: ports 0..0x3E0, matching metal
/// (`arch-metal/src/descriptors.rs` — every port the kernel's io_policy ever
/// grants lives below 0x3E0). Everything above stays permanently denied.
#[cfg(test)]
const IOPB_PORTS: u16 = 0x3E0;

/// One-time shim init shared by setup and IOPB policy installation.
/// can be called by the kernel's per-swap-in policy BEFORE the first
/// `execute()` builds the vcpu, and `write_shim`'s all-deny fill must not
/// clobber grants made through that path.
pub(super) fn ensure_shim() {
    static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        crate::sysdesc::ensure_sys_window();
        write_shim();
    });
}

/// Clear a port range's deny bits (kernel policy grant). SHIM_PORT stays
/// denied unconditionally — a CPL3 `out 0xF4` must #GP into the real shim,
/// never fabricate a shim exit.
#[cfg(test)]
pub(super) fn iopb_allow(port: u16, count: usize) {
    ensure_shim();
    let end = port.saturating_add(count as u16).min(IOPB_PORTS);
    for p in port..end {
        if p == SHIM_PORT {
            continue;
        }
        // Both TSS images (legacy + TSS64) carry the policy: a thread's mode
        // is not known at grant time and 32/64-bit slices interleave.
        for tss in [TSS_ADDR, TSS64_ADDR] {
            unsafe {
                let byte = sys_ptr(tss + 0x88 + (p / 8) as u64);
                *byte &= !(1 << (p % 8));
            }
        }
    }
}

/// Back to all-deny (per swap-in, like metal's io_policy baseline).
#[cfg(test)]
pub(super) fn iopb_reset() {
    ensure_shim();
    for tss in [TSS_ADDR, TSS64_ADDR] {
        unsafe {
            core::ptr::write_bytes(sys_ptr(tss + 0x88), 0xFF, (IOPB_PORTS / 8) as usize);
        }
    }
}

pub(super) fn iopb_install(policy: &arch_abi::IoPolicy) {
    ensure_shim();
    for tss in [TSS_ADDR, TSS64_ADDR] {
        unsafe {
            core::ptr::copy_nonoverlapping(
                policy.denied_bytes().as_ptr(),
                sys_ptr(tss + 0x88),
                arch_abi::IO_POLICY_BYTES,
            );
        }
    }
}

/// A null/unusable segment cache.
fn null_seg() -> kvm_segment {
    kvm_segment { unusable: 1, ..Default::default() }
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

/// Set the machine mode and enter the shared return path with a saved frame. Host-side page-table edits require an explicit CR3
/// change: setting identical SREGS does not flush cached guest translations.
pub(super) fn enter(k: &mut KvmCpu, r: &Regs, mode: UserMode) {
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

    let mut frame = *r;
    frame.frame.rflags = vif_to_if(
        r.flags32() & !(IOPL_MASK as u32) & !NT_FLAG & !TF_FLAG,
    ) as u64 | 2;
    if arch_abi::monitor::stepping(r) {
        frame.frame.rflags |= TF_FLAG as u64;
    }
    match mode {
        UserMode::VM86 => {
            frame.frame.rip &= 0xffff;
            frame.frame.rsp &= 0xffff;
            frame.frame.rflags |= VM_FLAG | (1 << 12) | (r.frame.rflags & NT_FLAG as u64);
        }
        UserMode::Mode32 => {
            frame.frame.rflags = (frame.frame.rflags & !VM_FLAG) | (1 << 12);
        }
        UserMode::Mode64 => {
            // Configure the machine for long mode; entry.asm restores user
            // registers, FS/GS bases, and privilege through IRETQ.
            sregs.cr3 = crate::paging::frame_phys(crate::paging::active_pml4()) as u64;
            sregs.cr4 |= 1 << 5;
            sregs.efer = (1 << 8) | (1 << 10);
            sregs.idt.base = IDT64_ADDR;
            sregs.idt.limit = 0xFFF;
            sregs.tr = kvm_segment {
                base: TSS64_ADDR, limit: 0xFFF, selector: TSS64_SEL,
                type_: 11, present: 1, s: 0, ..Default::default()
            };
            sregs.ldt = kvm_segment { unusable: 1, ..Default::default() };
            frame.frame.rflags &= !VM_FLAG;
        }
    }
    let wide = mode == UserMode::Mode64;
    let (ip, sp) = prepare_return(frame, wide);
    sregs.cs = decode_sel(if wide { KERNEL_CS64 } else { crate::sysdesc::KERNEL_CS });
    sregs.ss = decode_sel(crate::sysdesc::KERNEL_DS);
    sregs.ds = sregs.ss;
    sregs.es = sregs.ss;
    sregs.fs = sregs.ss;
    sregs.gs = sregs.ss;
    let regs = kvm_regs { rip: ip, rsp: sp, rflags: 2, ..Default::default() };

    if super::take_tlb_dirty() {
        // Toggle PWT, retaining the same valid root address in both legacy
        // and long mode. No guest instructions run with this temporary state.
        // Restoring CR3 below forces a change even if the previous guest CR3
        // happened to match the temporary value. PCID and PGE are disabled.
        let mut flush_sregs = sregs;
        flush_sregs.cr3 ^= 1 << 3;
        k.vcpu.set_sregs(&flush_sregs).expect("KVM_SET_SREGS flush");
    }
    k.vcpu.set_sregs(&sregs).expect("KVM_SET_SREGS");
    k.vcpu.set_regs(&regs).expect("KVM_SET_REGS");
}

/// Read guest state back into `Regs` after an exit that did NOT go through the
/// shim (timer EINTR, single-step debug exit): the interrupted user state is
/// live in the vcpu registers.
pub(super) fn sync_out(k: &KvmCpu, r: &mut Regs, mode: UserMode) {
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

/// Entry assembly has saved every register in the shared canonical frame.
pub(super) fn sync_out_shim(r: &mut Regs, mode: UserMode, frame: &Regs) {
    let saved_flags = r.frame.rflags;
    *r = *frame;
    r.frame.rflags = saved_flags;
    if mode == UserMode::Mode64 {
        let shadows = saved_flags & (USER_TF_SHADOW | FORCED_TF_SHADOW);
        r.frame.rflags = ((if_to_vif(frame.flags32()) as u64) & !IOPL_MASK & !(TF_FLAG as u64)) | shadows;
    } else {
        store_segs_flags(r, mode, frame.flags32(), [frame.code_seg() as u32,
            frame.stack_seg() as u32, frame.ds as u32, frame.es as u32,
            frame.fs as u32, frame.gs as u32]);
    }
}

/// The exit-side EFLAGS/segment normalization — identical to the TCG engine's
/// `store_regs`: IF mirrored into VIF (real IF forced 1), IOPL normalized to 1,
/// TF stripped, VM re-asserted for VM86; SP/IP masked to 16 bits when SS/CS is
/// a 16-bit segment.
fn store_segs_flags(r: &mut Regs, mode: UserMode, eflags: u32, segs: [u32; 6]) {
    let tf_shadows = r.frame.rflags & (USER_TF_SHADOW | FORCED_TF_SHADOW);
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
            let viopl = r.frame.rflags & IOPL_MASK;
            r.frame.rflags = (fl & !IOPL_MASK) | VM_FLAG | viopl | tf_shadows;
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
            // Forced TF belongs to the monitor; preserve its projected value
            // across guest instructions that may themselves write flags.
            let viopl = r.frame.rflags & IOPL_MASK;
            let tf = if r.forced_tf() {
                r.frame.rflags & TF_FLAG as u64
            } else {
                fl & TF_FLAG as u64
            };
            r.frame.rflags = (fl & !IOPL_MASK & !(TF_FLAG as u64)) | viopl | tf | tf_shadows;
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
                ((if_to_vif(eflags) as u64) & !IOPL_MASK & !(TF_FLAG as u64)) | tf_shadows;
        }
    }
}
