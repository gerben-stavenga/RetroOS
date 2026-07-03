//! The in-guest ring-0 trap shim — the KVM engine's micro `entry.asm`.
//!
//! Under KVM, a fault or `INT n` in the guest vectors through the *guest* IDT;
//! there is no hook to catch it host-side. So the SYS window carries a guest
//! IDT whose 256 gates point at per-vector stubs that capture the trap and
//! immediately hand control to the host:
//!
//! ```text
//! stub_n:  push 0          ; dummy err_code (vectors where the CPU pushes none)
//!          push n          ; the vector
//!          out 0xF4, al    ; SHIM_PORT → KVM_EXIT_IO → host
//!          hlt             ; never reached (belt & braces)
//! ```
//!
//! The stubs never IRET — every guest entry is a fresh `KVM_SET_REGS`/
//! `KVM_SET_SREGS` — so there is no restore path in guest code at all. The
//! CPL3→CPL0 transition switches to the ring-0 stack via TSS.esp0, leaving the
//! interrupted user frame for the host to read back:
//!
//! ```text
//! [esp+0]  vector      (stub-pushed)
//! [esp+4]  err_code    (CPU-pushed, or the stub's dummy 0)
//! [esp+8]  EIP  CS  EFLAGS  ESP  SS          ← CPU-pushed user frame
//! [esp+28] ES  DS  FS  GS                    ← VM86 entries only
//! ```
//!
//! This is arch-metal's `Raw32` + `Vm86Segs` stack convention
//! (`arch-metal/src/traps.rs`) read from guest RAM instead of the kernel stack.
//! The gate DPL policy also mirrors metal (`descriptors.rs`): 3, 4 and
//! 0x30..=0xFF are DPL=3 (user `INT n` reaches the gate → `SoftInt`); every
//! other vector is DPL=0, so a user `INT n` at it raises #GP(vector<<3|2)
//! exactly like real hardware under the metal kernel.
//!
//! A CPL3 guest cannot forge a shim exit: SHIM_PORT is never IOPB-allowed, so
//! a user `out 0xF4` #GPs into the real shim first.

use crate::sysdesc::{
    sys_ptr, IDT_ADDR, KERNEL_CS, KERNEL_DS, RING0_SP_TOP, STUB_ADDR, TSS_ADDR,
};

/// The magic port the stubs exit through (`KVM_EXIT_IO`).
pub(crate) const SHIM_PORT: u16 = 0xF4;

/// Vectors where the CPU pushes an error code (the stub must not push a dummy).
fn has_err_code(vector: usize) -> bool {
    matches!(vector, 8 | 10 | 11 | 12 | 13 | 14 | 17 | 21)
}

/// The user-frame image the host reads off the ring-0 stack after a shim exit.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ShimFrame {
    pub vector: u8,
    pub err_code: u32,
    pub eip: u32,
    pub cs: u32,
    pub eflags: u32,
    pub esp: u32,
    pub ss: u32,
    /// ES, DS, FS, GS — valid only when `eflags` has VM set (VM86 entry).
    pub vm86_segs: [u32; 4],
}

/// Read the shim frame at ring-0 stack pointer `rsp` (a SYS-window linear).
pub(crate) fn read_frame(rsp: u64) -> ShimFrame {
    let rd = |off: u64| -> u32 {
        let mut b = [0u8; 4];
        unsafe { core::ptr::copy_nonoverlapping(sys_ptr(rsp + off), b.as_mut_ptr(), 4) };
        u32::from_le_bytes(b)
    };
    ShimFrame {
        vector: rd(0) as u8,
        err_code: rd(4),
        eip: rd(8),
        cs: rd(12),
        eflags: rd(16),
        esp: rd(20),
        ss: rd(24),
        vm86_segs: [rd(28), rd(32), rd(36), rd(40)],
    }
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

/// Build the IDT, the per-vector stubs, and the TSS in the SYS-window frames.
/// Static content — written once at engine setup (the frames are shared by
/// every address space).
pub(crate) fn write_shim() {
    // IDT: 256 gates → STUB_ADDR + n*16, metal's DPL policy.
    let idt = sys_ptr(IDT_ADDR);
    for n in 0..256usize {
        let dpl = if n == 3 || n == 4 || n >= 0x30 { 3 } else { 0 };
        let gate = idt_gate((STUB_ADDR as u32) + (n as u32) * 16, dpl);
        unsafe {
            core::ptr::copy_nonoverlapping(gate.to_le_bytes().as_ptr(), idt.add(n * 8), 8);
        }
    }

    // Stubs: self-contained 16-byte slots (no shared tail → no jmp reach math).
    for n in 0..256usize {
        let mut code = [0x90u8; 16]; // pad with NOPs (never reached)
        let mut i = 0;
        if !has_err_code(n) {
            code[i] = 0x6A; // push 0  (dummy err_code)
            code[i + 1] = 0x00;
            i += 2;
        }
        if n < 0x80 {
            code[i] = 0x6A; // push imm8 (sign-extended; n < 0x80 stays positive)
            code[i + 1] = n as u8;
            i += 2;
        } else {
            code[i] = 0x68; // push imm32
            code[i + 1..i + 5].copy_from_slice(&(n as u32).to_le_bytes());
            i += 5;
        }
        code[i] = 0xE6; // out SHIM_PORT, al  → KVM_EXIT_IO
        code[i + 1] = SHIM_PORT as u8;
        code[i + 2] = 0xF4; // hlt (never reached)
        unsafe {
            core::ptr::copy_nonoverlapping(
                code.as_ptr(),
                sys_ptr(STUB_ADDR + (n as u64) * 16),
                16,
            );
        }
    }

    // TSS: only ss0/esp0 (the CPL3→CPL0 stack switch) and the IOPB matter.
    // iopb_offset = 0x88; bitmap all-1s = every port denied → IN/OUT at
    // CPL3/IOPL1 #GPs into the shared monitor, identical to the TCG engine and
    // the metal default. `allow_io_ports` clears bits per kernel policy.
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
const IOPB_PORTS: u16 = 0x3E0;

/// One-time shim init shared by setup and the IOPB hooks: `allow_io_ports`
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
pub(super) fn iopb_allow(port: u16, count: usize) {
    ensure_shim();
    let end = port.saturating_add(count as u16).min(IOPB_PORTS);
    for p in port..end {
        if p == SHIM_PORT {
            continue;
        }
        unsafe {
            let byte = sys_ptr(TSS_ADDR + 0x88 + (p / 8) as u64);
            *byte &= !(1 << (p % 8));
        }
    }
}

/// Back to all-deny (per swap-in, like metal's io_policy baseline).
pub(super) fn iopb_reset() {
    ensure_shim();
    unsafe {
        core::ptr::write_bytes(sys_ptr(TSS_ADDR + 0x88), 0xFF, (IOPB_PORTS / 8) as usize);
    }
}
