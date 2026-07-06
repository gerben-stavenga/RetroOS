//! Sensitive-instruction monitor — metal binding for the shared decoder.
//!
//! The decode/emulate logic lives in [`arch_abi::monitor`] so the metal and
//! interpreter backends share bit-for-bit sensitive-instruction semantics. This
//! module supplies the metal [`GuestView`]: on a real #GP the faulting thread's
//! page tables are live, so guest memory is reached by dereferencing the linear
//! address directly, and selectors resolve through `descriptors::seg_base`.
//!
//! The public surface (`monitor`, `step_virtual_if`, `sw_reflect_vm86_int`,
//! `seg_base`, `seg_is_32`, `MonitorResult`, `virtual_if_stepping`, plus the
//! re-exported `KernelEvent`/`IoSize`) is unchanged — callers in `traps.rs` /
//! `backend.rs` keep resolving `crate::monitor::*` as before.

use arch_abi::Regs;

// Backend-agnostic arch↔kernel contract types, re-exported so
// `crate::monitor::{KernelEvent, IoSize}` keeps resolving.
pub use arch_abi::{IoSize, KernelEvent};
pub use arch_abi::monitor::{virtual_if_stepping, MonitorResult};

// Segment resolution (re-exported from descriptors).
pub use crate::descriptors::{seg_base, seg_is_32};

// The shared decoder takes the faulting `&mut Vcpu`; metal reaches guest memory
// through the live page tables (its `GuestBytes` impl dereferences the linear
// address, ignoring the space handle), so the `space` we hand it is a throwaway
// — the same pattern the step tracer uses (`isr_handler_ring3`). The trap frame
// is a `&mut Regs`, so we wrap it in a temporary vcpu across the call and copy
// the (mutated) registers back. Segment/int resolution is `Metal::seg_base`
// etc. (associated fns, ambient descriptor state).

/// Decode the instruction at CS:IP and either finish it inline (`Resume`) or
/// return a typed kernel event. Called from `isr_handler_ring3` on #GP from
/// ring-3 — see [`arch_abi::monitor::monitor`]. `Metal` is the active-space
/// `GuestBytes` accessor (ZST); its memory ops deref the live page tables.
#[inline]
pub fn monitor(regs: &mut Regs) -> MonitorResult {
    arch_abi::monitor::monitor(&mut crate::backend::Metal, regs)
}

/// Virtual-IF single-step driver for PM clients — see
/// [`arch_abi::monitor::step_virtual_if`].
#[inline]
pub fn step_virtual_if(regs: &mut Regs) -> MonitorResult {
    arch_abi::monitor::step_virtual_if(&mut crate::backend::Metal, regs)
}

/// SW equivalent of the CPU's VM86 INT dispatch — see
/// [`arch_abi::monitor::sw_reflect_vm86_int`]. Memory reaches the active space
/// through `Metal` (`GuestBytes`).
///
/// # Safety
///
/// Kept `unsafe` for caller compatibility (it touches the live VM86 stack via
/// the active page tables).
#[inline]
pub unsafe fn sw_reflect_vm86_int(regs: &mut Regs, vector: u8) {
    arch_abi::monitor::sw_reflect_vm86_int(regs, &mut crate::backend::Metal, vector)
}

/// Log one PM/VM86 single-step: CS:EIP + key regs + the first opcode bytes.
/// Armed via `arch_abi::PM_STEP_BUDGET`; the single-step `#DB` handler calls
/// this each step until the budget drains. Pure arch-level instruction tracing.
pub fn pm_step_log(regs: &crate::Vcpu) {
    use arch_abi::GuestBytes;
    let is_vm86 = regs.frame.rflags & (1u64 << 17) != 0;
    let (cs_base, mode) = if is_vm86 {
        ((regs.code_seg() as u32) << 4, "RM")
    } else {
        let cs = regs.code_seg();
        let m = if seg_is_32(cs) { "PM32" } else { "PM16" };
        (seg_base(cs), m)
    };
    let ip = if mode == "PM32" { regs.ip32() } else { regs.ip32() & 0xFFFF };
    let lin = cs_base.wrapping_add(ip);
    let mut b = [0u8; 8];
    for (i, byte) in b.iter_mut().enumerate() {
        *byte = crate::backend::Metal.read::<u8>((lin + i as u32) as usize);
    }
    let f = regs.flags32();
    lib::dbg_println!(
        "[STEP {}] {:04X}:{:08X} VIF={} IF={} op={:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X} EAX={:08X} EBX={:08X} ECX={:08X} EDX={:08X} SS:SP={:04X}:{:08X}",
        mode, regs.code_seg(), ip,
        (f >> 19) & 1, (f >> 9) & 1,
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        regs.rax as u32, regs.rbx as u32, regs.rcx as u32, regs.rdx as u32,
        regs.frame.ss as u16, regs.sp32(),
    );
}
