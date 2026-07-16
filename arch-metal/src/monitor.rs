//! Sensitive-instruction monitor — metal binding for the shared decoder.
//!
//! The decode/emulate logic lives in [`arch_abi::monitor`] so the metal and
//! interpreter backends share bit-for-bit sensitive-instruction semantics. This
//! module supplies the metal [`GuestView`]: on a real #GP the faulting thread's
//! page tables are live, so guest memory is reached by dereferencing the linear
//! address directly, and selectors resolve through `descriptors::seg_base`.
//!
//! The public surface (`monitor`, `sw_reflect_vm86_int`, `seg_base`,
//! `seg_is_32`, `MonitorResult`, plus the re-exported `KernelEvent`/`IoSize`) is
//! resolved as `crate::monitor::*` by callers in `traps.rs` / `backend.rs`.

use arch_abi::Regs;

// Backend-agnostic arch↔kernel contract types, re-exported so
// `crate::monitor::{KernelEvent, IoSize}` keeps resolving.
pub use arch_abi::{IoSize, KernelEvent};
pub use arch_abi::monitor::MonitorResult;

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
