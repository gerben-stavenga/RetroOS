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

use arch_abi::monitor::GuestView;
use arch_abi::Regs;

// Backend-agnostic arch↔kernel contract types, re-exported so
// `crate::monitor::{KernelEvent, IoSize}` keeps resolving.
pub use arch_abi::{IoSize, KernelEvent};
pub use arch_abi::monitor::{virtual_if_stepping, MonitorResult};

// Segment resolution (re-exported from descriptors).
pub use crate::descriptors::{seg_base, seg_is_32};

/// Metal guest-memory view: the faulting thread's page tables are active during
/// the #GP, so a linear address is dereferenceable directly. Reads/writes are
/// unaligned-safe (real-mode IVT and 16-bit stacks are paragraph-aligned, not
/// dword-aligned).
struct MetalView;

impl GuestView for MetalView {
    #[inline]
    fn read8(&mut self, lin: u32) -> u8 {
        unsafe { *(lin as *const u8) }
    }
    #[inline]
    fn read16(&mut self, lin: u32) -> u16 {
        unsafe { core::ptr::read_unaligned(lin as *const u16) }
    }
    #[inline]
    fn read32(&mut self, lin: u32) -> u32 {
        unsafe { core::ptr::read_unaligned(lin as *const u32) }
    }
    #[inline]
    fn write16(&mut self, lin: u32, val: u16) {
        unsafe { core::ptr::write_unaligned(lin as *mut u16, val); }
    }
    #[inline]
    fn write32(&mut self, lin: u32, val: u32) {
        unsafe { core::ptr::write_unaligned(lin as *mut u32, val); }
    }
    #[inline]
    fn seg_base(&mut self, sel: u16) -> u32 { crate::descriptors::seg_base(sel) }
    #[inline]
    fn seg_is_32(&mut self, sel: u16) -> bool { crate::descriptors::seg_is_32(sel) }
    #[inline]
    fn int_intercepted(&mut self, vector: u8) -> bool {
        crate::descriptors::int_intercepted(vector)
    }
}

/// Decode the instruction at CS:IP and either finish it inline (`Resume`) or
/// return a typed kernel event. Called from `isr_handler_inner` on #GP from
/// ring-3 — see [`arch_abi::monitor::monitor`].
#[inline]
pub fn monitor(regs: &mut Regs) -> MonitorResult {
    arch_abi::monitor::monitor(regs, &mut MetalView)
}

/// Virtual-IF single-step driver for PM clients — see
/// [`arch_abi::monitor::step_virtual_if`].
#[inline]
pub fn step_virtual_if(regs: &mut Regs) -> MonitorResult {
    arch_abi::monitor::step_virtual_if(regs, &mut MetalView)
}

/// SW equivalent of the CPU's VM86 INT dispatch — see
/// [`arch_abi::monitor::sw_reflect_vm86_int`]. Kept `unsafe` for caller
/// compatibility (it touches the live VM86 stack via the active page tables).
#[inline]
pub unsafe fn sw_reflect_vm86_int(regs: &mut Regs, vector: u8) {
    arch_abi::monitor::sw_reflect_vm86_int(regs, &mut MetalView, vector)
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
    for i in 0..8 {
        b[i] = regs.read::<u8>((lin + i as u32) as usize);
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
