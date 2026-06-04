//! Segment resolution + canonical event types, mirroring the parts of
//! `kernel/src/arch/monitor.rs` the kernel/dos layers reach for.
//!
//! `KernelEvent`/`IoSize` are the shared contract (re-exported from `arch-abi`).
//! `seg_base`/`seg_is_32`/`sw_reflect_vm86_int` are consulted by the DOS/VM86
//! personality; the interpreter resolves them against its software descriptor
//! model, built out in Milestone 2.

pub use arch_abi::{IoSize, KernelEvent};
use arch_abi::Regs;

/// Linear base of selector `sel` in the active descriptor tables.
pub fn seg_base(_sel: u16) -> u32 {
    unimplemented!("interp seg_base — software descriptor model (M2)")
}

/// Whether selector `sel` is a 32-bit (D=1) segment.
pub fn seg_is_32(_sel: u16) -> bool {
    unimplemented!("interp seg_is_32 — software descriptor model (M2)")
}

/// Synthesize a real-mode `INT n` on the guest's VM86 stack (DOS reflection).
///
/// # Safety
/// Mirrors the metal signature; reads/writes guest VM86 memory via the IVT and
/// stack. The interpreter implementation lands with the VM86 path in M2.
pub unsafe fn sw_reflect_vm86_int(_regs: &mut Regs, _vector: u8) {
    unimplemented!("interp VM86 INT reflection (M2)")
}
