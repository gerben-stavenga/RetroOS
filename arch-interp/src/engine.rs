//! The engine seam — the one module that knows which execution engine this
//! crate was compiled with.
//!
//! `arch-interp` is the *hosted* backend; the CPU under the guest is a
//! compile-time choice between two engines (mutually exclusive crate features,
//! enforced by the `compile_error!` guards in lib.rs):
//!  * `tcg` (default): the Unicorn / QEMU-TCG software core in `cpu.rs`.
//!  * `kvm`: real hardware execution via `/dev/kvm` in `kvm/`.
//!
//! Everything above this seam (paging, phys frames, devices, the shared
//! monitor, front-ends) is engine-agnostic; everything below it may be
//! engine-specific. In-crate call sites route through these functions, never
//! through `cpu::` / `kvm::` directly.

#[cfg(feature = "tcg")]
mod imp {
    pub use crate::cpu::{execute, invalidate_code_range};
    /// Flush all cached translations (context switch / space teardown).
    pub fn flush() {
        crate::cpu::flush_uc()
    }
    /// Drop cached translations for a page range after a page-table edit.
    pub fn invalidate_pages(vpage: usize, count: usize) {
        crate::cpu::invalidate_uc(vpage, count)
    }
    /// All I/O is interpreted; there is no IOPB fast path on this engine.
    pub fn allow_io_ports(_port: u16, _count: usize) {}
    pub fn reset_io_bitmap() {}
    /// FPU state lives inside the software core; cross-switch save/restore
    /// is not wired on this engine (pre-existing status).
    pub fn fx_switch(_fx: &mut crate::machine::FxState) {}
}

#[cfg(feature = "kvm")]
mod imp {
    pub use crate::kvm::{allow_io_ports, execute, fx_switch, reset_io_bitmap};
    /// The guest TLB is real: mark it dirty so the next entry flushes it.
    pub fn flush() {
        crate::kvm::mark_tlb_dirty()
    }
    pub fn invalidate_pages(_vpage: usize, _count: usize) {
        crate::kvm::mark_tlb_dirty()
    }
    /// The real CPU is store-vs-fetch coherent; there are no cached
    /// translations to drop on a guest-code write.
    pub fn invalidate_code_range(_addr: u32, _len: u32) {}
}

pub(crate) use imp::*;
