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
    pub use crate::cpu::{execute, fpu_pop, fpu_st0, fx_switch, invalidate_code_range};
    /// Flush all cached translations (context switch / space teardown).
    pub fn flush() {
        crate::cpu::flush_uc()
    }
    /// Drop cached translations for a page range after a page-table edit.
    pub fn invalidate_pages(vpage: usize, count: usize) {
        crate::cpu::invalidate_uc(vpage, count)
    }

}

#[cfg(feature = "kvm")]
mod imp {
    pub use crate::kvm::execute;
}

pub(crate) use imp::*;
