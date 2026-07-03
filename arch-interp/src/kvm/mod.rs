//! The KVM engine — run guest ring-3/VM86 slices on the real CPU via
//! `/dev/kvm`, with the kernel staying a normal host process.
//!
//! Layering (everything above the engine seam is shared with the TCG engine):
//! * `setup.rs` — VM/vcpu/memory-slot/CPUID bring-up + the 1 ms timer kick.
//! * `shim.rs`  — the in-guest ring-0 trap shim (IDT + stubs + TSS) that turns
//!   guest faults into `KVM_EXIT_IO` on a magic port.
//! * `run.rs`   — the execute loop: `Regs` ↔ KVM register mapping, the
//!   `KVM_EXIT_*` → `KernelEvent` demux, virtual-IF single-stepping.

mod run;
mod setup;
mod shim;
#[cfg(test)]
mod tests;

pub use run::execute;

/// Host-side page-table edits invalidated guest translations. The execute loop
/// re-loads SREGS (CR3 included) on every guest entry — KVM resets the vcpu's
/// MMU context on that path — so the flush is inherent and nothing needs
/// recording; the hook exists as the engine-seam contract point (and becomes
/// real state if entry ever moves to dirty-tracked SREGS reloads).
pub fn mark_tlb_dirty() {}

/// IOPB fast path (M4): allow direct `KVM_EXIT_IO` for a port range by
/// clearing its bits in the guest TSS I/O bitmap.
pub fn allow_io_ports(_port: u16, _count: usize) {}

/// Reset the guest TSS I/O bitmap to all-deny (per swap-in, like metal).
pub fn reset_io_bitmap() {}
