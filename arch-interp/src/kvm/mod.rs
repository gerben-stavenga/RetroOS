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

/// IOPB fast path: allow direct `KVM_EXIT_IO` for a port range by clearing
/// its bits in the guest TSS I/O bitmap (kernel io_policy grants — real
/// passthrough hardware only; the hosted platform's emulated VGA keeps its
/// ports trapped through the shim + monitor).
pub fn allow_io_ports(port: u16, count: usize) {
    shim::iopb_allow(port, count)
}

/// Reset the guest TSS I/O bitmap to all-deny (per swap-in, like metal).
pub fn reset_io_bitmap() {
    shim::iopb_reset()
}

/// Swap the live guest FPU/SSE state with the thread save area `fx` (metal's
/// `arch_switch_to` fx semantics: on return `fx` holds the outgoing thread's
/// state, the vcpu holds the incoming). The vcpu's FXSAVE image is the first
/// 512 bytes of its XSAVE area; the XSAVE header is preserved and the
/// x87+SSE bits forced into XSTATE_BV so the restore actually loads them.
pub fn fx_switch(fx: &mut crate::machine::FxState) {
    setup::with(|k| {
        let mut xsave = k.vcpu.get_xsave().expect("KVM_GET_XSAVE");
        let outgoing = *fx;
        // region is [u32; 1024]; bytes 0..512 = the legacy FXSAVE image,
        // u64 at byte 512 (region[128..130]) = XSTATE_BV.
        unsafe {
            let bytes = xsave.region.as_mut_ptr() as *mut u8;
            core::ptr::copy_nonoverlapping(bytes, fx.0.as_mut_ptr(), 512);
            core::ptr::copy_nonoverlapping(outgoing.0.as_ptr(), bytes, 512);
        }
        xsave.region[128] |= 0x3; // XSTATE_BV: x87 | SSE
        unsafe { k.vcpu.set_xsave(&xsave) }.expect("KVM_SET_XSAVE");
    })
}
