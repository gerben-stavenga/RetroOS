//! Ring-0 arch layer
//!
//! Privileged supervisor code: interrupt handling, paging, physical memory,
//! descriptor tables, and the arch call interface for the ring-1 kernel.
//!
//! The boot sequence (PrepareKernel → KernelInit → enter_ring1) lives here
//! and calls submodules directly. After enter_ring1(), the kernel layer
//! uses only the re-exports below and arch calls (INT 0x80).

mod boot;
mod descriptors;
mod irq;
pub mod monitor;
mod paging2;
mod phys_mm;
mod traps;
mod x86;

// --- Re-exports for the kernel layer (ring 1) ---

// Types
pub use paging2::{KernelPages, RawPage, RootPageTable, PAGE_SIZE, LOW_MEM_BASE, unmap_kernel_page};
pub use irq::Irq;
pub use descriptors::{USER_CS, USER_CS64, USER_DS};

// Arch call constants (used by INT 0x80 wrappers in startup.rs)
pub use traps::arch_call;
pub(crate) use traps::REGS;

// Power/halt entry points. The kernel layer must not toggle IF directly —
// `cli`/`sti` stay arch-private; use `halt_forever` (panic) and
// `without_irqs` (critical sections) instead.
pub use x86::{hlt, shutdown};

/// Disable interrupts and halt forever. For panic / shutdown failure.
pub fn halt_forever() -> ! {
    x86::cli();
    loop { x86::hlt(); }
}

// TODO: migrate to arch calls
pub use x86::{inb, outb, inw, outw};
pub use x86::{FxState, clean_fx_template};
pub use irq::{get_ticks, take_pending_ticks, drain};

/// Physical free-page count, for diagnostic logging. Walks PAGE_REFS;
/// O(MAX_PAGES) but small (~64 KB scan) and only called from instrumentation.
pub fn free_page_count() -> usize {
    phys_mm::free_page_count()
}
