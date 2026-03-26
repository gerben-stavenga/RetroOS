//! Ring-0 arch layer
//!
//! Privileged supervisor code: interrupt handling, paging, physical memory,
//! descriptor tables, and the arch call interface for the ring-1 kernel.

pub mod descriptors;
pub mod irq;
pub mod paging2;
pub mod phys_mm;
pub mod traps;
pub mod x86;
