//! Ring-1 OS kernel
//!
//! Policy, scheduling, syscalls, filesystems, DOS emulation — everything
//! that gives the system meaning but doesn't require hardware privilege.

pub mod dpmi;
pub mod elf;
pub mod hdd;
pub mod heap;
pub mod keyboard;
// pipe.rs moved to crate root (shared between arch and kernel)
pub mod stacktrace;
pub mod startup;
pub mod syscalls;
pub mod tarfs;
pub mod thread;
pub mod vfs;
pub mod vm86;
