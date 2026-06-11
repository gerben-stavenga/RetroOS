//! Ring-1 OS kernel
//!
//! Policy, scheduling, syscalls, filesystems, DOS emulation — everything
//! that gives the system meaning but doesn't require hardware privilege.

pub mod ac97;
pub mod block;
pub mod dos;
pub mod elf;
pub mod exec;
pub mod ext4fs;
pub mod hdd;
pub mod hostfs;
pub mod nvme;
pub mod pci;
pub mod platform;
// The bare-metal demand-paging heap allocator is metal-only; the hosted build
// uses std's global allocator, so it needs just a no-op `init()`.
#[cfg(not(feature = "hosted"))]
pub mod heap;
#[cfg(feature = "hosted")]
pub mod heap {
    /// No-op on hosted: std installs the global allocator.
    pub fn init() {}
}
pub mod keyboard;
pub mod kpipe;
pub mod linux;
pub mod sound;
// pipe.rs moved to crate root (shared between arch and kernel)
pub mod stacktrace;
pub mod startup;
pub mod tarfs;
pub mod thread;
pub mod vfs;
