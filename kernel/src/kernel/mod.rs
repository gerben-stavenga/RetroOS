//! Ring-1 OS kernel
//!
//! Policy, scheduling, syscalls, filesystems, DOS emulation — everything
//! that gives the system meaning but doesn't require hardware privilege.

pub mod ac97;
pub mod alc298_amp;
pub mod hda;
pub mod block;
pub mod lwext4;
pub mod console;
pub mod dos;
pub mod elf;
pub mod exec;
pub mod exec_ctx;
pub mod focus;
pub mod hdd;
pub mod hostfs;
pub mod io_policy;
pub mod nvme;
pub mod pci;
pub mod platform;
pub mod portio;
pub mod sched;
pub mod keyboard;
pub mod kpipe;
pub mod net;
pub mod klog;
pub mod linux;
pub mod sound;
// pipe.rs moved to crate root (shared between arch and kernel)
pub mod stacktrace;
pub mod startup;
pub mod tarfs;
pub mod thread;
pub mod vfs;
