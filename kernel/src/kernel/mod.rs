//! Ring-1 OS kernel
//!
//! Policy, scheduling, syscalls, filesystems, DOS emulation — everything
//! that gives the system meaning but doesn't require hardware privilege.
//!
//! Three layers, and the dependency arrows only ever point down:
//!
//!   * personalities (`dos`, `linux`) — the ABIs user code sees
//!   * this module — policy, and the driver/fs APIs both personalities reuse
//!   * `drivers` / `fs` — the concrete hardware and on-disk formats

// ── Execution: threads, scheduling, address spaces, loading ──────────────
pub mod elf;
pub mod exec;
pub mod exec_ctx;
pub mod sched;
pub mod startup;
pub mod thread;

// ── Machine policy: what this box is, who owns the console, what it may do ─
pub mod focus;
pub mod io_policy;
pub mod platform;

// ── Diagnostics ─────────────────────────────────────────────────────────
pub mod iostat;
pub mod klog;
pub mod osd;
pub mod stacktrace;

// ── Kernel APIs the personalities call: one surface per resource class ───
pub mod block;
pub mod console;
pub mod display;
pub mod keyboard;
pub mod kpipe;
pub mod net;
pub mod pci;
pub mod portio;
pub mod sound;
pub mod vfs;
// pipe.rs moved to crate root (shared between arch and kernel)

// ── Implementations below those APIs ────────────────────────────────────
pub mod drivers;
pub mod fs;

// ── Personalities ───────────────────────────────────────────────────────
pub mod dos;
pub mod linux;
