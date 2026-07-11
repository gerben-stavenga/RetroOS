//! Kernel text console — re-exported from `lib::vga`.
//!
//! The console (framebuffer renderer + the platform-installed debug sink + the
//! `print!`/`println!`/`dbg_*!` macros) lives in `lib`, so every embedder — the
//! bootloader, the kernel, and each arch backend crate — shares one sink and one
//! set of macros. This module re-exports the kernel-facing surface so existing
//! `crate::vga::…` paths keep resolving; the macros are re-exported at the crate
//! root (see `lib.rs`) so `crate::println!` and bare `println!` keep working.

pub use lib::vga::{
    vga, Vga, Screen,
    set_debug_sink, debug_byte, putchar, DebugCon,
};
