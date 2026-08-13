//! The log stream: an unowned, non-ephemeral mirror of everything printed.
//!
//! The counterpart of a terminal, and deliberately its opposite in every
//! respect. A terminal is owned, exclusive and ephemeral — one owner at a
//! time, and what scrolls off is gone. This is ambient, shared and kept: the
//! `//klog` ring plus whatever sink the platform installed (`out 0xE9` on
//! metal, stderr or a file when hosted).
//!
//! Being unowned is the point, not an oversight. Any owner may mirror its
//! output here without taking anyone's display: a DOS program's INT 21h
//! output, a Linux process's stdout and the kernel's own diagnostics all land
//! in one stream, in order, regardless of who currently holds the screen. It
//! also has to work mid-panic, when there is no owner left to ask — hence the
//! atomic function-pointer sink and no allocation anywhere on this path.
//!
//! `print!`/`println!`/`dbg_print!`/`dbg_println!` all come here. Only
//! `screenln!` touches a terminal.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// =============================================================================
// Debug-output sink + the console macros
// =============================================================================
//
// Logging is a *platform* concern that must work ambiently (no `&mut machine` to
// thread into a `println!`) and even mid-panic, so it goes through a function-
// pointer sink the platform installs once at startup rather than the `arch`
// boundary: metal installs an `out 0xE9, al` emitter, the hosted binary a
// stderr/log-file writer, the bootloader installs nothing (sink stays null).
// Living in `lib` lets every embedder — bootloader, kernel, and each backend
// crate — share one sink, one allocation-free log ring, and one set of macros.

/// The platform-installed debug-output sink (`fn(u8)` as its address; 0 = none,
/// bytes dropped). Write-only and panic-safe: an atomic load + indirect call.
static DEBUG_SINK: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Monotonic milliseconds supplied by the embedding kernel. A 32-bit value
/// is sufficient on the 32-bit target and avoids requiring 64-bit atomics.
static TIMESTAMP_MS: AtomicU32 = AtomicU32::new(0);
static LINE_START: AtomicBool = AtomicBool::new(true);

/// Update the monotonic timestamp used for subsequent log lines.
pub fn set_timestamp_ms(ms: u64) {
    TIMESTAMP_MS.store(ms as u32, Ordering::Relaxed);
}

/// Install the platform debug-output sink. Called once, early, by the platform
/// entry point (metal `boot_kernel`, hosted `main`) before anything logs.
pub fn set_debug_sink(f: fn(u8)) {
    DEBUG_SINK.store(f as usize, core::sync::atomic::Ordering::Relaxed);
}

/// Emit one byte to the debug-output sink (the DOS console mirror uses this to
/// echo program output to the log stream alongside the VGA framebuffer).
pub fn debug_byte(b: u8) {
    stream(b);
}

/// Mirror one byte into the ring and the platform sink.
#[inline]
pub fn stream(b: u8) {
    if b != b'\n' && LINE_START.swap(false, Ordering::Relaxed) {
        emit_timestamp(TIMESTAMP_MS.load(Ordering::Relaxed));
    }
    klog::push_byte(b);
    let p = DEBUG_SINK.load(core::sync::atomic::Ordering::Relaxed);
    if p != 0 {
        let f: fn(u8) = unsafe { core::mem::transmute(p) };
        f(b);
    }
    if b == b'\n' {
        LINE_START.store(true, Ordering::Relaxed);
    }
}

fn emit_timestamp(ms: u32) {
    let seconds = ms / 1000;
    let millis = ms % 1000;
    let mut out = [b' '; 14];
    out[0] = b'[';
    out[9] = b'.';
    out[13] = b']';
    let mut value = seconds;
    for i in (1..=8).rev() {
        if value != 0 || i == 8 {
            out[i] = b'0' + (value % 10) as u8;
        }
        value /= 10;
    }
    out[10] = b'0' + (millis / 100) as u8;
    out[11] = b'0' + ((millis / 10) % 10) as u8;
    out[12] = b'0' + (millis % 10) as u8;
    for byte in out {
        klog::push_byte(byte);
        let p = DEBUG_SINK.load(Ordering::Relaxed);
        if p != 0 {
            let f: fn(u8) = unsafe { core::mem::transmute(p) };
            f(byte);
        }
    }
    // The separator is part of the prefix but is emitted through the same
    // raw path to avoid recursively generating another timestamp.
    klog::push_byte(b' ');
    let p = DEBUG_SINK.load(Ordering::Relaxed);
    if p != 0 {
        let f: fn(u8) = unsafe { core::mem::transmute(p) };
        f(b' ');
    }
}

/// Debug-console-only writer (the sink stream, never the framebuffer).
pub struct DebugCon;
impl Write for DebugCon {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            stream(b);
        }
        Ok(())
    }
}

/// Print formatted text to the log stream (debugcon sink + klog). Never the
/// screen: on-screen text requires holding the kernel's `Console` (or a bare
/// terminal, for an embedder alone on the machine) — use `screenln!`. Kept
/// alongside `dbg_print!` so existing log call sites compile; they are
/// synonyms.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = $crate::log::DebugCon.write_fmt(format_args!($($arg)*));
    }};
}

/// `print!` with a newline (log stream only, like `print!`).
#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => {{
        $crate::print!($($arg)*);
        $crate::print!("\n");
    }};
}

/// Print to the debug console (sink) only, never the framebuffer.
#[macro_export]
macro_rules! dbg_print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = $crate::log::DebugCon.write_fmt(format_args!($($arg)*));
    }};
}

/// `dbg_print!` with a newline.
#[macro_export]
macro_rules! dbg_println {
    () => { $crate::dbg_print!("\n") };
    ($($arg:tt)*) => {{
        $crate::dbg_print!($($arg)*);
        $crate::dbg_print!("\n");
    }};
}
