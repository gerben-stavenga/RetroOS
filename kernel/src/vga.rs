//! Kernel text console.
//!
//! The framebuffer *renderer* is `lib::vga` — a pure function from bytes to a
//! cell slice, with no I/O (so it stays a freestanding `lib` util, shared with
//! the bootloader). This module adds the kernel text console: the `print!` /
//! `println!` / `dbg_*!` macros plus the byte sink they mirror to.
//!
//! Logging is a *platform* concern, not an arch one — it must work ambiently
//! (no `&mut machine` to thread into a `println!`) and even mid-panic. So the
//! sink is a function pointer the platform installs once at startup, instead of
//! going through the `arch` boundary: metal installs an `out 0xE9, al` emitter;
//! the hosted binary installs a plain stderr (or log-file) writer. The kernel
//! itself never touches a port to log.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicUsize, Ordering};

// Re-export the renderer so `crate::vga::{vga, KERNEL_OWNS_SCREEN}` keep working
// (cursor/clear/base live on the lib `Vga`).
pub use lib::vga::{vga, Vga, KERNEL_OWNS_SCREEN};

/// The platform-installed debug-output sink (`fn(u8)` stored as its address; 0 =
/// none yet, in which case bytes are dropped). Write-only and panic-safe: a
/// plain atomic load + indirect call, no locks, no `&mut` state.
static DEBUG_SINK: AtomicUsize = AtomicUsize::new(0);

/// Install the platform debug-output sink. Called once, early, by the platform
/// entry point (metal `boot_kernel`, hosted `main`) before anything logs.
pub fn set_debug_sink(f: fn(u8)) {
    DEBUG_SINK.store(f as usize, Ordering::Relaxed);
}

/// Emit one byte to the debug-output sink (the DOS console mirror uses this to
/// echo program output to the log stream alongside the VGA framebuffer).
pub fn debug_byte(b: u8) {
    stream(b);
}

#[inline]
fn stream(b: u8) {
    let p = DEBUG_SINK.load(Ordering::Relaxed);
    if p != 0 {
        let f: fn(u8) = unsafe { core::mem::transmute(p) };
        f(b);
    }
}

/// Write one byte to the console: render it to the framebuffer and mirror it to
/// the `0xE9` output stream. Direct console writers (DOS/Linux `write`) use this.
pub fn putchar(c: u8) {
    vga().putchar(c);
    stream(c);
}

/// Console writer behind `print!`/`println!`: renders to the framebuffer when
/// the kernel owns the screen, and always mirrors to the `0xE9` stream.
pub struct Console;
impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let to_screen = KERNEL_OWNS_SCREEN.load(core::sync::atomic::Ordering::Relaxed);
        for b in s.bytes() {
            if to_screen {
                vga().putchar(b);
            }
            stream(b);
        }
        Ok(())
    }
}

/// Debug-console-only writer (port `0xE9`, never the framebuffer).
pub struct DebugCon;
impl Write for DebugCon {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            stream(b);
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = $crate::vga::Console.write_fmt(format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! println {
    () => { $crate::vga::putchar(b'\n') };
    ($($arg:tt)*) => {{
        $crate::print!($($arg)*);
        $crate::print!("\n");
    }};
}

#[macro_export]
macro_rules! dbg_print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = $crate::vga::DebugCon.write_fmt(format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! dbg_println {
    () => { $crate::dbg_print!("\n") };
    ($($arg:tt)*) => {{
        $crate::dbg_print!($($arg)*);
        $crate::dbg_print!("\n");
    }};
}
