//! Kernel text console.
//!
//! The framebuffer *renderer* is `lib::vga` — a pure function from bytes to a
//! cell slice, with no I/O (so it stays a freestanding `lib` util, shared with
//! the bootloader). This module adds the parts that cross the arch boundary:
//! the debug-console / output stream on port `0xE9`, driven through
//! `arch::outb` — a real `out` instruction on metal, the `PortIo` device bus on
//! the interpreter — plus the `print!`/`println!`/`dbg_*!` macros.

use core::fmt::{self, Write};

// Re-export the renderer so `crate::vga::{vga, KERNEL_OWNS_SCREEN}` keep working
// (cursor/clear/base live on the lib `Vga`).
pub use lib::vga::{vga, Vga, KERNEL_OWNS_SCREEN};

/// Debug console / output-stream port. `arch::outb` issues a real `out` on
/// metal and routes to the `PortIo` debug-console device on the interpreter.
const DEBUGCON: u16 = 0xE9;

#[inline]
fn stream(b: u8) {
    crate::arch::outb(DEBUGCON, b);
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
