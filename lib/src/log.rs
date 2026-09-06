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
    klog::push_byte(b);
    let p = DEBUG_SINK.load(core::sync::atomic::Ordering::Relaxed);
    if p != 0 {
        let f: fn(u8) = unsafe { core::mem::transmute(p) };
        f(b);
    }
}

/// Debug-console-only writer (the sink stream, never the framebuffer).
pub struct DebugCon;
impl compact_fmt::Write for DebugCon {
    fn write_str(&mut self, text: &str) -> compact_fmt::Result {
        for byte in text.bytes() {
            stream(byte);
        }
        Ok(())
    }
}

const PANIC_MESSAGE_CAPACITY: usize = 384;
static mut PANIC_MESSAGE: [u8; PANIC_MESSAGE_CAPACITY] = [0; PANIC_MESSAGE_CAPACITY];
static PANIC_MESSAGE_LEN: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
static PANIC_MESSAGE_CLAIMED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

#[doc(hidden)]
pub struct PanicMessageWriter {
    claimed: bool,
}

impl PanicMessageWriter {
    pub fn new() -> Self {
        let claimed = PANIC_MESSAGE_CLAIMED
            .compare_exchange(
                false,
                true,
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Relaxed,
            )
            .is_ok();
        if claimed {
            PANIC_MESSAGE_LEN.store(0, core::sync::atomic::Ordering::Relaxed);
        }
        Self { claimed }
    }
}

impl Default for PanicMessageWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl compact_fmt::Write for PanicMessageWriter {
    fn write_str(&mut self, text: &str) -> compact_fmt::Result {
        if !self.claimed {
            return Ok(());
        }
        let start = PANIC_MESSAGE_LEN.load(core::sync::atomic::Ordering::Relaxed);
        let count = text.len().min(PANIC_MESSAGE_CAPACITY.saturating_sub(start));
        unsafe {
            core::ptr::copy_nonoverlapping(
                text.as_ptr(),
                core::ptr::addr_of_mut!(PANIC_MESSAGE).cast::<u8>().add(start),
                count,
            );
        }
        PANIC_MESSAGE_LEN.store(start + count, core::sync::atomic::Ordering::Release);
        Ok(())
    }
}

pub fn panic_message() -> Option<&'static str> {
    let len = PANIC_MESSAGE_LEN.load(core::sync::atomic::Ordering::Acquire);
    if len == 0 {
        return None;
    }
    let bytes = unsafe {
        core::slice::from_raw_parts(core::ptr::addr_of!(PANIC_MESSAGE).cast::<u8>(), len)
    };
    core::str::from_utf8(bytes).ok()
}

#[macro_export]
macro_rules! compact_panic {
    ($($arg:tt)*) => {{
        let mut writer = $crate::log::PanicMessageWriter::new();
        let _ = compact_fmt::write!(&mut writer, $($arg)*);
        panic!("compact panic")
    }};
}

/// Print formatted text to the log stream (debugcon sink + klog). Never the
/// screen: on-screen text requires holding the kernel's `Console` (or a bare
/// terminal, for an embedder alone on the machine) — use `screenln!`. Kept
/// alongside `dbg_print!` so existing log call sites compile; they are
/// synonyms.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        let _ = compact_fmt::write!(&mut $crate::log::DebugCon, $($arg)*);
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

/// Compact formatting for diagnostics made only of primitive values.
#[macro_export]
macro_rules! compact_println {
    ($($arg:tt)*) => {{
        let _ = compact_fmt::writeln!(&mut $crate::log::DebugCon, $($arg)*);
    }};
}

/// Debug-console spelling of [`compact_println!`].
#[macro_export]
macro_rules! compact_dbg_println {
    ($($arg:tt)*) => { $crate::compact_println!($($arg)*) };
}

/// Print to the debug console (sink) only, never the framebuffer.
#[macro_export]
macro_rules! dbg_print {
    ($($arg:tt)*) => {{
        let _ = compact_fmt::write!(&mut $crate::log::DebugCon, $($arg)*);
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
