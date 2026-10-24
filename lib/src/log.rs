//! The log stream: an unowned, non-ephemeral mirror of everything printed.
//!
//! The counterpart of a terminal, and deliberately its opposite in every
//! respect. A terminal is owned, exclusive and ephemeral — one owner at a
//! time, and what scrolls off is gone. This is ambient, shared and kept: the
//! `//klog` ring plus whatever sink the platform installed (`out 0xE9` on
//! metal, stderr or a file when hosted).
//!
//! Being unowned is the point, not an oversight. Any owner may mirror its
//! output here without taking anyone's display: DOS INT 21h output and the
//! kernel's own diagnostics land in one stream, regardless of who holds the
//! screen. Linux terminal redraws use a separate console path. This stream
//! uses no allocation. Complete lines are serialized in kernel context;
//! interrupt and NMI handlers must not reenter this blocking logger.
//!
//! `print!`/`println!`/`dbg_print!`/`dbg_println!` all come here. Only
//! `screenln!` touches a terminal.

// =============================================================================
// Debug-output sink + the console macros
// =============================================================================
//
// Logging is a *platform* concern that must work ambiently (no `&mut machine` to
// thread into a `println!`), so it goes through a function-
// pointer sink the platform installs once at startup rather than the `arch`
// boundary: metal installs an `out 0xE9, al` emitter, the hosted binary a
// stderr/log-file writer, the bootloader installs nothing (sink stays null).
// Living in `lib` lets every embedder — bootloader, kernel, and each backend
// crate — share one sink, one allocation-free log ring, and one set of macros.

/// The platform-installed debug-output sink (`fn(u8)` as its address; 0 = none,
/// bytes dropped). Invoked with the output lock held; must not log recursively.
static DEBUG_SINK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static LINE_SINK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static CORE_ID_SOURCE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static LINE_CONTEXT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static OUTPUT_LOCK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Pending bytes owned by one execution context (one core on metal). Formatting
/// fragments are collected here; only complete lines reach shared output sinks.
pub struct LineBuffer {
    bytes: [u8; 512],
    len: usize,
    truncated: bool,
}
impl Default for LineBuffer {
    fn default() -> Self {
        Self::new()
    }
}
impl LineBuffer {
    pub const fn new() -> Self {
        Self {
            bytes: [0; 512],
            len: 0,
            truncated: false,
        }
    }
}
static mut FALLBACK_LINE: LineBuffer = LineBuffer::new();

/// Install a stable per-context buffer, before concurrent logging starts.
/// The provider must not allocate or log. Its storage is accessed only while
/// OUTPUT_LOCK is held and must remain alive for all calls using the context.
///
/// # Safety
/// The pointer must be valid and exclusive to the logger. Different execution
/// contexts must return different buffers; moving tasks need a fresh boundary.
/// Without a provider, the fallback buffer supports a single execution context.
pub unsafe fn set_line_context(f: fn() -> *mut LineBuffer) {
    LINE_CONTEXT.store(f as usize, core::sync::atomic::Ordering::Release);
}

/// Enable a logical core prefix on metal. Called before concurrent logging.
pub fn set_core_id_source(f: fn() -> u32) {
    CORE_ID_SOURCE.store(f as usize, core::sync::atomic::Ordering::Release);
}

struct OutputGuard;
impl OutputGuard {
    fn lock() -> Self {
        use core::sync::atomic::Ordering;
        while OUTPUT_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Self
    }
}
impl Drop for OutputGuard {
    fn drop(&mut self) {
        OUTPUT_LOCK.store(false, core::sync::atomic::Ordering::Release);
    }
}

/// Install the platform debug-output sink. Called once, early, by the platform
/// entry point (metal `boot_kernel`, hosted `main`) before anything logs.
pub fn set_debug_sink(f: fn(u8)) {
    DEBUG_SINK.store(f as usize, core::sync::atomic::Ordering::Relaxed);
}

/// Called after each completed log line. The platform must avoid blocking on
/// a filesystem lock when this runs from within filesystem code.
pub fn set_line_sink(f: fn()) {
    LINE_SINK.store(f as usize, core::sync::atomic::Ordering::Relaxed);
}

/// Emit one byte to the debug-output sink (the DOS console mirror uses this to
/// echo program output to the log stream alongside the VGA framebuffer).
pub fn debug_byte(b: u8) {
    stream(b);
}

/// Submit a byte in kernel context. Partial lines stay in the caller's buffer.
/// The output lock covers the complete prefixed line in both the ring and UART.
/// Arch/NMI handlers must not call this blocking kernel logger. Sinks must not
/// recurse into logging; completed-line callbacks run after releasing the lock.
pub fn stream(b: u8) {
    use core::sync::atomic::Ordering;
    let complete = {
        let _guard = OutputGuard::lock();
        let context = LINE_CONTEXT.load(Ordering::Acquire);
        let line = unsafe {
            if context == 0 {
                &mut *core::ptr::addr_of_mut!(FALLBACK_LINE)
            } else {
                let provider: fn() -> *mut LineBuffer = core::mem::transmute(context);
                &mut *provider()
            }
        };
        if b == b'\r' {
            return;
        }
        if b == b'\n' {
            emit_line(line);
            line.len = 0;
            line.truncated = false;
            true
        } else {
            if line.len < line.bytes.len() {
                line.bytes[line.len] = b;
                line.len += 1;
            } else {
                line.truncated = true;
            }
            false
        }
    };
    if complete {
        let p = LINE_SINK.load(Ordering::Acquire);
        if p != 0 {
            let f: fn() = unsafe { core::mem::transmute(p) };
            f();
        }
    }
}

fn emit_line(line: &LineBuffer) {
    use core::sync::atomic::Ordering;
    // Include the prefix in the ring's 512-byte line limit; truncate explicitly.
    let mut record = [0u8; 513];
    let mut n = 0;
    let source = CORE_ID_SOURCE.load(Ordering::Acquire);
    if source != 0 {
        let core_id: fn() -> u32 = unsafe { core::mem::transmute(source) };
        record[..5].copy_from_slice(b"core ");
        n = 5;
        let mut number = core_id();
        let mut digits = [0; 10];
        let mut at = digits.len();
        loop {
            at -= 1;
            digits[at] = b'0' + (number % 10) as u8;
            number /= 10;
            if number == 0 {
                break;
            }
        }
        record[n..n + digits.len() - at].copy_from_slice(&digits[at..]);
        n += digits.len() - at;
        record[n..n + 2].copy_from_slice(b": ");
        n += 2;
    }
    let truncated = line.truncated || line.len > 512 - n;
    let count = line.len.min(512 - n - if truncated { 3 } else { 0 });
    record[n..n + count].copy_from_slice(&line.bytes[..count]);
    n += count;
    if truncated {
        record[n..n + 3].copy_from_slice(b"...");
        n += 3;
    }
    record[n] = b'\n';
    n += 1;
    klog::push_bytes(&record[..n]);
    let sink = DEBUG_SINK.load(Ordering::Acquire);
    if sink != 0 {
        let output: fn(u8) = unsafe { core::mem::transmute(sink) };
        for &byte in &record[..n] {
            output(byte);
        }
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

/// Platform fatal tail. Controlled fatal diagnostics write their message
/// directly to the terminal and log, then call this hook for machine-specific
/// quiescing, stack tracing, final display publication, and halt.
static FATAL_HANDLER: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

pub fn set_fatal_handler(f: fn() -> !) {
    FATAL_HANDLER.store(f as usize, core::sync::atomic::Ordering::Relaxed);
}

#[doc(hidden)]
#[inline(never)]
pub fn finish_fatal() -> ! {
    let p = FATAL_HANDLER.load(core::sync::atomic::Ordering::Relaxed);
    if p != 0 {
        let f: fn() -> ! = unsafe { core::mem::transmute(p) };
        f();
    }
    loop {
        core::hint::spin_loop();
    }
}

#[macro_export]
macro_rules! compact_panic {
    ($($arg:tt)*) => {{
        let __screen = $crate::term::term();
        __screen.clear();
        let _ = compact_fmt::writeln!(__screen, "\x1b[91m!!! FATAL !!!\x1b[0m");
        let __location = ::core::panic::Location::caller();
        let _ = compact_fmt::writeln!(
            __screen,
            "at {}:{}",
            __location.file(),
            __location.line(),
        );
        let _ = compact_fmt::writeln!(__screen, $($arg)*);
        $crate::log::finish_fatal()
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
