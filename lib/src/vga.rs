//! VGA text mode output
//!
//! Supports both direct physical access (0xB8000) for bootloader
//! and paging-aware access via configurable base address.

use core::fmt::{self, Write};

const VGA_WIDTH: usize = 80;
const VGA_HEIGHT: usize = 25;
const VGA_SIZE: usize = VGA_WIDTH * VGA_HEIGHT;

/// ANSI escape sequence parser state
#[derive(Clone, Copy, PartialEq)]
enum EscState {
    Normal,
    Escape,  // saw ESC
    Csi,     // saw ESC [
}

/// VGA text mode state
pub struct Vga {
    pub base: usize,
    cursor_x: usize,
    cursor_y: usize,
    attr: u8,
    esc_state: EscState,
    esc_param: u8,
    /// Enable screen buffer writes (disable for early boot debugging)
    pub screen_enabled: bool,
}

impl Vga {
    const fn new() -> Self {
        Self {
            base: 0xB8000,
            cursor_x: 0,
            cursor_y: 0,
            attr: 0x07, // LightGray on Black
            esc_state: EscState::Normal,
            esc_param: 0,
            screen_enabled: true,
        }
    }

    /// Convert ANSI color code to VGA color
    fn ansi_to_vga(code: u8, bright: bool) -> u8 {
        // ANSI: black, red, green, yellow, blue, magenta, cyan, white
        // VGA:  black, blue, green, cyan, red, magenta, brown, lightgray
        const MAP: [u8; 8] = [0, 4, 2, 6, 1, 5, 3, 7];
        MAP[code as usize & 7] + if bright { 8 } else { 0 }
    }

    /// Handle ANSI SGR (Select Graphic Rendition) code
    fn handle_sgr(&mut self, code: u8) {
        match code {
            0 => self.attr = 0x07,  // reset
            30..=37 => self.attr = (self.attr & 0xF0) | Self::ansi_to_vga(code - 30, false),
            40..=47 => self.attr = (self.attr & 0x0F) | (Self::ansi_to_vga(code - 40, false) << 4),
            90..=97 => self.attr = (self.attr & 0xF0) | Self::ansi_to_vga(code - 90, true),
            100..=107 => self.attr = (self.attr & 0x0F) | (Self::ansi_to_vga(code - 100, true) << 4),
            _ => {}
        }
    }

    fn buffer(&mut self) -> &mut [u16] {
        unsafe { core::slice::from_raw_parts_mut(self.base as *mut u16, VGA_SIZE) }
    }

    /// Returns (column, row) cursor position.
    pub fn cursor_pos(&self) -> (usize, usize) {
        (self.cursor_x, self.cursor_y)
    }

    /// Sets the cursor position.
    pub fn set_cursor_pos(&mut self, col: usize, row: usize) {
        self.cursor_x = col;
        self.cursor_y = row;
    }

    pub fn clear(&mut self) {
        let blank = (self.attr as u16) << 8 | b' ' as u16;
        for cell in self.buffer() {
            *cell = blank;
        }
        self.cursor_x = 0;
        self.cursor_y = 0;
    }

    fn scroll(&mut self) {
        let blank = (self.attr as u16) << 8 | b' ' as u16;
        let buffer = self.buffer();
        buffer.copy_within(VGA_WIDTH.., 0);
        buffer[VGA_SIZE - VGA_WIDTH..].fill(blank);
    }

    pub fn putchar(&mut self, c: u8) {
        if !self.screen_enabled {
            return;
        }

        // Handle ANSI escape sequences
        match self.esc_state {
            EscState::Escape => {
                if c == b'[' {
                    self.esc_state = EscState::Csi;
                    self.esc_param = 0;
                } else {
                    self.esc_state = EscState::Normal;
                }
                return;
            }
            EscState::Csi => {
                if c.is_ascii_digit() {
                    self.esc_param = self.esc_param.saturating_mul(10).saturating_add(c - b'0');
                } else if c == b';' {
                    // Multi-parameter SGR (e.g. `\e[01;34m`): apply the
                    // accumulated param now and start collecting the next.
                    self.handle_sgr(self.esc_param);
                    self.esc_param = 0;
                } else if c == b'm' {
                    self.handle_sgr(self.esc_param);
                    self.esc_state = EscState::Normal;
                } else {
                    self.esc_state = EscState::Normal;
                }
                return;
            }
            EscState::Normal => {}
        }

        // Scroll before writing so we never index past the buffer end.
        if self.cursor_y >= VGA_HEIGHT {
            self.scroll();
            self.cursor_y = VGA_HEIGHT - 1;
        }

        match c {
            0x1b => {
                self.esc_state = EscState::Escape;
            }
            b'\n' => {
                self.cursor_x = 0;
                self.cursor_y += 1;
            }
            b'\r' => {
                self.cursor_x = 0;
            }
            _ => {
                let offset = self.cursor_y * VGA_WIDTH + self.cursor_x;
                self.buffer()[offset] = (self.attr as u16) << 8 | (c as u16);
                self.cursor_x += 1;
                if self.cursor_x >= VGA_WIDTH {
                    self.cursor_x = 0;
                    self.cursor_y += 1;
                }
            }
        }

        // Scroll immediately when cursor goes past bottom, so the cursor
        // position is always valid (not deferred to next call).
        if self.cursor_y >= VGA_HEIGHT {
            self.scroll();
            self.cursor_y = VGA_HEIGHT - 1;
        }
    }
}

/// The license to render kernel text on the display, tracked purely by move
/// semantics — no flag, no registry, no global. The platform entry constructs
/// exactly one and the boot call chain owns it (bootloader / `boot_kernel` →
/// `startup`); while a user program runs, `startup` holds the value without
/// writing, so kernel logs cannot trample the user's framebuffer (in CGA/EGA
/// graphics modes the same B8000 bytes are the program's pixel data). A call
/// site without the value simply has no way to draw: the ambient `println!` /
/// `dbg_println!` macros feed only the log stream.
///
/// Diverging paths — panic, SHUTDOWN — construct their own writer instead of
/// reaching for the holder: the ownership rules protect a *running* program's
/// screen, and theirs is dead, never to run again.
///
/// A focused program's own console output (`putchar` / DOS teletype) is the
/// program writing its own screen and takes no license.
pub struct Screen(());

impl Screen {
    /// See the type docs: platform entry (once per boot) and diverging
    /// paths (panic/shutdown) only.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Screen(())
    }

    /// Reset to a blank screen. Panic/shutdown banners start clean: the cells
    /// hold whatever the previous owner drew — raw pixel bytes, if it died in
    /// a graphics mode.
    pub fn clear(&mut self) {
        let v = vga();
        v.attr = 0x07;
        v.clear();
    }
}

impl Write for Screen {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            vga().putchar(b);
            stream(b);
        }
        text_flush();
        Ok(())
    }
}

/// Global VGA state
static mut VGA: Vga = Vga::new();

/// Access the global VGA state
pub fn vga() -> &'static mut Vga {
    // Bind the raw pointer first, then deref the local: `&mut *(&raw mut VGA)`
    // directly trips clippy::deref_addrof, while `&mut VGA` trips static_mut_refs.
    // Borrowing through a separate raw-pointer local satisfies both.
    let p = &raw mut VGA;
    unsafe { &mut *p }
}

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
// crate — share one sink and one set of macros. `lib::vga` itself only renders
// the framebuffer; the byte sink is the function pointer below.

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

/// Post-write console-flush hook (`fn()` as its address; 0 = none). On machines
/// whose text cells are not themselves the display — a GOP linear framebuffer
/// with no VGA text mode — the platform installs a renderer here that pushes
/// the dirty cells to pixels after each console write. Same shape as
/// `DEBUG_SINK`: an atomic load + indirect call, panic-safe.
static TEXT_FLUSH: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Install the post-write console-flush hook.
pub fn set_text_flush(f: fn()) {
    TEXT_FLUSH.store(f as usize, core::sync::atomic::Ordering::Relaxed);
}

#[inline]
fn text_flush() {
    let p = TEXT_FLUSH.load(core::sync::atomic::Ordering::Relaxed);
    if p != 0 {
        let f: fn() = unsafe { core::mem::transmute(p) };
        f();
    }
}

#[inline]
fn stream(b: u8) {
    let p = DEBUG_SINK.load(core::sync::atomic::Ordering::Relaxed);
    if p != 0 {
        let f: fn(u8) = unsafe { core::mem::transmute(p) };
        f(b);
    }
}

/// Write one byte to the console: render it to the framebuffer and mirror it to
/// the sink stream. Direct console writers (DOS/Linux `write`) use this.
pub fn putchar(c: u8) {
    vga().putchar(c);
    stream(c);
    text_flush();
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
/// screen: on-screen text requires holding the [`Screen`] value — use
/// `screenln!`. (Kept alongside `dbg_print!` so the kernel's existing log
/// call sites keep compiling; the two are now synonyms.)
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = $crate::vga::DebugCon.write_fmt(format_args!($($arg)*));
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

/// Print one line through an owned [`Screen`]: renders to the display and
/// mirrors to the log stream. The only formatted path that draws on screen.
#[macro_export]
macro_rules! screenln {
    ($screen:expr) => {{
        use core::fmt::Write;
        let _ = ::core::writeln!($screen);
    }};
    ($screen:expr, $($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = ::core::writeln!($screen, $($arg)*);
    }};
}

/// Print to the debug console (sink) only, never the framebuffer.
#[macro_export]
macro_rules! dbg_print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = $crate::vga::DebugCon.write_fmt(format_args!($($arg)*));
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
