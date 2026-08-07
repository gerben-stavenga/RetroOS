//! A terminal: an 80x25 character grid with a cursor and an ANSI parser.
//!
//! What a terminal is, in the device sense — a byte stream in which text and
//! control travel together, interpreted into cell writes. Cursor position,
//! current attribute, `ESC [ 32 m`, what happens at column 80, and what
//! happens at row 25.
//!
//! Not a console. A console is a *role* — whose display and keyboard these
//! are — and roles are assigned by a kernel, not by a library. Not a VGA
//! either: a VGA has no cursor to track and no line to scroll, it scans bytes
//! out of memory. The card is `//lib:vga`; the two meet only at the aperture
//! this writes cells into.
//!
//! Nor is this where output goes to be *kept* — see [`crate::log`], which is
//! unowned and survives. A terminal's contents scroll away by definition.

use core::fmt::{self, Write};

use crate::log::stream;

const WIDTH: usize = 80;
const HEIGHT: usize = 25;
const CELLS: usize = WIDTH * HEIGHT;

/// ANSI escape sequence parser state
#[derive(Clone, Copy, PartialEq)]
enum EscState {
    Normal,
    Escape,  // saw ESC
    Csi,     // saw ESC [
}

/// A terminal: its grid, its cursor, and where (if anywhere) the cells are
/// mirrored to hardware.
///
/// The grid is 4000 bytes, so nothing here tracks which cells changed — a
/// renderer that wants the screen simply draws all of it.
///
/// The grid is the terminal's own and is the source of truth. That sounds
/// obvious and was not the case: this used to keep no storage at all and write
/// `u16`s straight into whatever address `base` held, so the VGA's memory *was*
/// the terminal's memory. Everything downstream paid for it — a framebuffer
/// machine had to read the cells back and re-render every row to display one
/// character, a hosted machine had to fabricate an aperture for writes nothing
/// would ever read, and nothing could repaint, because after the pixels were
/// overwritten the text was simply gone.
pub struct Term {
    /// 80x25 cells, `attr << 8 | char` — the VGA text encoding, which is this
    /// terminal's format because it is the one hardware wants verbatim.
    grid: [u16; CELLS],
    /// A VGA text aperture to mirror cells into as they are written, when the
    /// machine has one. `None` on a framebuffer or hosted machine, which
    /// render from the grid instead.
    aperture: Option<usize>,
    cursor_x: usize,
    cursor_y: usize,
    attr: u8,
    esc_state: EscState,
    esc_param: u8,
    /// Enable screen buffer writes (disable for early boot debugging)
    pub screen_enabled: bool,
}

impl Term {
    pub const fn new(aperture: Option<usize>) -> Self {
        Self {
            grid: [0x0720; CELLS],
            aperture,
            cursor_x: 0,
            cursor_y: 0,
            attr: 0x07, // LightGray on Black
            esc_state: EscState::Normal,
            esc_param: 0,
            screen_enabled: true,
        }
    }

    /// Convert an ANSI colour code to a VGA text attribute nibble.
    fn ansi_to_attr(code: u8, bright: bool) -> u8 {
        // ANSI: black, red, green, yellow, blue, magenta, cyan, white
        // VGA:  black, blue, green, cyan, red, magenta, brown, lightgray
        const MAP: [u8; 8] = [0, 4, 2, 6, 1, 5, 3, 7];
        MAP[code as usize & 7] + if bright { 8 } else { 0 }
    }

    /// Handle ANSI SGR (Select Graphic Rendition) code
    fn handle_sgr(&mut self, code: u8) {
        match code {
            0 => self.attr = 0x07,  // reset
            30..=37 => self.attr = (self.attr & 0xF0) | Self::ansi_to_attr(code - 30, false),
            40..=47 => self.attr = (self.attr & 0x0F) | (Self::ansi_to_attr(code - 40, false) << 4),
            90..=97 => self.attr = (self.attr & 0xF0) | Self::ansi_to_attr(code - 90, true),
            100..=107 => self.attr = (self.attr & 0x0F) | (Self::ansi_to_attr(code - 100, true) << 4),
            _ => {}
        }
    }

    /// Write one cell into the grid and, if the machine has one, through to
    /// the VGA aperture. Marks the row dirty for whoever renders.
    fn put_cell(&mut self, offset: usize, cell: u16) {
        if offset >= CELLS {
            return;
        }
        self.grid[offset] = cell;
        if let Some(base) = self.aperture {
            unsafe { core::ptr::write_volatile((base as *mut u16).add(offset), cell) };
        }
    }

    /// Copy the whole grid through to the aperture — after a scroll or clear,
    /// where every cell moved.
    fn flush_aperture(&mut self) {
        if let Some(base) = self.aperture {
            for (i, &cell) in self.grid.iter().enumerate() {
                unsafe { core::ptr::write_volatile((base as *mut u16).add(i), cell) };
            }
        }
    }

    /// The grid, for a renderer that draws it.
    pub fn cells(&self) -> &[u16; CELLS] {
        &self.grid
    }

    /// The grid as bytes, in the VGA text layout a renderer expects.
    pub fn cells_bytes(&self) -> &[u8] {
        // `[u16; N]` to `[u8; 2N]`: same allocation, looser alignment.
        unsafe { core::slice::from_raw_parts(self.grid.as_ptr() as *const u8, CELLS * 2) }
    }

    /// Point the terminal at a VGA text aperture (or at nothing), mirroring the
    /// grid into it immediately so the display matches what has been printed.
    pub fn set_aperture(&mut self, aperture: Option<usize>) {
        self.aperture = aperture;
        self.flush_aperture();
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
        self.grid = [blank; CELLS];
        self.flush_aperture();
        self.cursor_x = 0;
        self.cursor_y = 0;
    }

    fn scroll(&mut self) {
        let blank = (self.attr as u16) << 8 | b' ' as u16;
        self.grid.copy_within(WIDTH.., 0);
        self.grid[CELLS - WIDTH..].fill(blank);
        self.flush_aperture();
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
        if self.cursor_y >= HEIGHT {
            self.scroll();
            self.cursor_y = HEIGHT - 1;
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
                let offset = self.cursor_y * WIDTH + self.cursor_x;
                self.put_cell(offset, (self.attr as u16) << 8 | (c as u16));
                self.cursor_x += 1;
                if self.cursor_x >= WIDTH {
                    self.cursor_x = 0;
                    self.cursor_y += 1;
                }
            }
        }

        // Scroll immediately when cursor goes past bottom, so the cursor
        // position is always valid (not deferred to next call).
        if self.cursor_y >= HEIGHT {
            self.scroll();
            self.cursor_y = HEIGHT - 1;
        }
    }
}

impl Write for Term {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            self.putchar(b);
            stream(b);
        }
        text_flush();
        Ok(())
    }
}

static mut TERM: Term = Term::new(Some(0xB8000));

/// Access the global console.
pub fn term() -> &'static mut Term {
    // Bind the raw pointer first, then deref the local: `&mut *(&raw mut VGA)`
    // directly trips clippy::deref_addrof, while `&mut VGA` trips static_mut_refs.
    // Borrowing through a separate raw-pointer local satisfies both.
    let p = &raw mut TERM;
    unsafe { &mut *p }
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
pub(crate) fn text_flush() {
    let p = TEXT_FLUSH.load(core::sync::atomic::Ordering::Relaxed);
    if p != 0 {
        let f: fn() = unsafe { core::mem::transmute(p) };
        f();
    }
}


/// Write one byte to the console: render it to the framebuffer and mirror it to
/// the sink stream. Direct console writers (DOS/Linux `write`) use this.
pub fn putchar(c: u8) {
    term().putchar(c);
    stream(c);
    text_flush();
}


/// Print one line to something that writes to the display — the kernel's
/// `Console`, or a bare [`Term`] for an embedder that is alone on the machine.
/// The only formatted path that draws on screen; everything else logs.
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

