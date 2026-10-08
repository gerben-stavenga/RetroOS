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

use crate::log::stream;

const WIDTH: usize = 80;
const HEIGHT: usize = 25;
const CELLS: usize = WIDTH * HEIGHT;

/// ANSI escape sequence parser state
#[derive(Clone, Copy, PartialEq)]
enum EscState {
    Normal,
    Escape, // saw ESC
    Csi,    // saw ESC [
    Osc,
    OscEscape,
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
struct SavedScreen {
    grid: [u16; CELLS],
    cursor: (usize, usize),
    attr: u8,
    wrap_pending: bool,
    saved_cursor: (usize, usize),
}

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
    esc_params: [u16; 16],
    esc_index: usize,
    esc_private: bool,
    utf8_value: u32,
    utf8_remaining: u8,
    wrap_pending: bool,
    saved_cursor: (usize, usize),
    primary_screen: Option<SavedScreen>,
    response: [u8; 64],
    response_len: usize,
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
            esc_params: [0; 16],
            esc_index: 0,
            esc_private: false,
            utf8_value: 0,
            utf8_remaining: 0,
            wrap_pending: false,
            saved_cursor: (0, 0),
            primary_screen: None,
            response: [0; 64],
            response_len: 0,
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
            1 => self.attr |= 8,
            22 => self.attr &= !8,
            39 => self.attr = self.attr & 0xf0 | 7,
            49 => self.attr &= 0x0f,
            0 => self.attr = 0x07, // reset
            30..=37 => self.attr = (self.attr & 0xF0) | Self::ansi_to_attr(code - 30, false),
            40..=47 => self.attr = (self.attr & 0x0F) | (Self::ansi_to_attr(code - 40, false) << 4),
            90..=97 => self.attr = (self.attr & 0xF0) | Self::ansi_to_attr(code - 90, true),
            100..=107 => {
                self.attr = (self.attr & 0x0F) | (Self::ansi_to_attr(code - 100, true) << 4)
            }
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
        self.cursor_x = col.min(WIDTH - 1);
        self.cursor_y = row.min(HEIGHT - 1);
        self.wrap_pending = false;
    }

    /// Replace the visible grid from a character/attribute cell buffer.
    /// `cells` is row-major pairs of `(character, attribute)`. This is the
    /// text screen a DOS session is already showing; a cursor-addressed
    /// program cannot be drawn there by streaming bytes through [`putchar`].
    pub fn blit_cells(
        &mut self,
        width: usize,
        height: usize,
        cells: &[u8],
        cursor_col: usize,
        cursor_row: usize,
    ) {
        let w = width.min(WIDTH);
        let h = height.min(HEIGHT);
        let blank = (self.attr as u16) << 8 | b' ' as u16;
        for y in 0..HEIGHT {
            for x in 0..WIDTH {
                let cell = if x < w && y < h {
                    let at = (y * width + x) * 2;
                    let ch = cells.get(at).copied().unwrap_or(b' ');
                    let attr = cells.get(at + 1).copied().unwrap_or(self.attr);
                    (attr as u16) << 8 | ch as u16
                } else {
                    blank
                };
                self.put_cell(y * WIDTH + x, cell);
            }
        }
        self.wrap_pending = false;
        self.cursor_x = cursor_col.min(WIDTH.saturating_sub(1));
        self.cursor_y = cursor_row.min(HEIGHT.saturating_sub(1));
        text_flush();
    }

    pub fn clear(&mut self) {
        let blank = (self.attr as u16) << 8 | b' ' as u16;
        self.grid = [blank; CELLS];
        self.flush_aperture();
        self.cursor_x = 0;
        self.cursor_y = 0;
        self.wrap_pending = false;
    }

    fn scroll(&mut self) {
        let blank = (self.attr as u16) << 8 | b' ' as u16;
        self.grid.copy_within(WIDTH.., 0);
        self.grid[CELLS - WIDTH..].fill(blank);
        self.flush_aperture();
    }

    fn put_display_glyph(&mut self, glyph: u8) {
        if !self.screen_enabled {
            return;
        }
        if self.wrap_pending {
            self.cursor_x = 0;
            self.cursor_y += 1;
            self.wrap_pending = false;
        }
        if self.cursor_y >= HEIGHT {
            self.scroll();
            self.cursor_y = HEIGHT - 1;
        }
        let offset = self.cursor_y * WIDTH + self.cursor_x;
        self.put_cell(offset, (self.attr as u16) << 8 | glyph as u16);
        if self.cursor_x == WIDTH - 1 {
            self.wrap_pending = true;
        } else {
            self.cursor_x += 1;
        }
    }

    /// Linux terminal output is a UTF-8 stream; DOS byte output remains in its
    /// selected codepage. Preserve decoding across write() boundaries.
    pub fn put_utf8(&mut self, byte: u8) {
        if self.esc_state != EscState::Normal && self.utf8_remaining == 0 {
            self.putchar(byte);
            return;
        }
        if self.utf8_remaining != 0 {
            if byte & 0xc0 == 0x80 {
                self.utf8_value = (self.utf8_value << 6) | u32::from(byte & 0x3f);
                self.utf8_remaining -= 1;
                if self.utf8_remaining == 0 {
                    let ch = char::from_u32(self.utf8_value).unwrap_or('�');
                    self.put_display_glyph(crate::codepage::current_codepage().encode_display(ch));
                }
                return;
            }
            self.utf8_remaining = 0;
            self.put_display_glyph(b'?');
        }
        match byte {
            0xc2..=0xdf => {
                self.utf8_value = u32::from(byte & 0x1f);
                self.utf8_remaining = 1;
            }
            0xe0..=0xef => {
                self.utf8_value = u32::from(byte & 0x0f);
                self.utf8_remaining = 2;
            }
            0xf0..=0xf4 => {
                self.utf8_value = u32::from(byte & 7);
                self.utf8_remaining = 3;
            }
            _ => self.putchar(byte),
        }
    }
    /// Drain terminal replies into the owner's input stream.
    pub fn take_response(&mut self, out: &mut [u8]) -> usize {
        let n = self.response_len.min(out.len());
        out[..n].copy_from_slice(&self.response[..n]);
        self.response.copy_within(n..self.response_len, 0);
        self.response_len -= n;
        n
    }
    fn reply(&mut self, bytes: &[u8]) {
        let n = bytes.len().min(self.response.len() - self.response_len);
        self.response[self.response_len..self.response_len + n].copy_from_slice(&bytes[..n]);
        self.response_len += n;
    }
    fn reply_decimal(&mut self, number: usize) {
        if number >= 10 {
            self.reply_decimal(number / 10);
        }
        self.reply(&[b'0' + (number % 10) as u8]);
    }
    fn csi(&mut self, command: u8) {
        let first = usize::from(self.esc_params[0]);
        let count = first.max(1);
        if self.esc_private {
            // Fullscreen terminal applications borrow an alternate screen;
            // leaving it restores the shell's grid and cursor in this same
            // terminal, rather than creating another console window.
            if self.esc_params[..=self.esc_index].contains(&1049) {
                if command == b'h' && self.primary_screen.is_none() {
                    self.primary_screen = Some(SavedScreen {
                        grid: self.grid,
                        cursor: (self.cursor_x, self.cursor_y),
                        attr: self.attr,
                        wrap_pending: self.wrap_pending,
                        saved_cursor: self.saved_cursor,
                    });
                    self.clear();
                } else if command == b'l' && let Some(saved) = self.primary_screen.take() {
                    self.grid = saved.grid;
                    (self.cursor_x, self.cursor_y) = saved.cursor;
                    self.attr = saved.attr;
                    self.wrap_pending = saved.wrap_pending;
                    self.saved_cursor = saved.saved_cursor;
                    self.flush_aperture();
                }
            }
            return;
        } // Unsupported DEC modes have no text payload.
        let blank = u16::from(self.attr) << 8 | u16::from(b' ');
        if matches!(
            command,
            b'H' | b'f' | b'A' | b'B' | b'C' | b'D' | b'G' | b'd'
        ) {
            self.wrap_pending = false;
        }
        match command {
            b'n' if first == 5 => self.reply(b"\x1b[0n"),
            b'n' if first == 6 => {
                self.reply(b"\x1b[");
                self.reply_decimal(self.cursor_y + 1);
                self.reply(b";");
                self.reply_decimal(self.cursor_x + 1);
                self.reply(b"R");
            }
            b'c' if first == 0 => self.reply(b"\x1b[?1;0c"), // Text terminal, no graphics protocols.
            b't' if first == 16 => self.reply(b"\x1b[6;16;9t"), // 80x25 text cells.
            b'H' | b'f' => {
                self.cursor_y = first.max(1).saturating_sub(1).min(HEIGHT - 1);
                self.cursor_x = usize::from(self.esc_params[1])
                    .max(1)
                    .saturating_sub(1)
                    .min(WIDTH - 1);
            }
            b'A' => self.cursor_y = self.cursor_y.saturating_sub(count),
            b'B' => self.cursor_y = (self.cursor_y + count).min(HEIGHT - 1),
            b'C' => self.cursor_x = (self.cursor_x + count).min(WIDTH - 1),
            b'D' => self.cursor_x = self.cursor_x.saturating_sub(count),
            b'G' => self.cursor_x = count.saturating_sub(1).min(WIDTH - 1),
            b'd' => self.cursor_y = count.saturating_sub(1).min(HEIGHT - 1),
            b'J' => {
                let cursor = self.cursor_y * WIDTH + self.cursor_x;
                let range = match first {
                    0 => cursor..CELLS,
                    1 => 0..cursor + 1,
                    2 | 3 => 0..CELLS,
                    _ => 0..0,
                };
                self.grid[range].fill(blank);
                self.flush_aperture();
            }
            b'K' => {
                let row = self.cursor_y * WIDTH;
                let range = match first {
                    0 => row + self.cursor_x..row + WIDTH,
                    1 => row..row + self.cursor_x + 1,
                    2 => row..row + WIDTH,
                    _ => 0..0,
                };
                self.grid[range].fill(blank);
                self.flush_aperture();
            }
            b'm' => {
                let mut i = 0;
                while i <= self.esc_index {
                    let p = self.esc_params[i];
                    if matches!(p, 38 | 48) && i < self.esc_index {
                        let mode = self.esc_params[i + 1];
                        let rgb = if mode == 2 && i + 4 <= self.esc_index {
                            let rgb = [
                                self.esc_params[i + 2].min(255) as u8,
                                self.esc_params[i + 3].min(255) as u8,
                                self.esc_params[i + 4].min(255) as u8,
                            ];
                            i += 4;
                            Some(rgb)
                        } else if mode == 5 && i + 2 <= self.esc_index {
                            let n = self.esc_params[i + 2].min(255) as u8;
                            i += 2;
                            if n < 16 {
                                let color = Self::ansi_to_attr(n & 7, n >= 8);
                                if p == 38 {
                                    self.attr = self.attr & 0xf0 | color;
                                } else {
                                    self.attr = self.attr & 0x0f | color << 4;
                                }
                                None
                            } else if n >= 232 {
                                let v = 8 + (n - 232) * 10;
                                Some([v, v, v])
                            } else {
                                let n = n - 16;
                                let v = |x| if x == 0 { 0 } else { 55 + x * 40 };
                                Some([v(n / 36), v(n / 6 % 6), v(n % 6)])
                            }
                        } else {
                            None
                        };
                        if let Some(rgb) = rgb {
                            let color = nearest_color(rgb);
                            if p == 38 {
                                self.attr = self.attr & 0xf0 | color;
                            } else {
                                self.attr = self.attr & 0x0f | color << 4;
                            }
                        }
                    } else if p <= 255 {
                        self.handle_sgr(p as u8);
                    }
                    i += 1;
                }
            }
            _ => {}
        }
    }
    pub fn putchar(&mut self, c: u8) {
        if !self.screen_enabled {
            return;
        }
        match self.esc_state {
            EscState::Escape => {
                if c == b'[' {
                    self.esc_state = EscState::Csi;
                    self.esc_params.fill(0);
                    self.esc_index = 0;
                    self.esc_private = false;
                } else if matches!(c, b']' | b'_' | b'P' | b'^') {
                    self.esc_state = EscState::Osc;
                } else {
                    if c == b'7' {
                        self.saved_cursor = (self.cursor_x, self.cursor_y);
                    } else if c == b'8' {
                        (self.cursor_x, self.cursor_y) = self.saved_cursor;
                        self.wrap_pending = false;
                    }
                    self.esc_state = EscState::Normal;
                }
                return;
            }
            EscState::Csi => {
                if c.is_ascii_digit() {
                    self.esc_params[self.esc_index] = self.esc_params[self.esc_index]
                        .saturating_mul(10)
                        .saturating_add(u16::from(c - b'0'));
                } else if c == b';' {
                    self.esc_index = (self.esc_index + 1).min(15);
                } else if matches!(c, b'?' | b'>' | b'<' | b'=') {
                    self.esc_private = true;
                } else if (0x40..=0x7e).contains(&c) {
                    self.csi(c);
                    self.esc_state = EscState::Normal;
                }
                return;
            }
            EscState::Osc => {
                if c == 7 {
                    self.esc_state = EscState::Normal;
                } else if c == 0x1b {
                    self.esc_state = EscState::OscEscape;
                }
                return;
            }
            EscState::OscEscape => {
                self.esc_state = if c == b'\\' {
                    EscState::Normal
                } else {
                    EscState::Osc
                };
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
                self.wrap_pending = false;
                self.cursor_x = 0;
                self.cursor_y += 1;
            }
            b'\r' => {
                self.wrap_pending = false;
                self.cursor_x = 0;
            }
            _ => {
                self.put_display_glyph(c);
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

fn nearest_color(rgb: [u8; 3]) -> u8 {
    const VGA: [[u8; 3]; 16] = [
        [0, 0, 0],
        [0, 0, 170],
        [0, 170, 0],
        [0, 170, 170],
        [170, 0, 0],
        [170, 0, 170],
        [170, 85, 0],
        [170, 170, 170],
        [85, 85, 85],
        [85, 85, 255],
        [85, 255, 85],
        [85, 255, 255],
        [255, 85, 85],
        [255, 85, 255],
        [255, 255, 85],
        [255, 255, 255],
    ];
    VGA.iter()
        .enumerate()
        .min_by_key(|(_, color)| {
            (0..3)
                .map(|i| {
                    let d = i32::from(rgb[i]) - i32::from(color[i]);
                    d * d
                })
                .sum::<i32>()
        })
        .map(|(i, _)| i as u8)
        .unwrap_or(7)
}

impl compact_fmt::Write for Term {
    fn write_str(&mut self, text: &str) -> compact_fmt::Result {
        for ch in text.chars() {
            if ch.is_ascii() {
                self.putchar(ch as u8);
            } else {
                self.put_display_glyph(crate::codepage::current_codepage().encode_display(ch));
            }
            let mut utf8 = [0u8; 4];
            for &byte in ch.encode_utf8(&mut utf8).as_bytes() {
                stream(byte);
            }
        }
        text_flush();
        Ok(())
    }
}

// Rust panic messages use core::fmt even though normal console output uses
// compact_fmt. Preserve the same display, log, and flush behavior for both.
impl core::fmt::Write for Term {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        compact_fmt::Write::write_str(self, text).map_err(|_| core::fmt::Error)
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
static TEXT_FLUSH: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

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

/// Write an unformatted line without constructing a formatting argument list.
#[inline(never)]
pub fn screen_text(screen: &mut dyn compact_fmt::Write, text: &str) {
    let _ = screen.write_str(text);
}

/// Print one line to something that writes to the display — the kernel's
/// `Console`, or a bare [`Term`] for an embedder that is alone on the machine.
/// Formatting is compiled to compact bytecode and writes through the small
/// `compact_fmt::Write` interface.
#[macro_export]
macro_rules! screenln {
    ($screen:expr => $machine:expr, $bios:expr) => {{
        let _ = compact_fmt::writeln!($screen, "");
        $screen.present($machine, $bios);
    }};
    ($screen:expr => $machine:expr, $bios:expr; $fmt:literal $($arg:tt)*) => {{
        let _ = compact_fmt::writeln!($screen, $fmt $($arg)*);
        $screen.present($machine, $bios);
    }};
    ($screen:expr) => {{
        $crate::term::screen_text($screen, "\n");
    }};
    ($screen:expr, $text:literal) => {{
        $crate::term::screen_text($screen, ::core::concat!($text, "\n"));
    }};
    ($screen:expr, $fmt:literal $($arg:tt)*) => {{
        let _ = compact_fmt::writeln!($screen, $fmt $($arg)*);
    }};
}

/// Compact primitive formatting to a screen writer.
#[macro_export]
macro_rules! compact_screenln {
    ($screen:expr, $($arg:tt)*) => {{
        let _ = compact_fmt::writeln!($screen, $($arg)*);
    }};
}

/// Optional raw terminal stream for a headless host. This is separate from
/// the kernel debug sink and never feeds KLOG. Graphical/metal consoles render
/// the grid instead and leave this hook unset.
static CONSOLE_SINK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

pub fn set_console_sink(f: fn(u8)) {
    CONSOLE_SINK.store(f as usize, core::sync::atomic::Ordering::Relaxed);
}

/// Write a Linux UTF-8 terminal byte to the console, without logging redraws.
pub fn put_utf8(c: u8) {
    term().put_utf8(c);
    let p = CONSOLE_SINK.load(core::sync::atomic::Ordering::Relaxed);
    if p != 0 {
        let f: fn(u8) = unsafe { core::mem::transmute(p) };
        f(c);
    }
    text_flush();
}

pub fn take_response(out: &mut [u8]) -> usize {
    term().take_response(out)
}
