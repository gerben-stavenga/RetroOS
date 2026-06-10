//! Host-side VGA text-screen snapshot. DOS programs like DN draw their UI
//! directly into VGA text memory at guest physical `0xB8000` (80x25 cells of
//! char + attribute), bypassing the `0xE9` debug console — so stdout shows
//! nothing. This renders that text buffer to a UTF-8 file (CP437 → Unicode,
//! box-drawing intact) so the headless interpreter's screen is inspectable.
//!
//! Guest RAM is thread-local to the CPU thread, so the actual read happens in
//! `cpu::execute` (which owns the active address space) when `DUMP_REQ` is set;
//! a watcher thread (armed from the hosted `main`) just flips the flag.

use std::io::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

/// Guest physical base of VGA text memory (mode 3, color).
const TEXT_BASE: usize = 0xB8000;
const COLS: usize = 80;
const ROWS: usize = 25;

// ── Live terminal rendering (interactive: drive DN and watch it) ───────────
//
// A full-screen DOS TUI writes its screen straight into VGA text memory; the
// 0xE9 stream only carries line output, not the screen. So to actually *see* the
// guest we paint the 80x25 cell grid to the terminal, in the alternate screen
// buffer, refreshed in place. Rendered on the CPU thread (it reads the active
// guest space), throttled to ~30 fps.

static LIVE: AtomicBool = AtomicBool::new(false);

/// VGA colour index (0..15) → ANSI SGR foreground code. VGA and ANSI order their
/// colours differently (VGA blue=1 vs ANSI blue=34), so this is a remap.
#[rustfmt::skip]
const ANSI_FG: [u8; 16] = [30,34,32,36,31,35,33,37, 90,94,92,96,91,95,93,97];

/// Enter the alternate screen and start live-rendering guest `0xB8000`.
pub fn enable_live() {
    let mut o = std::io::stdout();
    let _ = o.write_all(b"\x1b[?1049h\x1b[2J\x1b[?25l"); // alt screen, clear, hide cursor
    let _ = o.flush();
    LIVE.store(true, Ordering::Relaxed);
    unsafe { libc::atexit(leave_live); }
}

extern "C" fn leave_live() {
    if LIVE.load(Ordering::Relaxed) {
        let mut o = std::io::stdout();
        let _ = o.write_all(b"\x1b[?25h\x1b[?1049l"); // show cursor, leave alt screen
        let _ = o.flush();
    }
}

thread_local! {
    static LAST_RENDER: std::cell::Cell<Option<std::time::Instant>> =
        const { std::cell::Cell::new(None) };
}

/// Render the guest text screen to the terminal (throttled). Called on the CPU
/// thread from `cpu::execute`.
pub fn maybe_render_live() {
    if !LIVE.load(Ordering::Relaxed) {
        return;
    }
    let now = std::time::Instant::now();
    let due = LAST_RENDER.with(|l| match l.get() {
        Some(t) if now.duration_since(t).as_millis() < 33 => false,
        _ => { l.set(Some(now)); true }
    });
    if !due {
        return;
    }

    let mem = crate::vcpu::mem();
    let mut out = String::with_capacity(ROWS * COLS * 4 + 512);
    out.push_str("\x1b[H");
    use std::fmt::Write as _;
    let mut cur_attr = 0xFFFFu16;
    for row in 0..ROWS {
        // Absolute-position each row (the grid is fixed; don't rely on wrap).
        let _ = write!(out, "\x1b[{};1H", row + 1);
        for col in 0..COLS {
            let cell: u16 = mem.read(TEXT_BASE + (row * COLS + col) * 2);
            let attr = cell >> 8;
            if attr != cur_attr {
                let fg = ANSI_FG[(attr & 0xF) as usize];
                let bg = ANSI_FG[((attr >> 4) & 0x7) as usize] + 10;
                let _ = write!(out, "\x1b[0;{};{}m", fg, bg);
                cur_attr = attr;
            }
            out.push(CP437[(cell & 0xFF) as usize]);
        }
    }
    out.push_str("\x1b[0m");
    let mut o = std::io::stdout();
    let _ = o.write_all(out.as_bytes());
    let _ = o.flush();
}

static DUMP_REQ: AtomicBool = AtomicBool::new(false);
static DUMP_PATH: OnceLock<String> = OnceLock::new();

/// Arm snapshotting to `path`. Idempotent; first path wins.
pub fn set_dump_path(path: &str) {
    let _ = DUMP_PATH.set(path.to_string());
}

/// Request a snapshot at the next CPU slice boundary (called off-thread).
pub fn request() {
    DUMP_REQ.store(true, Ordering::Relaxed);
}

/// If a snapshot was requested, render guest `0xB8000` to the dump path. Must be
/// called on the CPU thread (it reads the active guest address space).
pub fn maybe_dump() {
    if !DUMP_REQ.swap(false, Ordering::Relaxed) {
        return;
    }
    let Some(path) = DUMP_PATH.get() else { return };
    // Graphics modes (mode 13h) render to a PPM through the shared VGA renderer;
    // text modes fall through to the CP437 character dump below.
    if crate::vga::try_dump_ppm(path) {
        return;
    }
    let mem = crate::vcpu::mem();
    let mut out = String::with_capacity(ROWS * (COLS + 1));
    for row in 0..ROWS {
        for col in 0..COLS {
            let cell: u16 = mem.read(TEXT_BASE + (row * COLS + col) * 2);
            out.push(CP437[(cell & 0xFF) as usize]);
        }
        out.push('\n');
    }
    let _ = std::fs::write(path, out);
}

/// Code page 437 → Unicode. Control range 0x00-0x1F and 0x7F use their CP437
/// glyphs (DOS text mode renders them); 0x00 maps to space for a clean blank.
#[rustfmt::skip]
const CP437: [char; 256] = [
    ' ','☺','☻','♥','♦','♣','♠','•','◘','○','◙','♂','♀','♪','♫','☼',
    '►','◄','↕','‼','¶','§','▬','↨','↑','↓','→','←','∟','↔','▲','▼',
    ' ','!','"','#','$','%','&','\'','(',')','*','+',',','-','.','/',
    '0','1','2','3','4','5','6','7','8','9',':',';','<','=','>','?',
    '@','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O',
    'P','Q','R','S','T','U','V','W','X','Y','Z','[','\\',']','^','_',
    '`','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o',
    'p','q','r','s','t','u','v','w','x','y','z','{','|','}','~','⌂',
    'Ç','ü','é','â','ä','à','å','ç','ê','ë','è','ï','î','ì','Ä','Å',
    'É','æ','Æ','ô','ö','ò','û','ù','ÿ','Ö','Ü','¢','£','¥','₧','ƒ',
    'á','í','ó','ú','ñ','Ñ','ª','º','¿','⌐','¬','½','¼','¡','«','»',
    '░','▒','▓','│','┤','╡','╢','╖','╕','╣','║','╗','╝','╜','╛','┐',
    '└','┴','┬','├','─','┼','╞','╟','╚','╔','╩','╦','╠','═','╬','╧',
    '╨','╤','╥','╙','╘','╒','╓','╫','╪','┘','┌','█','▄','▌','▐','▀',
    'α','ß','Γ','π','Σ','σ','µ','τ','Φ','Θ','Ω','δ','∞','φ','ε','∩',
    '≡','±','≥','≤','⌠','⌡','÷','≈','°','∙','·','√','ⁿ','²','■',' ',
];
