//! Host-side VGA text-screen snapshot. DOS programs like DN draw their UI
//! directly into VGA text memory at guest physical `0xB8000` (80x25 cells of
//! char + attribute), bypassing the `0xE9` debug console — so stdout shows
//! nothing. This renders that text buffer to a UTF-8 file (CP437 → Unicode,
//! box-drawing intact) so the headless interpreter's screen is inspectable.
//!
//! Guest RAM is thread-local to the CPU thread, so the actual read happens in
//! `cpu::execute` (which owns the active address space) when `DUMP_REQ` is set;
//! a watcher thread (armed from the hosted `main`) just flips the flag.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

/// Guest physical base of VGA text memory (mode 3, color).
const TEXT_BASE: usize = 0xB8000;
const COLS: usize = 80;
const ROWS: usize = 25;

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
