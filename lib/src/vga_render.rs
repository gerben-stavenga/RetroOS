//! Reusable software-VGA framebuffer renderer.
//!
//! Turns captured VGA state (DAC palette + video memory + mode) into a packed
//! RGB framebuffer (`0x00RRGGBB` per pixel). It is **backend-agnostic** — no
//! `std`, no host libraries — so exactly one renderer serves both the hosted
//! window (the interpreter displaying an emulated VGA) and, later, a windowed-
//! DOS compositor inside RetroOS-on-metal. This is the visual twin of the
//! Sound Blaster's passthrough-vs-emulate split: real VGA when present, this
//! software renderer when emulating or displaying in a window.
//!
//! The caller (the kernel, which owns `VgaState` and can read guest memory)
//! drives it; the backend only has to blit the returned pixels.
//!
//! Modes: mode 13h (linear 320×200×256) and text are implemented; planar
//! EGA/VGA 16-colour and unchained mode X are TODO.
//!
//! The renderer is freestanding: it never allocates. The caller sizes a
//! framebuffer (via [`dimensions`]) and passes it as `&mut [u32]`, so `lib` has
//! no global-allocator dependency (the bootloader links `lib` without one).

/// Which VGA mode the video memory is laid out for. The caller derives this from
/// the CRTC/SEQ/GC registers (or the INT 10h mode set); only the renderable
/// distinctions are named here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VgaMode {
    /// 80×25 text: each cell is (char, attribute) at 2 bytes, rendered with the
    /// 8×16 VGA font → 720×400.
    Text80x25,
    /// Mode 13h: 320×200, 8-bit palette index per pixel, linear (chain-4) at
    /// the start of the A0000 window.
    Mode13h,
}

/// One frame's worth of renderable VGA state. Borrowed — the renderer copies
/// nothing it doesn't have to.
pub struct Frame<'a> {
    pub mode: VgaMode,
    /// Video memory: the A0000 window for graphics, the B8000 text buffer for
    /// text. The renderer reads only what the mode needs.
    pub vram: &'a [u8],
    /// DAC palette: 256 entries × (R,G,B), each component 6-bit (0..63) as the
    /// VGA stores it. Used by indexed modes (mode 13h, text foreground/bg).
    pub palette: &'a [u8; 768],
    /// 8×16 glyph bitmap, 256 chars × 16 bytes (one bit per pixel). Required for
    /// text mode; ignored otherwise.
    pub font: &'a [u8],
}

/// Output framebuffer dimensions for a mode. Text is 80×25 cells of 9×16 px
/// (9 because VGA stretches the 8-px glyph to a 9-dot character clock) → 720×400.
pub const fn dimensions(mode: VgaMode) -> (usize, usize) {
    match mode {
        VgaMode::Mode13h => (320, 200),
        VgaMode::Text80x25 => (720, 400),
    }
}

/// The 16 standard CGA/EGA text colours as 6-bit DAC triples (R,G,B each 0..63),
/// in attribute-index order (0 = black … 15 = white). These occupy DAC entries
/// 0..15 at every text-mode and 16-colour boot; programs that never touch the
/// DAC (the common case for text-mode DOS) render correctly from this alone.
#[rustfmt::skip]
pub const EGA16: [(u8, u8, u8); 16] = [
    ( 0,  0,  0), ( 0,  0, 42), ( 0, 42,  0), ( 0, 42, 42),
    (42,  0,  0), (42,  0, 42), (42, 21,  0), (42, 42, 42),
    (21, 21, 21), (21, 21, 63), (21, 63, 21), (21, 63, 63),
    (63, 21, 21), (63, 21, 63), (63, 63, 21), (63, 63, 63),
];

/// A reasonable 256-entry DAC palette for when the guest hasn't (yet)
/// programmed its own: the 16 EGA colours, a 16-step grey ramp, then a 6×6×6
/// colour cube, with the tail left black. This is *not* the exact IBM VGA
/// power-on palette (which uses an HSV layout); it's a sane fallback so a
/// mode-13h frame captured before the program loads its palette is still
/// legible. Real games reprogram the DAC, overwriting all of this.
pub fn fallback_palette() -> [u8; 768] {
    let mut p = [0u8; 768];
    // 0..15: EGA colours.
    for (i, &(r, g, b)) in EGA16.iter().enumerate() {
        p[i * 3] = r;
        p[i * 3 + 1] = g;
        p[i * 3 + 2] = b;
    }
    // 16..31: grey ramp.
    for i in 0..16usize {
        let v = (i as u8 * 63 / 15) & 0x3F;
        let o = (16 + i) * 3;
        p[o] = v;
        p[o + 1] = v;
        p[o + 2] = v;
    }
    // 32..247: 6×6×6 colour cube (216 entries), 6-bit components.
    let lvl = [0u8, 12, 25, 38, 51, 63];
    let mut idx = 32usize;
    for r in 0..6 {
        for g in 0..6 {
            for b in 0..6 {
                let o = idx * 3;
                p[o] = lvl[r];
                p[o + 1] = lvl[g];
                p[o + 2] = lvl[b];
                idx += 1;
            }
        }
    }
    p
}

/// Expand a 6-bit VGA DAC component (0..63) to 8-bit (0..255).
#[inline]
fn c6to8(v: u8) -> u32 {
    let v = (v & 0x3F) as u32;
    (v << 2) | (v >> 4)
}

/// Pack a palette entry `idx` (0..255) from `palette` into `0x00RRGGBB`.
#[inline]
fn pal_rgb(palette: &[u8; 768], idx: u8) -> u32 {
    let o = idx as usize * 3;
    (c6to8(palette[o]) << 16) | (c6to8(palette[o + 1]) << 8) | c6to8(palette[o + 2])
}

// ── Present sink ─────────────────────────────────────────────────────────────
//
// The display half of the single-VGA design: the kernel emulates the VGA once
// (register file + DAC in the DOS machine layer) and renders here; the
// *platform* only supplies a place for pixels. Same shape as `lib::vga`'s
// debug/flush sinks: a function pointer the platform installs once — the metal
// boot glue points it at the GOP framebuffer blit (fbcon), the hosted binary
// at the window/screenshot frame mailbox. No sink (e.g. legacy metal, where
// the real card displays directly) means `present` is a no-op.

static PRESENT_SINK: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Install the platform's frame sink (`fn(width, height, pixels)`).
pub fn set_present_sink(f: fn(usize, usize, &[u32])) {
    PRESENT_SINK.store(f as usize, core::sync::atomic::Ordering::Relaxed);
}

/// Whether a sink is installed — lets the renderer skip work entirely.
pub fn present_sink_installed() -> bool {
    PRESENT_SINK.load(core::sync::atomic::Ordering::Relaxed) != 0
}

/// Hand a rendered frame (`0x00RRGGBB` pixels, row-major) to the platform.
pub fn present(w: usize, h: usize, px: &[u32]) {
    let p = PRESENT_SINK.load(core::sync::atomic::Ordering::Relaxed);
    if p != 0 {
        let f: fn(usize, usize, &[u32]) = unsafe { core::mem::transmute(p) };
        f(w, h, px);
    }
}

/// Render `frame` into the caller-provided framebuffer `out`, which must be at
/// least `dimensions(frame.mode).0 * .1` pixels (`0x00RRGGBB` each). Returns
/// `(width, height)`. The whole frame area is written (background-cleared first),
/// so the caller need not pre-zero; any slack beyond `w*h` is left untouched.
pub fn render(frame: &Frame, out: &mut [u32]) -> (usize, usize) {
    let (w, h) = dimensions(frame.mode);
    let n = (w * h).min(out.len());
    let out = &mut out[..n];
    for px in out.iter_mut() {
        *px = 0;
    }
    match frame.mode {
        VgaMode::Mode13h => render_mode13(frame, out, w, h),
        VgaMode::Text80x25 => render_text(frame, out, w, h),
    }
    (w, h)
}

/// Mode 13h: one palette index per pixel, linear at the start of vram.
fn render_mode13(frame: &Frame, out: &mut [u32], w: usize, h: usize) {
    let n = (w * h).min(frame.vram.len()).min(out.len());
    for i in 0..n {
        out[i] = pal_rgb(frame.palette, frame.vram[i]);
    }
}

const TEXT_COLS: usize = 80;
const TEXT_ROWS: usize = 25;
const CELL_W: usize = 9; // 8 glyph + 1 (col 8 repeats col 7 for line-draw)
const CELL_H: usize = 16;

/// 80×25 text: char+attr cells through the 8×16 font. Attribute byte is
/// `BBBBFFFF`-ish: bits 0-3 = foreground palette index, bits 4-6 = background
/// (bit 7 = blink, rendered as background bit 3 here — i.e. no blink).
fn render_text(frame: &Frame, out: &mut [u32], w: usize, _h: usize) {
    for row in 0..TEXT_ROWS {
        for col in 0..TEXT_COLS {
            render_text_cell(frame, col, row, out, w);
        }
    }
}

/// Render one text cell (9×16 px) of `frame` into a pitched output buffer.
/// `out` starts at the frame's pixel (0,0); `stride` is the output row pitch
/// in *pixels* (≥ 720), so a caller with a wider target (a GOP framebuffer)
/// can pass a sub-rectangle of it directly — no staging copy. A cell that
/// would overrun `out` is skipped. This is the dirty-cell primitive for
/// incremental console rendering; the full-frame path above is built on it.
pub fn render_text_cell(frame: &Frame, col: usize, row: usize, out: &mut [u32], stride: usize) {
    if frame.font.len() < 256 * 16 || col >= TEXT_COLS || row >= TEXT_ROWS {
        return;
    }
    let cell = (row * TEXT_COLS + col) * 2;
    if cell + 1 >= frame.vram.len() {
        return;
    }
    // Whole-cell bounds up front so the pixel loop can't overrun.
    if (row * CELL_H + CELL_H - 1) * stride + col * CELL_W + CELL_W > out.len() {
        return;
    }
    let ch = frame.vram[cell] as usize;
    let attr = frame.vram[cell + 1];
    let fg = pal_rgb(frame.palette, attr & 0x0F);
    let bg = pal_rgb(frame.palette, (attr >> 4) & 0x07);
    let glyph = &frame.font[ch * 16..ch * 16 + 16];
    for gy in 0..CELL_H {
        let bits = glyph[gy];
        let py = row * CELL_H + gy;
        for gx in 0..CELL_W {
            // Column 8 duplicates column 7 (VGA 9th-dot line-draw rule).
            let bit = if gx < 8 { gx } else { 7 };
            let on = bits & (0x80 >> bit) != 0;
            let px = col * CELL_W + gx;
            out[py * stride + px] = if on { fg } else { bg };
        }
    }
}
