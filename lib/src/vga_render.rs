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
    /// 8×16 VGA font → 720×400. Read from the linear B8000 window.
    Text80x25,
    /// Mode 13h: 320×200, 8-bit palette index per pixel, chained (linear) at
    /// the start of the A0000 window. Read from linear `vram`.
    Mode13h,
    /// CGA 320×200×4: 2 bits/pixel at B8000, even scanlines at +0x0000 and odd
    /// at +0x2000 (the CGA bank interleave). Fixed CGA palette. Linear `vram`.
    Cga4,
    /// CGA 640×200×2: 1 bit/pixel at B8000, same +0x2000 odd-bank interleave.
    /// Linear `vram`.
    Cga2,
    /// Planar 16-colour (EGA/VGA modes 0Dh/0Eh/10h/12h): 4 bit-planes, one bit
    /// per pixel per plane assembled into a 4-bit attribute → AC palette → DAC.
    /// Read from `planes` (the 4×64K plane-major VGA model). `row_bytes` is the
    /// per-plane bytes per scanline (CRTC offset × 2).
    Planar16 { w: u16, h: u16, row_bytes: u16 },
    /// Unchained 256-colour ("Mode X", 320×240 etc.): 4 planes, pixel x uses
    /// plane `x & 3` at byte `y*row_bytes + x/4`. Read from `planes`.
    ModeX { w: u16, h: u16, row_bytes: u16 },
}

/// One frame's worth of renderable VGA state. Borrowed — the renderer copies
/// nothing it doesn't have to.
pub struct Frame<'a> {
    pub mode: VgaMode,
    /// Linear video memory: the A0000 window (mode 13h) or the B8000 buffer
    /// (text, CGA). Used by the chained/linear modes; planar modes read
    /// `planes` instead. Empty slice is fine for planar-only frames.
    pub vram: &'a [u8],
    /// The 4-plane VGA model: plane-major, plane `p` byte `n` at
    /// `planes[p*0x10000 + n]`. Filled by the emulated VRAM-trap write path
    /// (or a real-card capture). Used by `Planar16`/`ModeX`; empty for the
    /// linear modes.
    pub planes: &'a [u8],
    /// Attribute Controller palette registers 0..15 (planar 16-colour: a
    /// pixel's 4-bit plane value indexes these, each a 6-bit value combined
    /// with the colour-select bits to form the DAC index). Index 16..20 are
    /// mode-control/overscan/etc; the renderer reads [16] (mode control) only
    /// via `blink`. AC[0x14] is the colour-select register.
    pub ac: &'a [u8; 21],
    /// DAC palette: 256 entries × (R,G,B), each component 6-bit (0..63) as the
    /// VGA stores it. Used by all indexed modes.
    pub palette: &'a [u8; 768],
    /// 8×16 glyph bitmap, 256 chars × 16 bytes (one bit per pixel). Required for
    /// text mode; ignored otherwise.
    pub font: &'a [u8],
    /// Attribute bit 7 semantics (AC mode-control bit 3): `true` = blink
    /// (bit 7 ignored here — not animated), `false` = 16 background colors.
    /// TUIs (DN, NC) disable blink via INT 10h AX=1003 to get bright
    /// backgrounds; masking bit 7 away rendered DN's dark-grey panels black.
    pub blink: bool,
}

/// Output framebuffer dimensions for a mode. Text is 80×25 cells of 9×16 px
/// (9 because VGA stretches the 8-px glyph to a 9-dot character clock) → 720×400.
pub const fn dimensions(mode: VgaMode) -> (usize, usize) {
    match mode {
        VgaMode::Mode13h => (320, 200),
        VgaMode::Text80x25 => (720, 400),
        VgaMode::Cga4 => (320, 200),
        VgaMode::Cga2 => (640, 200),
        VgaMode::Planar16 { w, h, .. } => (w as usize, h as usize),
        VgaMode::ModeX { w, h, .. } => (w as usize, h as usize),
    }
}

/// A captured VGA register set, just the fields the renderer needs to classify
/// the active mode and address video memory. The caller fills it from its
/// `VgaState` (or a real card). Keeping classification here — beside the
/// renderer that consumes it — means one source of truth across every consumer
/// (interp window, UEFI GOP, RetroOS-on-metal window compositing).
#[derive(Clone, Copy)]
pub struct Regs {
    /// CRTC registers 0..24 (0x3D4/0x3D5 index/data).
    pub crtc: [u8; 25],
    /// Sequencer registers 0..4 (0x3C4/0x3C5).
    pub seq: [u8; 5],
    /// Graphics Controller registers 0..8 (0x3CE/0x3CF).
    pub gc: [u8; 9],
    /// Miscellaneous Output register (0x3CC read / 0x3C2 write).
    pub misc: u8,
}

/// Derive the renderable `VgaMode` from the captured registers. `bda_mode` is
/// the BIOS-recorded mode byte (BDA 0x449), used only to disambiguate the
/// linear-256 families (BIOS-set mode 13h vs a register-hacked Mode X both
/// look "256-colour"); everything structural comes from the registers, so a
/// game that reprograms the CRTC behind the BIOS's back classifies correctly.
/// Returns `None` for a mode this renderer doesn't draw (e.g. a blanked or
/// mid-reprogram state).
pub fn classify(bda_mode: u8, r: &Regs) -> Option<VgaMode> {
    // GC[6] bit0: 1 = graphics, 0 = alphanumeric (text).
    let graphics = r.gc[6] & 0x01 != 0;
    if !graphics {
        // Registers report text. On a real card / a BIOS that programs the
        // GC, that's authoritative. But an emulated BIOS that only records
        // the mode in the BDA (RetroOS's personality BIOS today) leaves the
        // GC unprogrammed, so a BIOS-set *graphics* mode also lands here —
        // fall back to the BDA mode byte to recover it. Genuine text and
        // BIOS-set 13h both resolve correctly; a program that reprograms the
        // GC for Mode X sets the graphics bit and takes the register path
        // above instead.
        return classify_bda(bda_mode);
    }

    // Resolution from the CRTC display-end registers. Horizontal display end
    // (CRTC[1]) is in character clocks (8 px); vertical display end (CRTC[0x12]
    // plus the two overflow bits in CRTC[7]) is in scanlines.
    let chars = r.crtc[1] as u16 + 1;
    let mut w = chars * 8;
    let v_end = r.crtc[0x12] as u16
        | (((r.crtc[7] >> 1) & 1) as u16) << 8
        | (((r.crtc[7] >> 6) & 1) as u16) << 9;
    let mut h = v_end + 1;
    // Double-scan (CRTC[9] bit7) halves the visible line count (200-line modes
    // program 400 scan lines at 2× each).
    if r.crtc[9] & 0x80 != 0 {
        h /= 2;
    }
    // Per-plane bytes per scanline: CRTC offset (0x13) counts words.
    let row_bytes = (r.crtc[0x13] as u16) * 2;

    // 256-colour: GC[5] bit6 (256-colour shift).
    if r.gc[5] & 0x40 != 0 {
        // Chain-4 (SEQ[4] bit3) → linear mode 13h; unchained → Mode X. In
        // chain-4 the dot clock is halved, so the char count already gives the
        // true pixel width.
        if r.seq[4] & 0x08 != 0 {
            return Some(VgaMode::Mode13h);
        }
        // Mode X width: each char clock is 4 unchained pixels × 2 (the 256-col
        // half-dot-clock), i.e. row_bytes*4 pixels across the 4 planes.
        let xw = row_bytes * 4;
        if xw != 0 {
            w = xw;
        }
        return Some(VgaMode::ModeX { w, h, row_bytes });
    }

    // CGA 4-colour shift (GC[5] bit5): modes 4/5 at B8000.
    if r.gc[5] & 0x20 != 0 {
        return Some(VgaMode::Cga4);
    }
    if matches!(bda_mode, 0x04 | 0x05) {
        return Some(VgaMode::Cga4);
    }
    if bda_mode == 0x06 {
        return Some(VgaMode::Cga2);
    }

    // Planar 16-colour (the EGA/VGA default graphics family).
    Some(VgaMode::Planar16 { w, h, row_bytes })
}

/// Chain-4 deinterleave: spread a linear 64K "chained view" (mode 13h, where
/// the CPU sees byte `n` as pixel `n`) into the 4 planes the way real VGA
/// chain-4 hardware does — byte `n` lives in plane `n & 3` at offset `n >> 2`.
/// Called on a chain→unchain hop so pixels drawn in mode 13h survive into a
/// Mode X view (and on a real-card capture, to normalise either representation
/// into the planes the renderer reads). `chained` is 64K; `planes` is 4×64K
/// plane-major.
pub fn chain4_split(chained: &[u8], planes: &mut [u8]) {
    let n = chained.len().min(0x10000);
    for i in 0..n {
        let plane = i & 3;
        let off = i >> 2;
        if plane * 0x10000 + off < planes.len() {
            planes[plane * 0x10000 + off] = chained[i];
        }
    }
}

/// Chain-4 interleave: the inverse of [`chain4_split`] — gather the 4 planes
/// back into the linear chained view on an unchain→chain hop.
pub fn chain4_merge(planes: &[u8], chained: &mut [u8]) {
    let n = chained.len().min(0x10000);
    for i in 0..n {
        let plane = i & 3;
        let off = i >> 2;
        chained[i] = planes.get(plane * 0x10000 + off).copied().unwrap_or(0);
    }
}

/// Map a BIOS mode number (BDA 0x449) to a renderable mode with that mode's
/// standard geometry. The fallback when the GC isn't programmed (emulated
/// BIOS); also the source of the standard `row_bytes` for the planar modes.
fn classify_bda(bda_mode: u8) -> Option<VgaMode> {
    Some(match bda_mode {
        0x00 | 0x01 | 0x02 | 0x03 | 0x07 => VgaMode::Text80x25,
        0x04 | 0x05 => VgaMode::Cga4,
        0x06 => VgaMode::Cga2,
        0x0D => VgaMode::Planar16 { w: 320, h: 200, row_bytes: 40 },
        0x0E => VgaMode::Planar16 { w: 640, h: 200, row_bytes: 80 },
        0x0F | 0x10 => VgaMode::Planar16 { w: 640, h: 350, row_bytes: 80 },
        0x11 | 0x12 => VgaMode::Planar16 { w: 640, h: 480, row_bytes: 80 },
        0x13 => VgaMode::Mode13h,
        _ => return None,
    })
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
        VgaMode::Cga4 => render_cga4(frame, out, w, h),
        VgaMode::Cga2 => render_cga2(frame, out, w, h),
        VgaMode::Planar16 { row_bytes, .. } => render_planar16(frame, out, w, h, row_bytes as usize),
        VgaMode::ModeX { row_bytes, .. } => render_modex(frame, out, w, h, row_bytes as usize),
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

/// The fixed 4-colour CGA palette (mode 4 palette 1, high-intensity): the
/// canonical cyan/magenta/white set most CGA games use. Index 0 is the
/// background (programmable, but we render the common black).
const CGA4: [u32; 4] = [0x000000, 0x55FFFF, 0xFF55FF, 0xFFFFFF];

/// CGA 320×200×4: 2 bits/pixel at B8000, four pixels per byte (MSB first).
/// Scanlines interleave by bank — even lines at offset 0, odd lines at +0x2000.
fn render_cga4(frame: &Frame, out: &mut [u32], w: usize, h: usize) {
    let vram = frame.vram;
    for y in 0..h {
        let bank = (y & 1) * 0x2000 + (y >> 1) * (w / 4);
        for x in 0..w {
            let byte = match vram.get(bank + x / 4) {
                Some(&b) => b,
                None => continue,
            };
            let shift = 6 - (x & 3) * 2;
            let idx = (byte >> shift) & 0x03;
            out[y * w + x] = CGA4[idx as usize];
        }
    }
}

/// CGA 640×200×2: 1 bit/pixel at B8000, eight pixels per byte, same odd/even
/// bank interleave. White on black.
fn render_cga2(frame: &Frame, out: &mut [u32], w: usize, h: usize) {
    let vram = frame.vram;
    for y in 0..h {
        let bank = (y & 1) * 0x2000 + (y >> 1) * (w / 8);
        for x in 0..w {
            let byte = match vram.get(bank + x / 8) {
                Some(&b) => b,
                None => continue,
            };
            let on = byte & (0x80 >> (x & 7)) != 0;
            out[y * w + x] = if on { 0xFFFFFF } else { 0x000000 };
        }
    }
}

/// Map a planar 4-bit pixel value through the Attribute Controller palette and
/// colour-select register to a DAC index, then to RGB. AC[0..15] supply the
/// low 6 bits; AC[0x14] (colour select) supplies bits 4-5 (P4/P5) and 6-7
/// (P6/P7), gated by the mode-control P5P4-select bit.
#[inline]
fn planar_rgb(frame: &Frame, val: u8) -> u32 {
    let ac = frame.ac;
    let pal = ac[(val & 0x0F) as usize] & 0x3F;
    let csel = ac[0x14];
    // Mode control (AC[0x10]) bit 7: take P4/P5 from colour-select instead of
    // the palette register. Standard 16-colour boot leaves it clear.
    let idx = if ac[0x10] & 0x80 != 0 {
        (pal & 0x0F) | ((csel & 0x03) << 4) | ((csel & 0x0C) << 4)
    } else {
        pal | ((csel & 0x0C) << 4)
    };
    pal_rgb(frame.palette, idx)
}

/// Planar 16-colour: assemble one bit from each of the 4 planes into a 4-bit
/// pixel value. Pixel (x,y) → byte `y*row_bytes + x/8`, bit `7-(x&7)`.
fn render_planar16(frame: &Frame, out: &mut [u32], w: usize, h: usize, row_bytes: usize) {
    let planes = frame.planes;
    let rb = if row_bytes == 0 { w / 8 } else { row_bytes };
    for y in 0..h {
        for x in 0..w {
            let off = y * rb + x / 8;
            let bit = 7 - (x & 7);
            let mut val = 0u8;
            for p in 0..4 {
                let b = planes.get(p * 0x10000 + off).copied().unwrap_or(0);
                val |= ((b >> bit) & 1) << p;
            }
            out[y * w + x] = planar_rgb(frame, val);
        }
    }
}

/// Unchained 256-colour (Mode X): pixel (x,y) is plane `x & 3`, byte
/// `y*row_bytes + x/4`, value indexes the DAC directly.
fn render_modex(frame: &Frame, out: &mut [u32], w: usize, h: usize, row_bytes: usize) {
    let planes = frame.planes;
    let rb = if row_bytes == 0 { w / 4 } else { row_bytes };
    for y in 0..h {
        for x in 0..w {
            let plane = x & 3;
            let off = y * rb + x / 4;
            let idx = planes.get(plane * 0x10000 + off).copied().unwrap_or(0);
            out[y * w + x] = pal_rgb(frame.palette, idx);
        }
    }
}

const TEXT_COLS: usize = 80;
const TEXT_ROWS: usize = 25;
const CELL_W: usize = 9; // 8 glyph + 1 (col 8 repeats col 7 for line-draw)
const CELL_H: usize = 16;

/// 80×25 text: char+attr cells through the 8×16 font. Attribute byte:
/// bits 0-3 = foreground palette index; bits 4-6 = background; bit 7 =
/// blink when `frame.blink`, else background intensity (16 bg colors).
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
    let bg_mask = if frame.blink { 0x07 } else { 0x0F };
    let bg = pal_rgb(frame.palette, (attr >> 4) & bg_mask);
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

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;

    fn regs() -> Regs {
        Regs { crtc: [0; 25], seq: [0; 5], gc: [0; 9], misc: 0 }
    }

    #[test]
    fn classify_text() {
        let mut r = regs();
        r.gc[6] = 0x00; // alphanumeric
        assert_eq!(classify(0x03, &r), Some(VgaMode::Text80x25));
    }

    #[test]
    fn classify_mode13() {
        let mut r = regs();
        r.gc[6] = 0x01; // graphics
        r.gc[5] = 0x40; // 256-colour shift
        r.seq[4] = 0x08; // chain-4
        assert_eq!(classify(0x13, &r), Some(VgaMode::Mode13h));
    }

    #[test]
    fn classify_modex_320x240() {
        let mut r = regs();
        r.gc[6] = 0x01;
        r.gc[5] = 0x40; // 256-colour
        r.seq[4] = 0x00; // NOT chain-4 → unchained
        r.crtc[0x13] = 40; // offset 40 words → 80 bytes/plane row → 320 px
        r.crtc[0x12] = 0xEF; // v-end 239
        r.crtc[7] = 0x00;
        assert_eq!(classify(0x13, &r), Some(VgaMode::ModeX { w: 320, h: 240, row_bytes: 80 }));
    }

    #[test]
    fn classify_ega_planar() {
        let mut r = regs();
        r.gc[6] = 0x01;
        r.gc[5] = 0x00; // not 256, not cga-shift → planar 16
        r.crtc[1] = 39; // 40 chars → 320 px
        r.crtc[0x12] = 199 & 0xFF;
        r.crtc[7] = 0x00; // no overflow bits
        r.crtc[0x13] = 20; // 40 bytes/row
        match classify(0x0D, &r) {
            Some(VgaMode::Planar16 { w, h, row_bytes }) => {
                assert_eq!((w, h, row_bytes), (320, 200, 40));
            }
            other => panic!("expected Planar16, got {:?}", other),
        }
    }

    #[test]
    fn planar16_assembles_planes() {
        // Pixel 0 = colour 5 (planes 0 and 2 set at bit 7).
        let mut planes = vec![0u8; 4 * 0x10000];
        planes[0 * 0x10000 + 0] = 0x80; // plane 0 bit 7
        planes[2 * 0x10000 + 0] = 0x80; // plane 2 bit 7
        let mut ac = [0u8; 21];
        for i in 0..16 { ac[i] = i as u8; }
        let pal = fallback_palette();
        let frame = Frame {
            mode: VgaMode::Planar16 { w: 8, h: 1, row_bytes: 1 },
            vram: &[], planes: &planes, ac: &ac, palette: &pal,
            font: &crate::vga_font_8x16::FONT_8X16, blink: false,
        };
        let mut out = [0u32; 8];
        render(&frame, &mut out);
        assert_eq!(out[0], pal_rgb(&pal, 5)); // colour index 5
        assert_eq!(out[1], pal_rgb(&pal, 0)); // background
    }

    #[test]
    fn chain4_roundtrips() {
        let mut chained = vec![0u8; 0x10000];
        for i in 0..64000 { chained[i] = (i % 251) as u8; }
        let mut planes = vec![0u8; 4 * 0x10000];
        chain4_split(&chained, &mut planes);
        // Byte n must land in plane n&3 at n>>2.
        assert_eq!(planes[0 * 0x10000 + 0], chained[0]);
        assert_eq!(planes[1 * 0x10000 + 0], chained[1]);
        assert_eq!(planes[2 * 0x10000 + 0], chained[2]);
        assert_eq!(planes[3 * 0x10000 + 0], chained[3]);
        assert_eq!(planes[0 * 0x10000 + 1], chained[4]);
        let mut back = vec![0u8; 0x10000];
        chain4_merge(&planes, &mut back);
        assert_eq!(&back[..64000], &chained[..64000]);
    }

    #[test]
    fn modex_plane_select() {
        // Pixels 0..4 live in planes 0..3 at byte 0; set pixel 2 (plane 2) = 7.
        let mut planes = vec![0u8; 4 * 0x10000];
        planes[2 * 0x10000 + 0] = 7;
        let ac = [0u8; 21];
        let pal = fallback_palette();
        let frame = Frame {
            mode: VgaMode::ModeX { w: 4, h: 1, row_bytes: 1 },
            vram: &[], planes: &planes, ac: &ac, palette: &pal,
            font: &crate::vga_font_8x16::FONT_8X16, blink: false,
        };
        let mut out = [0u32; 4];
        render(&frame, &mut out);
        assert_eq!(out[2], pal_rgb(&pal, 7));
        assert_eq!(out[0], pal_rgb(&pal, 0));
    }
}
