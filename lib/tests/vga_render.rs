//! Tests for the reusable software-VGA renderer. These run as an ordinary std
//! binary (the test harness supplies the global allocator the `#![no_std]` lib
//! lacks), exercising the pure render path on synthetic VGA state.

use lib::vga_render::{self, Frame, VgaMode};

/// 6-bit DAC component → 8-bit, matching the renderer's expansion.
fn c6to8(v: u8) -> u32 {
    let v = (v & 0x3F) as u32;
    (v << 2) | (v >> 4)
}

fn pal_rgb(pal: &[u8; 768], idx: u8) -> u32 {
    let o = idx as usize * 3;
    (c6to8(pal[o]) << 16) | (c6to8(pal[o + 1]) << 8) | c6to8(pal[o + 2])
}

fn identity_ac() -> [u8; 21] {
    let mut ac = [0u8; 21];
    for i in 0..16 {
        ac[i] = i as u8;
    }
    ac
}

#[test]
fn dimensions_match_modes() {
    assert_eq!(vga_render::dimensions(VgaMode::Mode13h), (320, 200));
    assert_eq!(vga_render::dimensions(VgaMode::Text80x25), (720, 400));
}

#[test]
fn mode13h_maps_each_index_through_the_palette() {
    // A palette where index i → grey (i,i,i) keeps the mapping trivial to check.
    let mut pal = [0u8; 768];
    for i in 0..256usize {
        let v = (i as u8) & 0x3F;
        pal[i * 3] = v;
        pal[i * 3 + 1] = v;
        pal[i * 3 + 2] = v;
    }
    // VRAM: a horizontal index ramp on the first row, rest zero.
    let mut vram = vec![0u8; 320 * 200];
    for x in 0..320usize {
        vram[x] = (x & 0xFF) as u8;
    }
    let ac = identity_ac();
    let frame = Frame {
        mode: VgaMode::Mode13h,
        vram: &vram,
        planes: &[],
        ac: &ac,
        palette: &pal,
        font: &[],
        blink: false,
        start_offset: 0,
        pixel_pan: 0,
        line_compare: usize::MAX,
    };
    let mut out = vec![0u32; 320 * 200];
    let (w, h) = vga_render::render(&frame, &mut out);
    assert_eq!((w, h), (320, 200));
    for x in 0..320usize {
        assert_eq!(out[x], pal_rgb(&pal, (x & 0xFF) as u8), "pixel {x}");
    }
    // Index 0 → black everywhere on row 1.
    assert_eq!(out[320], pal_rgb(&pal, 0));
}

#[test]
fn mode13h_tolerates_short_vram() {
    // Fewer bytes than the frame must not panic; the tail stays the cleared 0.
    let vram = vec![7u8; 100];
    let pal = vga_render::fallback_palette();
    let ac = identity_ac();
    let frame = Frame {
        mode: VgaMode::Mode13h,
        vram: &vram,
        planes: &[],
        ac: &ac,
        palette: &pal,
        font: &[],
        blink: false,
        start_offset: 0,
        pixel_pan: 0,
        line_compare: usize::MAX,
    };
    let mut out = vec![0u32; 320 * 200];
    let (w, h) = vga_render::render(&frame, &mut out);
    assert_eq!((w, h), (320, 200));
    assert_eq!(out[0], pal_rgb(&pal, 7));
    assert_eq!(out[200], pal_rgb(&pal, 0)); // past the supplied bytes
}

#[test]
fn text_renders_glyph_pixels_with_fg_bg() {
    // One glyph (index 1) that is all-bits-set on every scanline → a solid
    // foreground block; cell attribute fg=15 (white) on bg=1 (blue).
    let mut font = vec![0u8; 256 * 16];
    for b in &mut font[1 * 16..1 * 16 + 16] {
        *b = 0xFF;
    }
    // 80×25 cells; put char 1 / attr 0x1F at cell (0,0), leave the rest blank.
    let mut vram = vec![0u8; 80 * 25 * 2];
    vram[0] = 1;
    vram[1] = 0x1F;
    let pal = vga_render::fallback_palette();
    let ac = identity_ac();
    let frame = Frame {
        mode: VgaMode::Text80x25,
        vram: &vram,
        planes: &[],
        ac: &ac,
        palette: &pal,
        font: &font,
        blink: false,
        start_offset: 0,
        pixel_pan: 0,
        line_compare: usize::MAX,
    };
    let mut out = vec![0u32; 720 * 400];
    let (w, h) = vga_render::render(&frame, &mut out);
    assert_eq!((w, h), (720, 400));
    let fg = pal_rgb(&pal, 15);
    let bg = pal_rgb(&pal, 1);
    // Glyph is solid: every pixel of the 9×16 top-left cell is foreground.
    for y in 0..16usize {
        for x in 0..9usize {
            assert_eq!(out[y * w + x], fg, "cell0 px ({x},{y})");
        }
    }
    let _ = bg;
    // A blank cell (char 0, attr 0) renders all-background = palette index 0.
    let c1 = 9; // cell (1,0) starts at x=9
    assert_eq!(out[c1], pal_rgb(&pal, 0));
}

#[test]
fn fallback_palette_has_ega_colors_first() {
    let pal = vga_render::fallback_palette();
    // Entry 15 is white (63,63,63); entry 1 is blue (0,0,42).
    assert_eq!((pal[15 * 3], pal[15 * 3 + 1], pal[15 * 3 + 2]), (63, 63, 63));
    assert_eq!((pal[1 * 3], pal[1 * 3 + 1], pal[1 * 3 + 2]), (0, 0, 42));
}
