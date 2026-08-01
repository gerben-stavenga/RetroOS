//! Tests for the reusable software-VGA renderer. These run as an ordinary std
//! binary (the test harness supplies the global allocator the `#![no_std]` lib
//! lacks), exercising the pure render path on synthetic VGA state.

use lib::vga_render::{self, Frame, PixelFormat, VgaMode};

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
fn chain4_roundtrips_between_linear_aperture_and_planes() {
    let mut chained = vec![0u8; 0x10000];
    for (i, byte) in chained.iter_mut().enumerate().take(64000) {
        *byte = (i % 251) as u8;
    }

    let mut planes = vec![0xA5u8; 4 * 0x10000];
    vga_render::chain4_split(&chained, &mut planes);
    assert_eq!(planes[0], chained[0]);
    assert_eq!(planes[0x10000], chained[1]);
    assert_eq!(planes[0x20000], chained[2]);
    assert_eq!(planes[0x30000], chained[3]);
    assert_eq!(planes[1], chained[4]);

    let mut back = vec![0u8; 0x10000];
    vga_render::chain4_merge(&planes, &mut back);
    assert_eq!(back, chained);
}

#[test]
fn text_odd_even_roundtrips_without_touching_other_plane_data() {
    let mut text = vec![0u8; 0x8000];
    for i in 0..0x4000 {
        text[i * 2] = (i % 251) as u8;
        text[i * 2 + 1] = (i % 16) as u8;
    }

    let mut planes = vec![0xA5u8; 4 * 0x10000];
    vga_render::text_odd_even_split(&text, &mut planes);
    assert_eq!(planes[0], text[0]);
    assert_eq!(planes[0x10000], text[1]);
    assert_eq!(planes[2], text[2]);
    assert_eq!(planes[0x10002], text[3]);
    assert_eq!(planes[0x7FFE], text[0x7FFE]);
    assert_eq!(planes[0x17FFE], text[0x7FFF]);
    assert_eq!(planes[1], 0xA5);
    assert_eq!(planes[0x10001], 0xA5);
    assert_eq!(planes[0x8000], 0xA5);
    assert_eq!(planes[0x20000], 0xA5);

    let mut back = vec![0u8; 0x8000];
    vga_render::text_odd_even_merge(&planes, &mut back);
    assert_eq!(back, text);
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
    let mut frame = Frame {
        mode: VgaMode::Mode13h,
        vram: &vram,
        planes: &[],
        ac: &ac,
        palette: &pal,
        dac_mask: 0xFF,
        font: &[],
        blink: false,
        cga_palette: [0; 4],
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

    // PEL mask 0x0F aliases index 0x21 to DAC entry 0x01.
    frame.dac_mask = 0x0F;
    vga_render::render(&frame, &mut out);
    assert_eq!(out[0x21], pal_rgb(&pal, 0x01));
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
        dac_mask: 0xFF,
        font: &[],
        blink: false,
        cga_palette: [0; 4],
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
    // Two solid (all-bits-set) glyphs: char 1 (a normal glyph) and char 0xC4 (a
    // line-draw glyph in the 0xC0..=0xDF block). Cell attribute fg=15 (white) on
    // bg=1 (blue).
    let mut font = vec![0u8; 256 * 16];
    for b in &mut font[16..16 + 16] {
        *b = 0xFF;
    }
    for b in &mut font[0xC4 * 16..0xC4 * 16 + 16] {
        *b = 0xFF;
    }
    // 80×25 cells: char 1 at (0,0), a blank at (1,0), char 0xC4 at (2,0).
    let mut vram = vec![0u8; 80 * 25 * 2];
    vram[0] = 1;
    vram[1] = 0x1F;
    vram[4] = 0xC4;
    vram[5] = 0x1F;
    let pal = vga_render::fallback_palette();
    let ac = identity_ac();
    let frame = Frame {
        mode: VgaMode::Text80x25,
        vram: &vram,
        planes: &[],
        ac: &ac,
        palette: &pal,
        dac_mask: 0xFF,
        font: &font,
        blink: false,
        cga_palette: [0; 4],
        start_offset: 0,
        pixel_pan: 0,
        line_compare: usize::MAX,
    };
    let mut out = vec![0u32; 720 * 400];
    let (w, h) = vga_render::render(&frame, &mut out);
    assert_eq!((w, h), (720, 400));
    let fg = pal_rgb(&pal, 15);
    let bg = pal_rgb(&pal, 1);
    // Char 1 (not a line-draw code): columns 0..8 are foreground, and the 9th
    // column (x=8) is BLANK background — inter-character spacing, not a replica
    // of column 8.
    for y in 0..16usize {
        for x in 0..8usize {
            assert_eq!(out[y * w + x], fg, "cell0 px ({x},{y})");
        }
        assert_eq!(out[y * w + 8], bg, "cell0 9th-dot must be spacing ({y})");
    }
    // Char 0xC4 (line-draw block): the 9th column (x = 2*9 + 8 = 26) DOES repeat
    // column 8, so horizontal box rules join across cells.
    for y in 0..16usize {
        assert_eq!(out[y * w + 26], fg, "cell2 9th-dot must replicate ({y})");
    }
    // A blank cell (char 0, attr 0) renders all-background = palette index 0.
    assert_eq!(out[9], pal_rgb(&pal, 0)); // cell (1,0) starts at x=9
}

#[test]
fn fallback_palette_has_ega_colors_first() {
    let pal = vga_render::fallback_palette();
    // Entry 15 is white (63,63,63); entry 1 is blue (0,0,42).
    assert_eq!((pal[15 * 3], pal[15 * 3 + 1], pal[15 * 3 + 2]), (63, 63, 63));
    assert_eq!((pal[3], pal[3 + 1], pal[3 + 2]), (0, 0, 42));
}

#[test]
fn packed_stretch_rows_match_for_16_24_and_32_bit_outputs() {
    let mut palette = [0u8; 768];
    for i in 0..256usize {
        palette[i * 3] = (i & 63) as u8;
        palette[i * 3 + 1] = ((i * 3) & 63) as u8;
        palette[i * 3 + 2] = ((i * 5) & 63) as u8;
    }
    // A full mode-13h page, so the last row reads real pixels rather than
    // falling off the end into index 0 (which would compare black to black).
    let vram: Vec<u8> = (0..320 * 200).map(|i| (i % 320 & 255) as u8).collect();
    let ac = identity_ac();
    let frame = Frame {
        mode: VgaMode::Mode13h,
        vram: &vram,
        planes: &[],
        ac: &ac,
        palette: &palette,
        dac_mask: 0xFF,
        font: &[],
        blink: false,
        cga_palette: [0; 4],
        start_offset: 0,
        pixel_pan: 0,
        line_compare: usize::MAX,
    };
    let formats = [
        PixelFormat::from_rgb(2, [11, 5, 5, 6, 0, 5]).unwrap(),
        PixelFormat::from_rgb(3, [16, 8, 8, 8, 0, 8]).unwrap(),
        PixelFormat::NATIVE,
    ];
    let out_w = 643usize; // non-integral 643/320 exercises the DDA carry
    let sy = 199usize; // the LAST row: its final stores land in the slack
    for fmt in formats {
        let step = fmt.bytes_per_pixel as usize;
        let n = out_w.div_ceil(320);
        // The whole shadow, exactly as the raster allocates it.
        let mut out = vec![0u8; out_w * step * 200 + n * 4];
        let mut pal = vga_render::Pal::new();
        let mut cache = [0u8; 768];
        pal.sync(&palette, 0xFF, fmt, &mut cache);
        vga_render::render_row_stretched(&frame, sy, &pal, &mut out, out_w);
        let row = &out[sy * out_w * step..];

        let (base, rem) = (out_w / 320, out_w % 320);
        let (mut xout, mut err) = (0usize, 0usize);
        for (x, &idx) in vram[sy * 320..(sy + 1) * 320].iter().enumerate() {
            err += rem;
            let carry = (err >= 320) as usize;
            err -= carry * 320;
            let run = base + carry;
            let expected = fmt.encode(pal_rgb(&palette, idx)).to_le_bytes();
            for p in xout..xout + run {
                assert_eq!(
                    &row[p * step..p * step + step],
                    &expected[..step],
                    "{step}-byte output, source {x}, output {p}"
                );
            }
            xout += run;
        }
        assert_eq!(xout, out_w);
        // Only row `sy` was asked for, so every earlier row must be untouched.
        assert!(out[..sy * out_w * step].iter().all(|&b| b == 0));
    }
}

#[test]
fn overlay_x_projection_scales_fills_and_glyph_pixels() {
    let (w, h, logical_w) = (16usize, 16usize, 8usize);
    let mut out = vec![0u8; w * h * 4];
    let pixel = |buf: &[u8], x: usize, y: usize| {
        let o = (y * w + x) * 4;
        u32::from_le_bytes(buf[o..o + 4].try_into().unwrap())
    };

    // Logical [2,4) maps exactly to packed-shadow [4,8).
    vga_render::overlay_fill_xscaled(
        &mut out,
        w * 4,
        w,
        h,
        logical_w,
        2,
        0,
        2,
        1,
        0x0012_3456,
        PixelFormat::NATIVE,
    );
    assert_eq!(pixel(&out, 3, 0), 0);
    for x in 4..8 {
        assert_eq!(pixel(&out, x, 0), 0x0012_3456);
    }
    assert_eq!(pixel(&out, 8, 0), 0);

    out.fill(0);
    let ch = b'A';
    let glyph = &lib::vga_fonts::FONT_8X16[ch as usize * 16..ch as usize * 16 + 16];
    vga_render::overlay_text_xscaled(
        &mut out,
        w * 4,
        w,
        h,
        logical_w,
        0,
        0,
        &[ch],
        0x00AA_5500,
        0x0000_0011,
        PixelFormat::NATIVE,
    );
    for (y, &bits) in glyph.iter().enumerate() {
        for gx in 0..8 {
            let want = if bits & (0x80 >> gx) != 0 {
                0x00AA_5500
            } else {
                0x0000_0011
            };
            assert_eq!(pixel(&out, gx * 2, y), want);
            assert_eq!(pixel(&out, gx * 2 + 1, y), want);
        }
    }
}
