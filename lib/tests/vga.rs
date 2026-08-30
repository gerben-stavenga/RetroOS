//! Tests for the VGA: mode classification, the plane ALU, and scanout. These run as an ordinary std
//! binary (the test harness supplies the global allocator the `#![no_std]` lib
//! lacks), exercising the pure render path on synthetic VGA state.

use vga::{self as vga_render, Frame, PixelFormat, VgaMode, VramLayout, VramTransition};

const TEXT80: VgaMode = VgaMode::Text { cols: 80, rows: 25, cell_w: 9, cell_h: 16 };
const TEXT40: VgaMode = VgaMode::Text { cols: 40, rows: 25, cell_w: 18, cell_h: 16 };

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
    assert_eq!(vga_render::dimensions(TEXT80), (720, 400));
    assert_eq!(vga_render::dimensions(TEXT40), (720, 400));
}

#[test]
fn bios_text_geometry_comes_from_registers() {
    assert_eq!(vga_render::classify(&vga_render::bios_mode_regs(1).unwrap()), Some(TEXT40));
    assert_eq!(vga_render::classify(&vga_render::bios_mode_regs(3).unwrap()), Some(TEXT80));
}

#[test]
fn standard_text_requires_live_mode3_environment() {
    let r = vga_render::bios_mode_regs(3).unwrap();
    assert!(vga_render::is_standard_text(&r));
    assert!(!vga_render::is_standard_text(
        &vga_render::bios_mode_regs(0x13).unwrap(),
    ));

    let mut screen_off = r;
    screen_off.seq[1] |= 0x20;
    assert!(!vga_render::is_standard_text(&screen_off));
}

#[test]
fn initial_mode3_state_is_complete() {
    let state = vga_render::VgaState::new_mode3_boxed();
    assert_eq!(state.classify_mode(), Some(TEXT80));
    assert_eq!(state.planes.len(), 4 * 0x10000);

    let mut text = vec![0u8; 80 * 25 * 2];
    text.copy_from_slice(&state.planes[..80 * 25 * 2]);
    assert!(text.chunks_exact(2).all(|cell| cell == [b' ', 0x07]));

    for ch in 0..256 {
        let font = ch * 16;
        for row in 0..16 {
            assert_eq!(
                state.planes[state.layout().index(2, ch * 32 + row)],
                lib::vga_fonts::FONT_8X16[font + row],
            );
        }
    }
}

#[test]
fn complete_layout_transition_is_reversible() {
    let mut planes = vec![0u8; 4 * 0x10000];
    for plane in 0..4 {
        for off in 0..0x10000 {
            planes[VramLayout::PlaneMinor.index(plane, off)] = (plane as u8).wrapping_mul(61)
                ^ (off as u8).wrapping_mul(17)
                ^ (off >> 8) as u8;
        }
    }
    let original = planes.clone();
    VramTransition::between(VramLayout::PlaneMinor, VramLayout::OddEven)
        .apply(&mut planes);
    for plane in 0..4 {
        for off in 0..0x10000 {
            assert_eq!(
                planes[VramLayout::OddEven.index(plane, off)],
                original[VramLayout::PlaneMinor.index(plane, off)],
            );
        }
    }
    VramTransition::between(VramLayout::OddEven, VramLayout::PlaneMinor)
        .apply(&mut planes);
    assert_eq!(planes, original);
}

#[test]
fn both_layouts_are_complete_bijections() {
    for layout in [VramLayout::PlaneMinor, VramLayout::OddEven] {
        let mut seen = vec![false; 4 * 0x10000];
        for plane in 0..4 {
            for off in 0..0x10000 {
                let index = layout.index(plane, off);
                assert!(index < seen.len() && !seen[index]);
                seen[index] = true;
            }
        }
        assert!(seen.into_iter().all(|v| v));
    }
}

#[test]
fn register_writes_move_vram_with_the_cpu_aperture() {
    let mut state = *vga::VgaState::new_mode3_boxed();
    let mut vram = state.planes.clone();
    // Materializing mode 3 produces the complete odd/even ordering. Its first
    // 32K is exactly the B800 CPU view, while plane set 2/3 remains preserved
    // in the second 128K.
    assert_eq!(state.layout(), VramLayout::OddEven);
    for cell in 0..80 * 25 {
        assert_eq!(vram[cell * 2], b' ');
        assert_eq!(vram[cell * 2 + 1], 0x07);
    }

    // IT temporarily selects sequential plane access while loading character
    // maps. Trapping can address the current complete ordering directly, so a
    // register write does not reorder all VRAM.
    state.port_write(0x3C4, 4);
    let write = state.port_write(0x3C5, 0x04);
    assert!(matches!(write.new_aperture, vga::CpuAperture::Trapped { .. }));
    assert_eq!(write.vram_transition, Some(VramTransition::between(
        VramLayout::OddEven,
        VramLayout::PlaneMinor,
    )));
    write.vram_transition.unwrap().apply(&mut vram);
    assert_eq!(state.layout(), VramLayout::PlaneMinor);

    // Returning to odd/even addressing is immediately direct again and needs
    // no representation change because the trapped access preserved layout.
    let mode3_seq4 = vga::bios_mode_regs(3).unwrap().seq[4];
    let write = state.port_write(0x3C5, mode3_seq4);
    assert!(matches!(write.new_aperture, vga::CpuAperture::Direct { pages: 8, .. }));
    assert_eq!(write.vram_transition, Some(VramTransition::between(
        VramLayout::PlaneMinor,
        VramLayout::OddEven,
    )));
}

#[test]
fn trapped_addressing_is_independent_of_backing_layout() {
    let mut state = *vga::VgaState::new_mode3_boxed();
    let mut vram = state.planes.clone();
    assert_eq!(state.layout(), VramLayout::OddEven);

    // Conventional odd/even: A0 selects plane 0/1 and the remaining address
    // bits select a compact byte offset within that plane.
    assert_eq!(state.cpu_read_address(6), (3, 0));
    assert_eq!(state.cpu_read_address(7), (3, 1));
    assert_eq!(state.cpu_write_address(6), (3, 0x01));
    assert_eq!(state.cpu_write_address(7), (3, 0x02));

    // Sequential plane access traps and changes the register-derived complete
    // ordering to plane-minor.
    state.port_write(0x3C4, 4);
    let write = state.port_write(0x3C5, 0x04);
    assert_eq!(write.vram_transition, Some(VramTransition::between(
        VramLayout::OddEven,
        VramLayout::PlaneMinor,
    )));
    write.vram_transition.unwrap().apply(&mut vram);
    assert_eq!(state.cpu_write_address(7), (7, 0x03));
    assert_eq!(state.cpu_read_address(7), (3, 1));

    // Chain-4 uses A1:A0 as the plane and the upper address bits as offset.
    state.port_write(0x3C4, 2);
    state.port_write(0x3C5, 0x0F);
    state.port_write(0x3C4, 4);
    let write = state.port_write(0x3C5, 0x0E);
    assert_eq!(state.cpu_read_address(7), (1, 3));
    assert_eq!(state.cpu_write_address(7), (1, 0x08));
    assert!(write.vram_transition.is_none());
}

#[test]
fn odd_even_map_zero_exposes_the_full_128k_aperture() {
    let mut state = vga::VgaState::new();
    let regs = vga::bios_mode_regs(3).unwrap();
    state.seq = regs.seq;
    state.gc = regs.gc;
    // GC6 memory map 00 decodes A0000..BFFFF. With the standard plane-0/1
    // odd/even selection, that whole 128K is one direct prefix of OddEven.
    state.gc[6] &= !0x0C;
    assert_eq!(state.layout(), VramLayout::OddEven);
    assert_eq!(
        state.cpu_aperture(),
        vga::CpuAperture::Direct {
            range: vga::ApertureRange { start_page: 0xA0, end_page: 0xC0 },
            pages: 32,
        },
    );
}

#[test]
fn mode6_is_sequential_plane_zero_and_trapped() {
    let mut state = vga::VgaState::new();
    let regs = vga::bios_mode_regs(6).unwrap();
    state.seq = regs.seq;
    state.gc = regs.gc;
    assert_eq!(state.classify_mode(), Some(VgaMode::Cga2));
    assert_eq!(state.layout(), VramLayout::PlaneMinor);
    assert_eq!(
        state.cpu_aperture(),
        vga::CpuAperture::Trapped {
            range: vga::ApertureRange { start_page: 0xB8, end_page: 0xC0 },
        },
    );
    assert_eq!(state.cpu_write_address(0x2345), (0x2345, 0x01));
    assert_eq!(state.cpu_read_address(0x2345), (0x2345, 0));

    // Sequential mode obeys the sequencer map mask without hidden special
    // cases: selecting plane 2 routes the same offset only to plane 2.
    state.seq[2] = 0x04;
    assert_eq!(state.cpu_write_address(0x2345), (0x2345, 0x04));
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
    assert_eq!(planes[1], chained[1]);
    assert_eq!(planes[2], chained[2]);
    assert_eq!(planes[3], chained[3]);
    assert_eq!(planes[4], chained[4]);

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
    assert_eq!(planes[1], text[1]);
    assert_eq!(planes[4], text[2]);
    assert_eq!(planes[5], text[3]);
    assert_eq!(planes[VramLayout::PlaneMinor.index(0, 0x3FFF)], text[0x7FFE]);
    assert_eq!(planes[VramLayout::PlaneMinor.index(1, 0x3FFF)], text[0x7FFF]);
    assert_eq!(planes[VramLayout::PlaneMinor.index(2, 0)], 0xA5);

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
        font_b: &[],
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
        font_b: &[],
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
        mode: TEXT80,
        vram: &vram,
        planes: &[],
        ac: &ac,
        palette: &pal,
        dac_mask: 0xFF,
        font: &font,
        font_b: &font,
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
fn text_attribute_bit_three_selects_character_map() {
    let mut font_a = vec![0u8; 256 * 16];
    let mut font_b = vec![0u8; 256 * 16];
    font_a[16] = 0x80; // map A: leftmost dot
    font_b[16] = 0x40; // map B: next dot
    let mut vram = vec![0u8; 80 * 25 * 2];
    vram[0] = 1;
    vram[1] = 0x0F; // attribute bit 3 set selects map A
    vram[2] = 1;
    vram[3] = 0x07; // attribute bit 3 clear selects map B
    let pal = vga_render::fallback_palette();
    let ac = identity_ac();
    let frame = Frame {
        mode: TEXT80,
        vram: &vram,
        planes: &[],
        ac: &ac,
        palette: &pal,
        dac_mask: 0xFF,
        font: &font_a,
        font_b: &font_b,
        blink: false,
        cga_palette: [0; 4],
        start_offset: 0,
        pixel_pan: 0,
        line_compare: usize::MAX,
    };
    let mut out = vec![0u32; 720 * 400];
    vga_render::render(&frame, &mut out);
    assert_eq!(out[0], pal_rgb(&pal, 15));
    assert_eq!(out[1], pal_rgb(&pal, 0));
    assert_eq!(out[9], pal_rgb(&pal, 0));
    assert_eq!(out[10], pal_rgb(&pal, 7));
}

#[test]
fn text40_keeps_rows_separate_and_doubles_character_dots() {
    let mut font = vec![0u8; 256 * 16];
    font[16] = 0x80; // character 1: top-left glyph dot only
    let mut vram = vec![0u8; 40 * 25 * 2];
    let cell = (40 * 1) * 2; // row 1, column 0
    vram[cell] = 1;
    vram[cell + 1] = 0x0F;
    let pal = vga_render::fallback_palette();
    let ac = identity_ac();
    let frame = Frame {
        mode: TEXT40, vram: &vram, planes: &[],
        ac: &ac, palette: &pal,
        dac_mask: 0xFF, font: &font, font_b: &font, blink: false, cga_palette: [0; 4],
        start_offset: 0, pixel_pan: 0, line_compare: usize::MAX,
    };
    let mut out = vec![0u32; 720 * 400];
    vga_render::render(&frame, &mut out);
    let fg = pal_rgb(&pal, 15);
    assert_eq!(out[16 * 720], fg);
    assert_eq!(out[16 * 720 + 1], fg); // one VGA dot repeated horizontally
    assert_ne!(out[0], fg);            // row 1 was not concatenated onto row 0
}

#[test]
fn fallback_palette_has_ega_colors_first() {
    let pal = vga_render::fallback_palette();
    // Entry 15 is white (63,63,63); entry 1 is blue (0,0,42).
    assert_eq!((pal[15 * 3], pal[15 * 3 + 1], pal[15 * 3 + 2]), (63, 63, 63));
    assert_eq!((pal[3], pal[3 + 1], pal[3 + 2]), (0, 0, 42));
}

#[test]
fn native_rows_hold_one_output_encoded_word_per_vga_pixel() {
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
        font_b: &[],
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
    let sy = 199usize;
    for fmt in formats {
        let mut out = vec![0u32; 320];
        let mut pal = vga_render::Pal::new();
        let mut cache = [0u8; 768];
        pal.sync(&palette, 0xFF, fmt, &mut cache);
        vga_render::render_row(&frame, sy, &pal, &mut out);
        for (x, &idx) in vram[sy * 320..(sy + 1) * 320].iter().enumerate() {
            assert_eq!(out[x], fmt.encode(pal_rgb(&palette, idx)));
        }
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
