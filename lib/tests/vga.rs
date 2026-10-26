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
fn packed_rows_match_encoded_words_for_every_vga_mode() {
    let modes = [
        VgaMode::Mode13h, TEXT80, TEXT40, VgaMode::Cga4, VgaMode::Cga2,
        VgaMode::Planar16 { w: 24, h: 4, row_bytes: 3 },
        VgaMode::ModeX { w: 12, h: 4, row_bytes: 3 },
        VgaMode::LinearSvga { w: 7, h: 4, bpp: 8, pitch: 11 },
        VgaMode::LinearSvga { w: 7, h: 4, bpp: 15, pitch: 18 },
        VgaMode::LinearSvga { w: 7, h: 4, bpp: 16, pitch: 18 },
        VgaMode::LinearSvga { w: 7, h: 4, bpp: 24, pitch: 25 },
        VgaMode::LinearSvga { w: 7, h: 4, bpp: 32, pitch: 32 },
    ];
    let memory: Vec<u8> = (0..4 * 65536).map(|i| (i * 29 + i / 256) as u8).collect();
    let palette = vga::fallback_palette();
    let ac = identity_ac();
    for mode in modes {
        let (w, h) = vga::dimensions(mode);
        let frame = Frame {
            memory: None,
            plane_layout: vga::VramLayout::PlaneMinor,
            mode, vram: &memory, planes: &memory, ac: ac, palette: palette,
            dac_mask: 0x7F, font: &lib::vga_fonts::FONT_8X16,
            font_b: &lib::vga_fonts::FONT_8X16, font_maps: None, blink: true, text_cursor: None,
            cga_palette: [0, 0x123456, 0xABCDEF, 0xFFFFFF],
            start_offset: 8, pixel_pan: 1, split_pixel_pan: 0, line_compare: 1, blank_start: h - 1,
        };
        for format in [PixelFormat::RGB332, PixelFormat::RGB555, PixelFormat::RGB565,
            PixelFormat::RGB888, PixelFormat::NATIVE]
        {
            let mut pal = vga::Pal::new();
            pal.sync(&palette, frame.dac_mask, format, &mut [0; 768]);
            pal.sync_planar(&ac);
            let step = usize::from(format.bytes_per_pixel);
            for sy in [0, 1, h - 1] {
                let mut words = vec![0; w];
                vga::render_row(&frame, sy, &pal, &mut words);
                let storage = w * step + vga::PACKED_ROW_PADDING;
                let mut packed = vec![0xEE; storage + 2];
                vga::render_row_packed(&frame, sy, &pal, &mut packed[1..1 + storage]);
                let expected: Vec<u8> = words.iter()
                    .flat_map(|p| p.to_le_bytes().into_iter().take(step)).collect();
                assert_eq!(&packed[1..1 + w * step], expected, "{mode:?} {format:?} row={sy}");
                assert_eq!(packed[0], 0xEE);
                assert_eq!(packed[1 + storage], 0xEE);
                // A caller without the required writable tail must not be
                // allowed into the unchecked per-pixel writer.
                let mut short = vec![0xEE; storage - 1];
                vga::render_row_packed(&frame, sy, &pal, &mut short);
                assert!(short.iter().all(|&b| b == 0xEE));
            }
        }
    }
}

#[test]
fn packed_rows_share_tail_storage_without_corrupting_following_rows() {
    let palette = vga::fallback_palette();
    let ac = identity_ac();
    let planes: Vec<u8> = (1..=16).collect();
    for width in [1, 2, 4] {
        let frame = Frame {
            memory: None,
            plane_layout: vga::VramLayout::PlaneMinor,
            mode: VgaMode::ModeX { w: width, h: 4, row_bytes: 1 },
            vram: &[], planes: &planes, ac: ac, palette: palette, dac_mask: 0xFF,
            font: &[], font_b: &[], font_maps: None, blink: false, text_cursor: None, cga_palette: [0; 4],
            start_offset: 0, pixel_pan: 0, split_pixel_pan: 0, line_compare: usize::MAX, blank_start: 3,
        };
        for format in [PixelFormat::RGB332, PixelFormat::RGB555, PixelFormat::RGB565,
            PixelFormat::RGB888, PixelFormat::NATIVE]
        {
            let mut pal = vga::Pal::new();
            pal.sync(&palette, 0xFF, format, &mut [0; 768]);
            let step = usize::from(format.bytes_per_pixel);
            let row_bytes = usize::from(width) * step;
            let storage = row_bytes * 4 + vga::PACKED_ROW_PADDING;
            let mut output = vec![0xEE; storage + 2];
            let mut expected = Vec::new();
            for y in 0..4 {
                let mut words = vec![0; usize::from(width)];
                vga::render_row(&frame, y, &pal, &mut words);
                expected.extend(words.iter().flat_map(|p| p.to_le_bytes().into_iter().take(step)));
                vga::render_row_packed(&frame, y, &pal,
                    &mut output[1 + y * row_bytes..1 + (y + 1) * row_bytes + vga::PACKED_ROW_PADDING]);
            }
            assert_eq!(&output[1..1 + 4 * row_bytes], expected);
            assert_eq!(output[0], 0xEE);
            assert_eq!(output[1 + storage], 0xEE);
        }
    }
}

#[test]
fn packed_text_reads_cells_and_font_directly_from_vga_planes() {
    let mut state = vga::LegacyVgaState::new_mode3_boxed();
    let layout = state.layout();
    state.planes[layout.index(0, 0)] = b'A';
    state.planes[layout.index(1, 0)] = 0x0F;
    let mut text = vec![0u8; 80 * 25 * 2];
    for cell in 0..80 * 25 {
        text[cell * 2] = state.planes[layout.index(0, cell)];
        text[cell * 2 + 1] = state.planes[layout.index(1, cell)];
    }
    let ac = identity_ac();
    let direct = Frame {
            memory: None,
        plane_layout: layout,
        mode: TEXT80,
        vram: &[],
        planes: &state.planes,
        ac: ac,
        palette: state.dac.read(),
        dac_mask: state.dac_mask.get(),
        font: &[],
        font_b: &[],
        font_maps: Some((0, 0)),
        blink: false, text_cursor: None,
        cga_palette: [0; 4],
        start_offset: 0,
        pixel_pan: 0, split_pixel_pan: 0,
        line_compare: usize::MAX,
        blank_start: usize::MAX,
    };
    let compact = Frame {
            memory: None,
        vram: &text,
        planes: &[],
        font: &lib::vga_fonts::FONT_8X16,
        font_b: &lib::vga_fonts::FONT_8X16,
        font_maps: None,
        ..direct
    };
    let mut pal = vga::Pal::new();
    pal.sync(&state.dac.read(), state.dac_mask.get(), PixelFormat::NATIVE, &mut [0; 768]);
    for y in 0..16 {
        let mut expected = vec![0u8; 720 * 4 + vga::PACKED_ROW_PADDING];
        let mut actual = vec![0u8; expected.len()];
        vga::render_row_packed(&compact, y, &pal, &mut expected);
        vga::render_row_packed(&direct, y, &pal, &mut actual);
        assert_eq!(actual, expected, "text row {y}");
    }
}

#[test]
fn dimensions_match_modes() {
    assert_eq!(vga_render::dimensions(VgaMode::Mode13h), (320, 200));
    assert_eq!(vga_render::dimensions(TEXT80), (720, 400));
    assert_eq!(vga_render::dimensions(TEXT40), (720, 400));
}

#[test]
fn scanout_reads_either_live_plane_layout_without_reordering() {
    let minor: Vec<u8> = (0..4 * 65536).map(|i| (i * 29 + i / 256) as u8).collect();
    let mut odd_even = minor.clone();
    VramTransition::between(VramLayout::PlaneMinor, VramLayout::OddEven).apply(&mut odd_even);
    let palette = vga::fallback_palette();
    let ac = identity_ac();
    for mode in [VgaMode::ModeX { w: 24, h: 4, row_bytes: 8 },
        VgaMode::Planar16 { w: 24, h: 4, row_bytes: 4 }]
    {
        let mut frame = Frame {
            memory: None,
            mode, plane_layout: VramLayout::PlaneMinor, planes: &minor, vram: &[],
            ac: ac, palette: palette, dac_mask: 0xFF, font: &[], font_b: &[], font_maps: None,
            blink: false, text_cursor: None, cga_palette: [0; 4], start_offset: 0x4000,
            pixel_pan: 3, split_pixel_pan: 0, line_compare: 2, blank_start: 3,
        };
        let mut pal = vga::Pal::new();
        pal.sync(&palette, 0xFF, PixelFormat::RGB565, &mut [0; 768]);
        pal.sync_planar(&ac);
        for y in 0..4 {
            frame.plane_layout = VramLayout::PlaneMinor;
            frame.planes = &minor;
            let mut expected = vec![0; 48 + vga::PACKED_ROW_PADDING];
            vga::render_row_packed(&frame, y, &pal, &mut expected);
            frame.plane_layout = VramLayout::OddEven;
            frame.planes = &odd_even;
            let mut actual = vec![0; expected.len()];
            vga::render_row_packed(&frame, y, &pal, &mut actual);
            assert_eq!(actual, expected, "{mode:?} row {y}");
        }
    }
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
    let state = vga_render::LegacyVgaState::new_mode3_boxed();
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
    let mut state = *vga::LegacyVgaState::new_mode3_boxed();
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
    let mut state = *vga::LegacyVgaState::new_mode3_boxed();
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
fn byte_mode_odd_even_blits_preserve_full_plane_offsets() {
    let state = vga::LegacyVgaState::new();
    let regs = vga::bios_mode_regs(0x13).unwrap();
    state.seq.write(regs.seq);
    state.gc.write(regs.gc);
    state.crtc.write(regs.crtc);
    // Jazz combines odd/even plane selection with byte-mode scanout and a
    // 336-pixel virtual stride. A0 chooses planes without halving the offset.
    state.seq.set(4, 0x02);
    state.gc.set(5, 0x50);
    state.crtc.set(0x14, 0);
    state.crtc.set(0x17, 0xE3);
    state.crtc.set(0x13, 42);
    let mut vram = vec![0u8; 4 * 0x10000];
    for (offset, pixels) in [(0x1200, [11, 12, 13, 14]), (0x1201, [21, 22, 23, 24])] {
        for (plane, pixel) in pixels.into_iter().enumerate() {
            vram[state.layout().index(plane, offset)] = pixel;
        }
    }
    for parity in 0..2 {
        let (source, plane) = state.cpu_read_address(0x1200 + parity);
        assert_eq!((source, plane), (0x1200 + parity, parity));
        let cur = core::array::from_fn(|p| vram[state.layout().index(p, source)]);
        let mut gc = state.gc.read();
        gc[4] = plane as u8;
        let (_, latches) = vga::planar_read(cur, &gc);
        gc[5] |= 1; // VRAM-to-VRAM latch copy
        let (destination, mask) = state.cpu_write_address(0x2000 + parity);
        assert_eq!(destination, 0x2000 + parity);
        let out = vga::planar_write([0; 4], latches, &gc, mask, 0);
        for (p, value) in out.into_iter().enumerate() {
            vram[state.layout().index(p, destination)] = value;
        }
    }
    VramTransition::between(state.layout(), VramLayout::PlaneMinor).apply(&mut vram);
    assert_eq!(&vram[4 * 0x2000..4 * 0x2002], &[11, 0, 13, 0, 0, 22, 0, 24]);
}

#[test]
fn byte_mode_odd_even_cannot_use_compact_text_alias() {
    let mut state = *vga::LegacyVgaState::new_mode3_boxed();
    assert!(matches!(state.cpu_aperture(), vga::CpuAperture::Direct { .. }));
    state.port_write(0x3D4, 0x17);
    let write = state.port_write(0x3D5, state.crtc.get(0x17) | 0x40);
    assert!(matches!(write.new_aperture, vga::CpuAperture::Trapped { .. }));
    // GC6 chain-odd/even pairs addresses independently of plane selection.
    assert_eq!(state.cpu_read_address(7), (6, 1));
    assert_eq!(state.cpu_write_address(7), (6, 0x02));
    state.gc.set(6, state.gc.get(6) & (!0x02));
    assert_eq!(state.cpu_read_address(7), (7, 1));
    assert_eq!(state.cpu_write_address(7), (7, 0x02));
}

#[test]
fn odd_even_map_zero_exposes_the_full_128k_aperture() {
    let state = vga::LegacyVgaState::new();
    let regs = vga::bios_mode_regs(3).unwrap();
    state.seq.write(regs.seq);
    state.gc.write(regs.gc);
    // GC6 memory map 00 decodes A0000..BFFFF. With the standard plane-0/1
    // odd/even selection, that whole 128K is one direct prefix of OddEven.
    state.gc.set(6, state.gc.get(6) & (!0x0C));
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
fn unchained_single_plane_reads_still_trap() {
    let state = vga::LegacyVgaState::new();
    state.seq.set(4, 0x04);
    state.seq.set(2, 0x04);
    state.gc.set(4, 2);
    state.gc.set(6, 0x04);
    assert!(matches!(state.cpu_aperture(), vga::CpuAperture::Trapped { .. }));
}

#[test]
fn mode6_is_sequential_plane_zero_and_trapped() {
    let state = vga::LegacyVgaState::new();
    let regs = vga::bios_mode_regs(6).unwrap();
    state.seq.write(regs.seq);
    state.gc.write(regs.gc);
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
    state.seq.set(2, 0x04);
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
            memory: None,
        plane_layout: vga::VramLayout::PlaneMinor,
        mode: VgaMode::Mode13h,
        vram: &vram,
        planes: &[],
        ac: ac,
        palette: pal,
        dac_mask: 0xFF,
        font: &[],
        font_b: &[],
        font_maps: None,
        blink: false, text_cursor: None,
        cga_palette: [0; 4],
        start_offset: 0,
        pixel_pan: 0, split_pixel_pan: 0,
        line_compare: usize::MAX,
        blank_start: usize::MAX,
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
            memory: None,
        plane_layout: vga::VramLayout::PlaneMinor,
        mode: VgaMode::Mode13h,
        vram: &vram,
        planes: &[],
        ac: ac,
        palette: pal,
        dac_mask: 0xFF,
        font: &[],
        font_b: &[],
        font_maps: None,
        blink: false, text_cursor: None,
        cga_palette: [0; 4],
        start_offset: 0,
        pixel_pan: 0, split_pixel_pan: 0,
        line_compare: usize::MAX,
        blank_start: usize::MAX,
    };
    let mut out = vec![0u32; 320 * 200];
    let (w, h) = vga_render::render(&frame, &mut out);
    assert_eq!((w, h), (320, 200));
    assert_eq!(out[0], pal_rgb(&pal, 7));
    assert_eq!(out[200], pal_rgb(&pal, 0)); // past the supplied bytes
}

#[test]
fn packed_indexed_spans_preserve_short_source_and_palette_zero() {
    let memory: Vec<u8> = (0..350).map(|i| (i * 37) as u8).collect();
    let mut palette = vga::fallback_palette();
    palette[..3].copy_from_slice(&[63, 31, 15]); // Missing VRAM is index 0, not black.
    let ac = identity_ac();
    for mode in [VgaMode::Mode13h, VgaMode::ModeX { w: 13, h: 4, row_bytes: 5 },
        VgaMode::LinearSvga { w: 13, h: 4, bpp: 8, pitch: 17 }]
    {
        let (w, h) = vga::dimensions(mode);
        for len in [0, 1, 23, 350] {
            let frame = Frame {
            memory: None,
                mode, plane_layout: VramLayout::PlaneMinor,
                vram: &memory[..len], planes: &memory[..len],
                ac: ac, palette: palette, dac_mask: 0x7F, font: &[], font_b: &[], font_maps: None,
                blink: false, text_cursor: None, cga_palette: [0; 4], start_offset: 3,
                pixel_pan: 7, split_pixel_pan: 0, line_compare: 2, blank_start: h,
            };
            for format in [PixelFormat::RGB332, PixelFormat::RGB565,
                PixelFormat::RGB888, PixelFormat::NATIVE]
            {
                let mut pal = vga::Pal::new();
                pal.sync(&palette, frame.dac_mask, format, &mut [0; 768]);
                let step = usize::from(format.bytes_per_pixel);
                for y in 0..4 {
                    let (start, pan, ry) = if y >= 2 { (0, 0, y - 2) } else { (3, 7, y) };
                    let base = match mode {
                        VgaMode::Mode13h => start + ry * w + pan,
                        VgaMode::ModeX { .. } => (start + ry * 5) * 4 + pan,
                        _ => y * 17,
                    };
                    let mut output = vec![0xEE; w * step + vga::PACKED_ROW_PADDING];
                    vga::render_row_packed(&frame, y, &pal, &mut output);
                    for x in 0..w {
                        let index = memory[..len].get(base + x).copied().unwrap_or(0) & 0x7F;
                        let expected = format.encode(pal_rgb(&palette, index)).to_le_bytes();
                        assert_eq!(&output[x * step..(x + 1) * step], &expected[..step],
                            "{mode:?} {format:?} len={len} row={y} x={x}");
                    }
                }
            }
        }
    }
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
            memory: None,
        plane_layout: vga::VramLayout::PlaneMinor,
        mode: TEXT80,
        vram: &vram,
        planes: &[],
        ac: ac,
        palette: pal,
        dac_mask: 0xFF,
        font: &font,
        font_b: &font,
        font_maps: None,
        blink: false, text_cursor: None,
        cga_palette: [0; 4],
        start_offset: 0,
        pixel_pan: 0, split_pixel_pan: 0,
        line_compare: usize::MAX,
        blank_start: usize::MAX,
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
            memory: None,
        plane_layout: vga::VramLayout::PlaneMinor,
        mode: TEXT80,
        vram: &vram,
        planes: &[],
        ac: ac,
        palette: pal,
        dac_mask: 0xFF,
        font: &font_a,
        font_b: &font_b,
        font_maps: None,
        blink: false, text_cursor: None,
        cga_palette: [0; 4],
        start_offset: 0,
        pixel_pan: 0, split_pixel_pan: 0,
        line_compare: usize::MAX,
        blank_start: usize::MAX,
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
            memory: None,
        plane_layout: vga::VramLayout::PlaneMinor,
        mode: TEXT40, vram: &vram, planes: &[],
        ac: ac, palette: pal,
        dac_mask: 0xFF, font: &font, font_b: &font, font_maps: None, blink: false, text_cursor: None, cga_palette: [0; 4],
        start_offset: 0, pixel_pan: 0, split_pixel_pan: 0, line_compare: usize::MAX, blank_start: usize::MAX,
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
fn initial_vga_palette_has_standard_greys_and_hue_rings() {
    let p = vga::fallback_palette();
    let grey = [0, 5, 8, 11, 14, 17, 20, 24, 28, 32, 36, 40, 45, 50, 56, 63];
    for (i, value) in grey.into_iter().enumerate() {
        assert_eq!(&p[(16 + i) * 3..(17 + i) * 3], &[value; 3]);
    }
    for (index, rgb) in [
        (32, [0, 0, 63]), (33, [16, 0, 63]), (40, [63, 0, 0]),
        (48, [0, 63, 0]), (56, [31, 31, 63]), (80, [45, 45, 63]),
        (104, [0, 0, 28]), (128, [14, 14, 28]), (152, [20, 20, 28]),
        (176, [0, 0, 16]), (200, [8, 8, 16]), (224, [11, 11, 16]),
        (247, [11, 12, 16]),
    ] {
        assert_eq!(&p[index * 3..index * 3 + 3], &rgb);
    }
    assert!(p[248 * 3..].iter().all(|&v| v == 0));
    assert!(p.iter().all(|&v| v <= 63));
    assert_eq!(vga::LegacyVgaState::new().dac.read(), p);
    assert_eq!(vga::LegacyVgaState::new_boxed().dac.read(), p);
}

#[test]
fn ega_defaults_map_both_bios_attribute_tables_to_rgbi() {
    let normal = vga::ega_dac();
    let rgb200 = vga::ega_200line_dac();
    assert!(normal[64 * 3..].iter().all(|&v| v == 0));
    assert!(rgb200[64 * 3..].iter().all(|&v| v == 0));
    let normal_ac = [0, 1, 2, 3, 4, 5, 0x14, 7, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];
    let ac200 = [0, 1, 2, 3, 4, 5, 6, 7, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
    for (i, &(r, g, b)) in vga::EGA16.iter().enumerate() {
        for (palette, index) in [(&normal, normal_ac[i]), (&rgb200, ac200[i])] {
            assert_eq!(&palette[index * 3..index * 3 + 3], &[r, g, b]);
        }
    }
    // EGA's primary and secondary bits contribute 42 and 21 respectively.
    for index in 0..64 {
        let expected = [
            (42 * ((index >> 2) & 1) + 21 * ((index >> 5) & 1)) as u8,
            (42 * ((index >> 1) & 1) + 21 * ((index >> 4) & 1)) as u8,
            (42 * (index & 1) + 21 * ((index >> 3) & 1)) as u8,
        ];
        assert_eq!(&normal[index * 3..index * 3 + 3], &expected);
    }
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
            memory: None,
        plane_layout: vga::VramLayout::PlaneMinor,
        mode: VgaMode::Mode13h,
        vram: &vram,
        planes: &[],
        ac: ac,
        palette: palette,
        dac_mask: 0xFF,
        font: &[],
        font_b: &[],
        font_maps: None,
        blink: false, text_cursor: None,
        cga_palette: [0; 4],
        start_offset: 0,
        pixel_pan: 0, split_pixel_pan: 0,
        line_compare: usize::MAX, blank_start: usize::MAX,
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

#[test]
fn text_cursor_tracks_page_shape_disable_and_blink_in_both_renderers() {
    let mode = VgaMode::Text { cols: 3, rows: 2, cell_w: 9, cell_h: 16 };
    let palette = vga::fallback_palette();
    let ac = identity_ac();
    let font = [0u8; 256 * 16];
    // Page starts at cell 16. Cursor at row 1, column 1; foreground white.
    let mut memory = vec![0; 44];
    for cell in memory.chunks_exact_mut(2) { cell[1] = 0x1F; }
    let mut crtc = [0u8; 25];
    crtc[0x0A] = 14;
    crtc[0x0B] = 15;
    crtc[0x0F] = 20;
    let mut frame = Frame {
            memory: None,
        mode, plane_layout: VramLayout::PlaneMinor, vram: &memory, planes: &[],
        ac: ac, palette: palette, dac_mask: 0xFF,
        font: &font, font_b: &font, font_maps: None, blink: false,
        text_cursor: vga::TextCursor::from_crtc(&crtc, true),
        cga_palette: [0; 4], start_offset: 16, pixel_pan: 0, split_pixel_pan: 0,
        line_compare: usize::MAX, blank_start: usize::MAX,
    };
    let (w, h) = vga::dimensions(mode);
    let fg = pal_rgb(&palette, 15);
    let bg = pal_rgb(&palette, 1);
    let mut full = vec![0; w * h];
    let mut pal = vga::Pal::new();
    pal.sync(&palette, frame.dac_mask, PixelFormat::NATIVE, &mut [0; 768]);
    pal.sync_planar(&ac);
    for phase in 0..4 {
        if phase == 1 { frame.text_cursor = vga::TextCursor::from_crtc(&crtc, false); }
        if phase == 2 {
            crtc[0x0A] |= 0x20;
            frame.text_cursor = vga::TextCursor::from_crtc(&crtc, true);
        }
        if phase == 3 {
            crtc[0x0A] = 15;
            crtc[0x0B] = 14; // VGA hides a split cursor rather than wrapping.
            frame.text_cursor = vga::TextCursor::from_crtc(&crtc, true);
        }
        vga::render(&frame, &mut full);
        for y in 0..h {
            let mut packed = vec![0; w * 4 + vga::PACKED_ROW_PADDING];
            vga::render_row_packed(&frame, y, &pal, &mut packed);
            for x in 0..w {
                let expected = if phase == 0 && (9..18).contains(&x) && (30..32).contains(&y) { fg } else { bg };
                assert_eq!(full[y * w + x], expected, "phase={phase} x={x} y={y}");
                assert_eq!(u32::from_le_bytes(packed[x*4..x*4+4].try_into().unwrap()), expected);
            }
        }
    }
}

#[test]
fn display_start_waits_for_retrace_before_fine_pan_wrap() {
    let mut state = vga::LegacyVgaState::new();
    state.crtc.set(0x0d, 29);
    state.latch_display_start(10);
    state.latch_pixel_pan(10);
    // Prepare the next coarse scroll address during the active frame.
    state.port_write(0x3d4, 0x0d);
    state.port_write(0x3d5, 28);
    assert!(!state.latch_display_start(10));
    assert_eq!(state.display_start(), 29);
    assert_eq!(state.crtc.get(0x0d), 28); // Register reads see programmed state.
    // At retrace the address latches, then the guest changes pan 0 -> 7.
    assert!(state.latch_display_start(11));
    state.port_write(0x3c0, 0x13);
    state.port_write(0x3c0, 7);
    assert!(!state.latch_pixel_pan(10)); // Still inside retrace.
    assert_eq!(state.pixel_pan(), 0);
    assert!(state.latch_pixel_pan(11)); // Retrace ended.
    assert_eq!(usize::from(state.display_start()) * 8 + usize::from(state.pixel_pan()), 29 * 8 - 1);
    assert!(!state.latch_display_start(11));
}

#[test]
fn active_frame_scroll_writes_keep_both_old_latches_until_retrace() {
    let mut state = vga::LegacyVgaState::new_boxed();
    state.crtc.set(0x0d, 29);
    state.latch_display_start(10);
    state.latch_pixel_pan(10);
    // Keen's active-frame update prepares coarse and fine scroll together.
    state.port_write(0x3d4, 0x0d);
    state.port_write(0x3d5, 28);
    state.port_write(0x3c0, 0x13);
    state.port_write(0x3c0, 7);
    assert!(!state.latch_display_start(10));
    assert!(!state.latch_pixel_pan(10));
    assert_eq!((state.display_start(), state.pixel_pan()), (29, 0));
    assert_eq!(state.ac.get(0x13), 7); // CPU still reads the programmed value.
    state.latch_display_start(11);
    assert_eq!((state.display_start(), state.pixel_pan()), (28, 0));
    state.latch_pixel_pan(11);
    assert_eq!((state.display_start(), state.pixel_pan()), (28, 7));
}

#[test]
fn display_start_latches_before_next_frames_write() {
    let mut state = vga::LegacyVgaState::new_boxed();
    state.latch_display_start(1);
    state.crtc.set(0x0c, 0x21);
    state.crtc.set(0x0d, 0x1d);
    // No capture occurred in frame 2. A frame-3 write must still retain
    // the previously programmed page for the current scanout.
    assert!(state.latch_display_start(3));
    state.crtc.set(0x0c, 0);
    assert_eq!(state.display_start(), 0x211d);
    assert!(state.latch_display_start(4));
    assert_eq!(state.display_start(), 0x001d);
}


#[test]
fn beam_status_and_scroll_latches_share_programmed_edges() {
    let mut state = vga::LegacyVgaState::new_boxed();
    let regs = vga::bios_mode_regs(0x0d).unwrap();
    state.crtc.write(regs.crtc);
    state.seq.write(regs.seq);
    state.misc_output.set(regs.misc);
    // Mode 0Dh: 50 character clocks * 16 dots, 449 scanlines,
    // vertical retrace at line 412, ending at line 414.
    let time = |line: u64, dot: u64| ((line * 800 + dot) * 1_000_000_000).div_ceil(25_175_000);
    let before = state.beam(time(411, 799));
    let start = state.beam(time(412, 0));
    let during = state.beam(time(413, 799));
    let end = state.beam(time(414, 0));
    assert_eq!((before.address_epoch, before.panning_epoch), (0, 0));
    assert_eq!((start.address_epoch, start.panning_epoch), (1, 0));
    assert_eq!((end.address_epoch, end.panning_epoch), (1, 1));
    assert_eq!(before.status & 8, 0);
    assert_eq!(start.status & 8, 8);
    assert_eq!(during.status & 8, 8);
    assert_eq!(end.status & 8, 0);
    assert_eq!(state.beam(time(100, 0)).status, 0);
    assert_eq!(state.beam(time(100, 700)).status, 1);
    // Repeated reads at the same instant cannot move the beam.
    for _ in 0..32 { assert_eq!(state.beam(time(100, 0)).status, 0); }
    state.latch_display_start(before.address_epoch);
    state.latch_pixel_pan(before.panning_epoch);
    state.crtc.set(0x0d, 17);
    state.ac.set(0x13, 3);
    state.latch_display_start(start.address_epoch);
    state.latch_pixel_pan(start.panning_epoch);
    assert_eq!((state.display_start(), state.pixel_pan()), (17, 0));
    state.ac.set(0x13, 7); // Pan programmed during retrace belongs to this frame.
    state.latch_pixel_pan(end.panning_epoch);
    assert_eq!((state.display_start(), state.pixel_pan()), (17, 7));
    state.crtc.set(0x0d, 18); // Active-frame programming waits for the next edge.
    state.ac.set(0x13, 0);
    let next = state.beam(time(449 + 411, 799));
    state.latch_display_start(next.address_epoch);
    state.latch_pixel_pan(next.panning_epoch);
    assert_eq!((state.display_start(), state.pixel_pan()), (17, 7));
}

#[test]
fn beam_uses_mode_specific_refresh_and_wrapped_retrace_end() {
    let state = vga::LegacyVgaState::new_boxed();
    let regs = vga::bios_mode_regs(0x12).unwrap();
    state.crtc.write(regs.crtc);
    state.seq.write(regs.seq);
    state.misc_output.set(regs.misc);
    let time = |line: u64| (line * 800 * 1_000_000_000).div_ceil(25_175_000);
    // 640x480: 525 total lines, retrace 490..492, approximately 60 Hz.
    assert_eq!(state.beam(time(489)).status & 8, 0);
    assert_eq!(state.beam(time(490)).status & 8, 8);
    assert_eq!(state.beam(time(492)).status & 8, 0);
    assert_eq!(state.beam(time(525 + 490)).address_epoch, 2);
    // The four-bit retrace-end comparator wraps: start 490, end 0 means
    // line 496, not a pulse ending immediately or at the frame boundary.
    state.crtc.set(0x11, state.crtc.get(0x11) & (0xf0));
    assert_eq!(state.beam(time(495)).status & 8, 8);
    assert_eq!(state.beam(time(496)).status & 8, 0);
}

fn short_beam_timing() -> vga::beam::Timing {
    vga::beam::Timing {
        dot_hz: 1_000_000_000, dots_per_clock: 1,
        horizontal_total: 10, horizontal_display: 8,
        horizontal_blank_start: 8, horizontal_blank_end: 10,
        vertical_total: 6, vertical_display: 3,
        blank_start: 3, blank_end: 6, retrace_start: 4, retrace_end: 5,
    }
}

#[test]
fn beam_phases_do_not_depend_on_polling_frequency() {
    use vga::beam::{Phase, Sequencer};
    let timing = short_beam_timing();
    let mut synchronous = Sequencer::new(timing, 0);
    let mut asynchronous = Sequencer::new(timing, 0);
    let mut frequent = Vec::new();
    let mut batched = Vec::new();
    for now in 1..=180 {
        while let Some(event) = asynchronous.next(now) { frequent.push(event); }
    }
    for now in [3, 19, 79, 80, 180] {
        while let Some(event) = synchronous.next(now) { batched.push(event); }
    }
    assert_eq!(frequent, batched);
    assert!(frequent.windows(2).all(|pair|
        (pair[0].clock, pair[0].phase) < (pair[1].clock, pair[1].phase)));
    let boundary: Vec<_> = frequent.iter().filter(|e| e.clock == 60).map(|e| e.phase).collect();
    assert_eq!(boundary, [Phase::BlankEnd, Phase::HorizontalBlankEnd, Phase::FrameStart, Phase::RowStart]);
    assert_eq!(synchronous.deadline_ns(), 188);
}

#[test]
fn beam_status_and_latch_events_use_the_same_clock() {
    use vga::beam::{Phase, Sequencer};
    let timing = short_beam_timing();
    let mut clock = Sequencer::new(timing, 0);
    assert_eq!(timing.status(7), 0);
    assert_eq!(timing.status(8), 1);
    assert_eq!(timing.status(10), 0);
    assert_eq!(timing.status(30), 1);
    assert_eq!(timing.status(40), 9);
    assert_eq!(timing.status(50), 1);
    let mut edges = Vec::new();
    while let Some(event) = clock.next(180) {
        if event.phase == Phase::RetraceStart {
            assert_eq!(timing.status(event.clock) & 8, 8);
            assert_eq!(timing.latch_epoch(event.clock, timing.retrace_start), event.frame + 1);
            edges.push(event.clock);
        }
        if event.phase == Phase::RetraceEnd {
            assert_eq!(timing.status(event.clock) & 8, 0);
        }
    }
    assert_eq!(edges, [40, 100, 160]);
}

#[test]
fn beam_retrace_can_wrap_through_frame_start() {
    use vga::beam::{Phase, Sequencer};
    let mut timing = short_beam_timing();
    timing.retrace_start = 5;
    timing.retrace_end = 7;
    let mut clock = Sequencer::new(timing, 49);
    let mut edges = Vec::new();
    while let Some(event) = clock.next(71) {
        if matches!(event.phase, Phase::RetraceStart | Phase::RetraceEnd) {
            edges.push((event.clock, event.phase));
        }
    }
    assert_eq!(edges, [(50, Phase::RetraceStart), (70, Phase::RetraceEnd)]);
    assert_eq!(timing.status(59) & 8, 8);
    assert_eq!(timing.status(60) & 8, 8);
    assert_eq!(timing.status(70) & 8, 0);
}

#[test]
fn beam_deadline_rounding_never_fires_early() {
    use vga::beam::Timing;
    let state = vga::LegacyVgaState::new_mode3_boxed();
    let timing = Timing::from_registers(state.misc_output.get(), &state.seq.read(), &state.crtc.read());
    for clock in [1, 7, 100, 999, 45_000, 1_000_000, 9_000_000_000] {
        let deadline = timing.time_at(clock);
        assert_eq!(timing.clock_at(deadline), clock);
        assert!(timing.clock_at(deadline - 1) < clock);
    }
}

#[test]
fn beam_reprogramming_does_not_replay_old_rows() {
    use vga::beam::Sequencer;
    let timing = short_beam_timing();
    let mut clock = Sequencer::new(timing, 0);
    while clock.next(79).is_some() {}
    clock.reprogram(timing, 79);
    assert_eq!(clock.deadline_ns(), 80);
    let mut changed = timing;
    changed.horizontal_total = 12;
    clock.reprogram(changed, 79);
    assert_eq!(clock.deadline_ns(), 80); // Blank at column 8 of row 6.
    assert!(clock.next(79).is_none());
    assert_eq!(clock.next(80).unwrap().clock, 80);
}

fn tiny_scanout_device() -> (vga::LegacyVgaState, vga::memory::Memory<'static>, vga::beam::Timing) {
    use std::sync::atomic::AtomicU8;
    let state = vga::LegacyVgaState::new();
    state.seq.set(1, 1);
    state.seq.set(4, 4);
    state.gc.set(6, 1);
    state.crtc.set(0, 5); // Ten character clocks per physical line.
    state.crtc.set(1, 0); // Eight visible pixels.
    state.crtc.set(6, 4); // Six physical lines, four visible.
    state.crtc.set(0x12, 3);
    state.crtc.set(0x13, 1); // Two bytes per plane per source row.
    state.crtc.set(0x15, 4);
    state.crtc.set(0x16, 6);
    state.crtc.set(0x10, 4);
    state.crtc.set(0x11, 5);
    state.crtc.set(0x18, 255);
    for i in 0..16 { state.ac.set(i, i as u8); }
    state.dac.write([0; 768]);
    state.dac.set(3, 63); // Colour 1 red; colour 2 green.
    state.dac.set(7, 63);
    let bytes = Box::leak((0..4 * 65536).map(|_| AtomicU8::new(0)).collect::<Vec<_>>().into_boxed_slice());
    let memory = vga::memory::Memory::from_bytes(bytes);
    let timing = vga::beam::Timing::from_registers(state.misc_output.get(), &state.seq.read(), &state.crtc.read());
    (state, memory, timing)
}

fn assert_packed_colour(pixels: &[u8], start_row: usize, end_row: usize, colour: u32) {
    for row in start_row..end_row {
        for pixel in 0..8 {
            let offset = (row * 8 + pixel) * 4;
            assert_eq!(u32::from_le_bytes(pixels[offset..offset + 4].try_into().unwrap()), colour);
        }
    }
}

#[test]
fn scanout_latches_active_display_flip_for_next_frame() {
    let (device, memory, timing) = tiny_scanout_device();
    for row in 0..4 {
        memory.put(device.layout().index(0, row * 2), 255);
        memory.put(device.layout().index(1, 8 + row * 2), 255);
    }
    let mut scanout = vga::scanout::Scanout::new(&device, memory, PixelFormat::NATIVE, 0);
    let mut front = Vec::new();
    scanout.reserve(32, &mut front);
    for clock in [40, 60, 65] { scanout.advance(timing.time_at(clock), &mut front, || {}); }
    assert!(front.is_empty()); // A partial frame must never reach presentation.
    device.crtc.set(0x0d, 8); // Active display; the current address stays latched.
    assert!(scanout.advance(timing.time_at(90), &mut front, || {}).is_some());
    assert_packed_colour(&front, 0, 4, 0x00ff0000);
    for clock in [100, 120, 150] { scanout.advance(timing.time_at(clock), &mut front, || {}); }
    assert_packed_colour(&front, 0, 4, 0x0000ff00);
}

#[test]
fn scanout_fetches_live_rows_without_publication_or_frame_copy() {
    let (device, memory, timing) = tiny_scanout_device();
    for row in 0..4 { memory.put(device.layout().index(0, row * 2), 255); }
    let mut scanout = vga::scanout::Scanout::new(&device, memory, PixelFormat::NATIVE, 0);
    let mut front = Vec::new();
    scanout.reserve(32, &mut front);
    for clock in [40, 60] { scanout.advance(timing.time_at(clock), &mut front, || {}); }
    // Drawing after row zero was scanned affects subsequent rows only.
    for row in 0..4 {
        memory.put(device.layout().index(0, row * 2), 0);
        memory.put(device.layout().index(1, row * 2), 255);
    }
    scanout.advance(timing.time_at(90), &mut front, || {});
    assert_packed_colour(&front, 0, 1, 0x00ff0000);
    assert_packed_colour(&front, 1, 4, 0x0000ff00);
}

#[test]
fn scanout_sync_and_async_drivers_produce_identical_images() {
    let (device, memory, timing) = tiny_scanout_device();
    for row in 0..4 { memory.put(device.layout().index(0, row * 2), 255); }
    let mut synchronous = vga::scanout::Scanout::new(&device, memory, PixelFormat::NATIVE, 0);
    let mut asynchronous = vga::scanout::Scanout::new(&device, memory, PixelFormat::NATIVE, 0);
    let (mut sync_front, mut async_front) = (Vec::new(), Vec::new());
    synchronous.reserve(32, &mut sync_front);
    asynchronous.reserve(32, &mut async_front);
    for clock in 1..=150 {
        asynchronous.advance(timing.time_at(clock), &mut async_front, || {});
        if [30, 60, 75, 90, 120, 150].contains(&clock) {
            synchronous.advance(timing.time_at(clock), &mut sync_front, || {});
            assert_eq!(sync_front, async_front);
        }
        if clock == 75 {
            // Both consumers reached the write time; subsequent row fetches
            // observe the changed DAC cells, without changing the earlier rows.
            device.dac.set(3, 0);
            device.dac.set(4, 63);
        }
    }
}

#[test]
fn scanout_shares_registers_but_process_clone_does_not() {
    let original = vga::LegacyVgaState::new();
    let consumer = original.scanout_view();
    let child = original.clone();
    original.crtc.set(0x0d, 42);
    assert_eq!(consumer.crtc.get(0x0d), 42);
    assert_eq!(child.crtc.get(0x0d), 0);
    drop(original);
    assert_eq!(consumer.crtc.get(0x0d), 42); // Consumer owns a lifetime reference.
}

#[test]
fn stalled_scanout_discards_partial_frame_and_recovers() {
    let (device, memory, timing) = tiny_scanout_device();
    for row in 0..4 { memory.put(device.layout().index(0, row * 2), 255); }
    let mut scanout = vga::scanout::Scanout::new(&device, memory, PixelFormat::NATIVE, 0);
    let mut front = Vec::new();
    scanout.reserve(32, &mut front);
    scanout.advance(timing.time_at(40), &mut front, || {});
    scanout.advance(timing.time_at(60), &mut front, || {});
    scanout.advance(timing.time_at(600), &mut front, || {});
    assert!(front.is_empty());
    for clock in [630, 660, 690] { scanout.advance(timing.time_at(clock), &mut front, || {}); }
    assert_packed_colour(&front, 0, 4, 0x00ff0000);
}
