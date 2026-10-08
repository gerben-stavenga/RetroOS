use lib::{codepage, unicode_font};

#[test]
fn unicode_glyphs_are_independent_of_the_selected_page() {
    assert_eq!(unicode_font::GLYPH_COUNT, 2899);
    for ch in ['A', 'é', 'Ж', 'Ω', 'א', '€', '─', '█'] {
        let glyph = unicode_font::lookup(ch).unwrap();
        assert_eq!(glyph.len(), 16);
        assert!(glyph.iter().any(|&row| row != 0));
    }
    assert!(unicode_font::lookup('😀').is_none());
    assert_eq!(unicode_font::glyph16('😀'), unicode_font::glyph16('?'));
    assert_eq!(unicode_font::glyph16(' '), &[0; 16]);
    assert_eq!(unicode_font::glyph16('\0'), &[0; 16]);
}

#[test]
fn vga_fonts_follow_the_byte_to_unicode_mapping() {
    for id in [437, 850, 852, 866] {
        let page = codepage::codepage(id).unwrap();
        let font = page.fonts().h16;
        assert_eq!(&font[..16], &[0; 16]);
        for byte in 1..256 {
            let ch = page.decode_glyph(byte as u8);
            assert!(unicode_font::lookup(ch).is_some(), "CP{id} byte {byte:02x}: {ch:?}");
            assert_eq!(&font[byte * 16..byte * 16 + 16], unicode_font::glyph16(ch));
        }
        // Right-edge extension is essential for VGA's ninth-column line art.
        let horizontal = page.encode_exact('─').unwrap() as usize;
        assert!(font[horizontal * 16..horizontal * 16 + 16].contains(&0xff));
        let block = page.encode_exact('█').unwrap() as usize;
        assert_eq!(&font[block * 16..block * 16 + 16], &[0xff; 16]);
    }
}

#[test]
fn terminal_rasterization_reads_unicode_and_extends_box_drawing() {
    use lib::term::Cell;
    let cells = [Cell { character: 'Ж', attribute: 0x12 }, Cell { character: '█', attribute: 0x34 }];
    let palette: Vec<u32> = (0..16).collect();
    let mut pixels = [0; 18 * 16];
    unicode_font::render_terminal(&cells, 2, 9, &palette, &mut pixels);
    for row in 0..16 {
        let pixels = &pixels[row * 18..(row + 1) * 18];
        let bits = unicode_font::lookup('Ж').unwrap()[row];
        for (column, &pixel) in pixels[..8].iter().enumerate() {
            assert_eq!(pixel, if bits & (0x80 >> column) != 0 { 2 } else { 1 });
        }
        assert_eq!(pixels[8], 1); // Ordinary letters do not extend into spacing.
        assert_eq!(&pixels[9..], &[4; 9]);
    }
}
