//! Unicode-indexed 8×16 Uni-VGA bitmaps. No allocation or page selection.
//! Provenance and redistribution terms: lib/fonts/uni-vga/README.md.

const RECORD_SIZE: usize = 20; // little-endian u32 scalar followed by 16 rows
const DATA: &[u8] = include_bytes!("fonts/unicode_8x16.bin");
pub const GLYPH_COUNT: usize = DATA.len() / RECORD_SIZE;

/// Exact bitmap lookup; unsupported scalars have no glyph.
pub fn lookup(ch: char) -> Option<&'static [u8]> {
    let (mut low, mut high) = (0, GLYPH_COUNT);
    while low < high {
        let mid = low + (high - low) / 2;
        let at = mid * RECORD_SIZE;
        let scalar = u32::from_le_bytes(DATA[at..at + 4].try_into().unwrap());
        match scalar.cmp(&(ch as u32)) {
            core::cmp::Ordering::Less => low = mid + 1,
            core::cmp::Ordering::Greater => high = mid,
            core::cmp::Ordering::Equal => return Some(&DATA[at + 4..at + RECORD_SIZE]),
        }
    }
    None
}

/// One cell, with a visible replacement for unsupported characters.
pub fn glyph16(ch: char) -> &'static [u8] {
    if ch == '\0' { return lookup(' ').unwrap(); }
    lookup(ch).unwrap_or_else(|| lookup('?').unwrap())
}

/// Assemble the byte-indexed font a VGA character generator requires.
pub fn codepage_font(page: &crate::codepage::CodePage) -> [u8; 4096] {
    let mut font = [0; 4096];
    for byte in 0..256 {
        let ch = page.decode_glyph(byte as u8);
        // Byte zero in VGA memory is blank, rather than Uni-VGA's missing-glyph
        // diagnostic at Unicode zero. Text control handling lives in the API.
        if ch != '\0' {
            font[byte * 16..byte * 16 + 16].copy_from_slice(glyph16(ch));
        }
    }
    font
}

/// Rasterize Unicode terminal cells without a byte encoding. A ninth column
/// extends box drawing and block glyphs as VGA text does.
pub fn render_terminal(
    cells: &[crate::term::Cell],
    columns: usize,
    cell_width: usize,
    palette: &[u32],
    output: &mut [u32],
) {
    assert!(matches!(cell_width, 8 | 9) && columns != 0);
    assert!(cells.len().is_multiple_of(columns));
    assert!(palette.len() >= 16 && output.len() == cells.len() * cell_width * 16);
    let stride = columns * cell_width;
    for (index, cell) in cells.iter().enumerate() {
        let glyph = glyph16(cell.character);
        let foreground = palette[(cell.attribute & 15) as usize];
        let background = palette[(cell.attribute >> 4) as usize];
        let base = index / columns * 16 * stride + index % columns * cell_width;
        let extend = ('\u{2500}'..='\u{259f}').contains(&cell.character);
        for (row, &bits) in glyph.iter().enumerate() {
            let pixels = &mut output[base + row * stride..base + row * stride + cell_width];
            for (col, pixel) in pixels.iter_mut().enumerate() {
                let ink = if col < 8 { bits & (0x80 >> col) != 0 }
                    else { extend && bits & 1 != 0 };
                *pixel = if ink { foreground } else { background };
            }
        }
    }
}
