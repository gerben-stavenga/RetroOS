//! Active single-byte DOS character encoding. DOS keeps byte-oriented APIs;
//! names and logs cross into UTF-8 through this page. Each installed page
//! carries matching VGA font bitmaps. Multibyte pages need a stateful decoder.

use core::sync::atomic::{AtomicU16, Ordering};

pub struct CodePage {
    pub id: u16,
    pub glyphs: &'static [char; 256],
    pub replacement: u8,
}

pub struct Fonts {
    pub h8: &'static [u8; 2048],
    pub h14: &'static [u8; 3584],
    pub h16: [u8; 4096],
}

impl CodePage {
    pub fn font8(&self) -> &'static [u8; 2048] {
        match self.id {
            850 => include_bytes!("fonts/cp850_8x8.bin"),
            852 => include_bytes!("fonts/cp852_8x8.bin"),
            866 => include_bytes!("fonts/cp866_8x8.bin"),
            _ => &crate::vga_fonts::FONT_8X8,
        }
    }

    pub fn font14(&self) -> &'static [u8; 3584] {
        match self.id {
            850 => include_bytes!("fonts/cp850_8x14.bin"),
            852 => include_bytes!("fonts/cp852_8x14.bin"),
            866 => include_bytes!("fonts/cp866_8x14.bin"),
            _ => &crate::vga_fonts::FONT_8X14,
        }
    }

    /// Build the 8×16 character generator when installing a VGA font.
    pub fn fonts(&self) -> Fonts {
        Fonts {
            h8: self.font8(),
            h14: self.font14(),
            h16: crate::unicode_font::codepage_font(self),
        }
    }
}

impl CodePage {
    /// DOS text semantics: C0 bytes and DEL remain control characters.
    pub fn decode(&self, byte: u8) -> char {
        if byte < 0x20 || byte == 0x7f { char::from(byte) } else { self.decode_glyph(byte) }
    }

    /// VGA text semantics: the same low bytes name the ROM symbol glyphs.
    pub fn decode_glyph(&self, byte: u8) -> char { self.glyphs[byte as usize] }

    /// Exact conversion for names and other data where a display fallback
    /// would silently change the value.
    pub fn encode_exact(&self, ch: char) -> Option<u8> {
        if ch.is_ascii() { return Some(ch as u8); }
        self.glyphs[0x80..].iter().position(|&glyph| glyph == ch)
            .map(|index| (index + 0x80) as u8)
            .or_else(|| self.glyphs[0x01..0x20].iter().position(|&glyph| glyph == ch)
                .map(|index| (index + 1) as u8))
            .or_else(|| (self.glyphs[0x7f] == ch).then_some(0x7f))
    }

    /// One-byte case conversion for DOS names and country services.
    pub fn uppercase(&self, byte: u8) -> u8 {
        let mut upper = self.decode(byte).to_uppercase();
        let Some(ch) = upper.next() else { return byte };
        if upper.next().is_some() { return byte; }
        self.encode_exact(ch).unwrap_or(byte)
    }

    /// One display cell for a Unicode scalar. This may approximate characters
    /// that have no exact byte in the selected page.
    pub fn encode_display(&self, ch: char) -> u8 {
        self.encode_exact(ch)
            .or_else(|| crate::unicode_lookalike::simplify(ch)
                .and_then(|simple| self.encode_exact(simple)))
            .unwrap_or(self.replacement)
    }

    /// Convert a UTF-8 log line to DOS display bytes. Historical lines with
    /// invalid UTF-8 retain their original bytes.
    pub fn display_line(&self, input: &[u8], output: &mut [u8]) -> usize {
        if let Ok(text) = core::str::from_utf8(input) {
            let mut len = 0;
            for ch in text.chars() {
                if len == output.len() { break; }
                output[len] = self.encode_display(ch);
                len += 1;
            }
            len
        } else {
            let len = input.len().min(output.len());
            output[..len].copy_from_slice(&input[..len]);
            len
        }
    }
}

static CP437: CodePage = CodePage {
    id: 437,
    glyphs: &crate::cp437::TABLE,
    replacement: 0xfe,
};
static CP850: CodePage = CodePage { id: 850, glyphs: &crate::codepage_tables::CP850, replacement: b'?' };
static CP852: CodePage = CodePage { id: 852, glyphs: &crate::codepage_tables::CP852, replacement: b'?' };
static CP866: CodePage = CodePage { id: 866, glyphs: &crate::codepage_tables::CP866, replacement: b'?' };
static CP1250: CodePage = CodePage { id: 1250, glyphs: &crate::ansi_tables::CP1250, replacement: b'?' };
static CP1251: CodePage = CodePage { id: 1251, glyphs: &crate::ansi_tables::CP1251, replacement: b'?' };
static CP1252: CodePage = CodePage { id: 1252, glyphs: &crate::ansi_tables::CP1252, replacement: b'?' };
static CURRENT: AtomicU16 = AtomicU16::new(437);

pub fn current_codepage() -> &'static CodePage {
    codepage(CURRENT.load(Ordering::Acquire)).unwrap_or(&CP437)
}

pub fn codepage(id: u16) -> Option<&'static CodePage> {
    match id { 437 => Some(&CP437), 850 => Some(&CP850), 852 => Some(&CP852), 866 => Some(&CP866), _ => None }
}

/// Encoding tables also include Windows ANSI pages, which have no DOS font.
pub fn encoding_page(id: u16) -> Option<&'static CodePage> {
    match id {
        1250 => Some(&CP1250), 1251 => Some(&CP1251), 1252 => Some(&CP1252),
        _ => codepage(id),
    }
}

/// Callers must install the matching VGA font before publishing the new page.
pub fn select_codepage(id: u16) -> bool {
    if codepage(id).is_none() { return false; }
    CURRENT.store(id, Ordering::Release);
    true
}
