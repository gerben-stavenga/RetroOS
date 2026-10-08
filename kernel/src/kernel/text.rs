//! Guest encodings at the boundary; UTF-8 for shared text and paths.
//! File contents and guest display cell buffers are not implicitly transcoded.
use alloc::{string::String, vec::Vec};
use lib::codepage::{self, CodePage};

#[derive(Clone, Copy)]
pub enum Encoding {
    Utf8,
    SingleByte(&'static CodePage),
}

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidText;

impl Encoding {
    pub fn for_codepage(id: u32) -> Option<Self> {
        if id == 65001 { Some(Self::Utf8) }
        else { u16::try_from(id).ok().and_then(codepage::encoding_page).map(Self::SingleByte) }
    }

    pub fn oem() -> Self { Self::SingleByte(codepage::current_codepage()) }

    pub fn decode(self, bytes: &[u8], strict: bool) -> Result<String, InvalidText> {
        match self {
            Self::Utf8 if strict => core::str::from_utf8(bytes).map(String::from).map_err(|_| InvalidText),
            Self::Utf8 => Ok(String::from_utf8_lossy(bytes).into_owned()),
            Self::SingleByte(page) => Ok(bytes.iter().map(|&byte| page.decode(byte)).collect()),
        }
    }

    /// Reports substitution so APIs can reject lossy names or report use of
    /// their default character. No visual lookalikes are used for stored data.
    pub fn encode(self, text: &str, replacement: u8) -> (Vec<u8>, bool) {
        match self {
            Self::Utf8 => (text.as_bytes().to_vec(), false),
            Self::SingleByte(page) => {
                let mut substituted = false;
                let bytes = text.chars().map(|ch| page.encode_exact(ch).unwrap_or_else(|| {
                    substituted = true;
                    replacement
                })).collect();
                (bytes, substituted)
            }
        }
    }
}

pub fn from_utf16(units: &[u16], strict: bool) -> Result<String, InvalidText> {
    if strict { String::from_utf16(units).map_err(|_| InvalidText) }
    else { Ok(String::from_utf16_lossy(units)) }
}

pub fn to_utf16(text: &str) -> Vec<u16> { text.encode_utf16().collect() }

pub fn equal_folded(left: &[u8], right: &[u8]) -> bool {
    String::from_utf8_lossy(left).chars().flat_map(char::to_uppercase)
        .eq(String::from_utf8_lossy(right).chars().flat_map(char::to_uppercase))
}

/// A wildcard consumes Unicode characters rather than UTF-8 bytes.
pub fn wildcard(pattern: &[u8], name: &[u8]) -> bool {
    fn matches(pattern: &[char], name: &[char]) -> bool {
        let (mut p, mut n, mut star, mut retry) = (0, 0, None, 0);
        while n < name.len() {
            if p < pattern.len() && (pattern[p] == '?' || pattern[p] == name[n]) { p += 1; n += 1; }
            else if p < pattern.len() && pattern[p] == '*' { star = Some(p); p += 1; retry = n; }
            else if let Some(s) = star { retry += 1; n = retry; p = s + 1; }
            else { return false; }
        }
        while p < pattern.len() && pattern[p] == '*' { p += 1; }
        p == pattern.len()
    }
    let p: Vec<char> = String::from_utf8_lossy(pattern).chars().flat_map(char::to_uppercase).collect();
    let n: Vec<char> = String::from_utf8_lossy(name).chars().flat_map(char::to_uppercase).collect();
    matches(&p, &n) || (p.ends_with(&['.', '*']) && matches(&p[..p.len() - 2], &n))
}

/// Unicode lookup independent of the guest's ANSI/OEM encoding.
pub fn glyph16(ch: char) -> &'static [u8] {
    lib::unicode_font::glyph16(ch)
}
