//! Win32 encoding contracts backed by the shared UTF-8 conversion layer.
use super::*;
use crate::kernel::text::{Encoding, to_utf16};
#[cfg(test)]
use crate::kernel::text::from_utf16;

pub(super) fn ansi() -> Encoding { Encoding::for_codepage(u32::from(lib::locale::current().ansi)).unwrap() }

pub(super) fn page(id: u32) -> Option<Encoding> {
    match id {
        0 | 3 => Some(ansi()),
        1 => Some(Encoding::oem()),
        _ => Encoding::for_codepage(id),
    }
}

pub(super) fn encode(text: &[u8], wide: bool) -> Vec<u16> {
    encode_with(text, wide, ansi())
}

pub(super) fn encode_with(text: &[u8], wide: bool, page: Encoding) -> Vec<u16> {
    let text = alloc::string::String::from_utf8_lossy(text);
    if wide { to_utf16(&text) }
    else { page.encode(&text, b'?').0.into_iter().map(u16::from).collect() }
}

pub(super) fn copy<A: crate::Arch>(m: &mut A, out: usize, cap: usize, text: &[u8], wide: bool) -> u32 {
    copy_with(m, out, cap, text, wide, ansi())
}

pub(super) fn copy_with<A: crate::Arch>(m: &mut A, out: usize, cap: usize, text: &[u8], wide: bool, page: Encoding) -> u32 {
    let value = encode_with(text, wide, page);
    if cap <= value.len() || out == 0 { return (value.len() + 1) as u32; }
    for (i, &unit) in value.iter().enumerate() {
        if wide { m.write::<u16>(out + i * 2, unit); }
        else { m.write::<u8>(out + i, unit as u8); }
    }
    if wide { m.write::<u16>(out + value.len() * 2, 0); }
    else { m.write::<u8>(out + value.len(), 0); }
    value.len() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_encodings_share_unicode_values_without_sharing_byte_values() {
        for (id, encoded, text) in [
            (437, &b"caf\x82"[..], "café"),
            (850, &b"caf\x82"[..], "café"),
            (852, &b"\xa5\x88"[..], "ął"),
            (866, &b"\x8f\xe0\xa8\xa2\xa5\xe2"[..], "Привет"),
            (1250, &b"\xb9\xb3"[..], "ął"),
            (1251, &b"\xcf\xf0\xe8\xe2\xe5\xf2"[..], "Привет"),
            (1252, &b"caf\xe9 \x80"[..], "café €"),
        ] {
            let page = Encoding::for_codepage(id).unwrap();
            assert_eq!(page.decode(encoded, true).unwrap(), text);
            assert_eq!(page.encode(text, b'?'), (encoded.to_vec(), false));
            assert_eq!(from_utf16(&to_utf16(text), true).unwrap(), text);
        }
    }

    #[test]
    fn unicode_surrogates_invalid_sequences_and_lossy_encoding_are_explicit() {
        assert_eq!(to_utf16("é😀"), [0xe9, 0xd83d, 0xde00]);
        assert!(from_utf16(&[0xd800], true).is_err());
        assert_eq!(from_utf16(&[0xd800], false).unwrap(), "\u{fffd}");
        assert!(Encoding::Utf8.decode(&[0xc0, 0xaf], true).is_err());
        assert_eq!(Encoding::Utf8.decode(&[0xff], false).unwrap(), "\u{fffd}");
        assert_eq!(ansi().encode("Ж", b'?'), (b"?".to_vec(), true));
        assert_eq!(encode("é😀".as_bytes(), true), [0xe9, 0xd83d, 0xde00]);
        assert_eq!(encode("é".as_bytes(), false), [0xe9]);
        assert!(crate::kernel::text::wildcard("?.TXT".as_bytes(), "Ж.txt".as_bytes()));
        assert!(crate::kernel::text::wildcard("пр*.txt".as_bytes(), "ПРИВЕТ.TXT".as_bytes()));
        assert!(!crate::kernel::text::wildcard(b"?.txt", "ёж.txt".as_bytes()));
    }
}
