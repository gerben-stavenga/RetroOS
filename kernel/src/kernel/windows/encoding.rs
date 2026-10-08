//! Win32 encoding contracts backed by the shared UTF-8 conversion layer.
use super::*;
use crate::kernel::text::{Encoding, from_utf16, to_utf16};

pub(super) fn ansi() -> Encoding { Encoding::for_codepage(1252).unwrap() }

pub(super) fn file_page(state: &WindowsState) -> Encoding {
    if state.file_oem { Encoding::oem() } else { ansi() }
}

pub(super) fn file_string<A: crate::Arch>(m: &A, state: &WindowsState, address: u32, wide: bool) -> Result<Vec<u8>, u32> {
    if wide { w_string(m, address) }
    else { Ok(file_page(state).decode(&raw_string(m, address)?, false).unwrap().into_bytes()) }
}

pub(super) fn page(id: u32) -> Option<Encoding> {
    match id {
        0 | 3 => Some(ansi()),
        1 => Some(Encoding::oem()),
        _ => Encoding::for_codepage(id),
    }
}

pub(super) fn bytes<A: crate::Arch>(m: &A, address: u32, count: i32) -> Result<Vec<u8>, u32> {
    if address == 0 || count == 0 || count < -1 { return Err(ERROR_INVALID_PARAMETER); }
    if count == -1 {
        let mut value = raw_string(m, address)?;
        value.push(0);
        Ok(value)
    } else {
        Ok((0..count as usize).map(|i| m.read::<u8>(address as usize + i)).collect())
    }
}

pub(super) fn units<A: crate::Arch>(m: &A, address: u32, count: i32) -> Result<Vec<u16>, u32> {
    if address == 0 || count == 0 || count < -1 { return Err(ERROR_INVALID_PARAMETER); }
    let mut value = Vec::new();
    for i in 0..if count == -1 { 32768 } else { count as usize } {
        let unit = m.read::<u16>(address as usize + i * 2);
        value.push(unit);
        if count == -1 && unit == 0 { return Ok(value); }
    }
    if count == -1 { Err(ERROR_INVALID_PARAMETER) } else { Ok(value) }
}

pub(super) fn multi_to_wide<A: crate::Arch>(m: &mut A, s: &mut WindowsState, r: &Regs) -> u32 {
    let id = arg(m, r, 0);
    let Some(page) = page(id) else { return fail(s, ERROR_INVALID_PARAMETER, 0); };
    let flags = arg(m, r, 1);
    let utf8 = matches!(page, Encoding::Utf8);
    if flags & !if utf8 { 8 } else { 1 | 4 | 8 } != 0 { return fail(s, 1004, 0); }
    let input = arg(m, r, 2);
    let out = arg(m, r, 4) as usize;
    let cap = arg(m, r, 5) as i32;
    if cap < 0 || (cap != 0 && out == 0) || input as usize == out {
        return fail(s, ERROR_INVALID_PARAMETER, 0);
    }
    let data = match bytes(m, input, arg(m, r, 3) as i32) {
        Ok(data) => data, Err(e) => return fail(s, e, 0),
    };
    let text = if flags & 4 != 0 {
        let Encoding::SingleByte(page) = page else { unreachable!() };
        Ok(data.iter().map(|&b| page.decode_glyph(b)).collect())
    } else { page.decode(&data, flags & 8 != 0) };
    let Ok(text) = text else { return fail(s, 1113, 0); };
    let wide = to_utf16(&text);
    if cap == 0 { return wide.len() as u32; }
    if (cap as usize) < wide.len() { return fail(s, 122, 0); }
    for (i, &unit) in wide.iter().enumerate() { m.write::<u16>(out + i * 2, unit); }
    wide.len() as u32
}

pub(super) fn wide_to_multi<A: crate::Arch>(m: &mut A, s: &mut WindowsState, r: &Regs) -> u32 {
    let Some(page) = page(arg(m, r, 0)) else { return fail(s, ERROR_INVALID_PARAMETER, 0); };
    let flags = arg(m, r, 1);
    let utf8 = matches!(page, Encoding::Utf8);
    if flags & !if utf8 { 0x80 } else { 0x400 } != 0 { return fail(s, 1004, 0); }
    let input = arg(m, r, 2);
    let out = arg(m, r, 4) as usize;
    let cap = arg(m, r, 5) as i32;
    let default = arg(m, r, 6) as usize;
    let used = arg(m, r, 7) as usize;
    if cap < 0 || (cap != 0 && out == 0) || input as usize == out
        || (utf8 && (default != 0 || used != 0)) {
        return fail(s, ERROR_INVALID_PARAMETER, 0);
    }
    let data = match units(m, input, arg(m, r, 3) as i32) {
        Ok(data) => data, Err(e) => return fail(s, e, 0),
    };
    let Ok(text) = from_utf16(&data, flags & 0x80 != 0) else { return fail(s, 1113, 0); };
    let replacement = if default == 0 { b'?' } else { m.read::<u8>(default) };
    let (bytes, substituted) = page.encode(&text, replacement);
    if cap != 0 && (cap as usize) < bytes.len() { return fail(s, 122, 0); }
    if used != 0 { m.write::<u32>(used, u32::from(substituted)); }
    if cap != 0 { m.copy_to(out, &bytes); }
    bytes.len() as u32
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
