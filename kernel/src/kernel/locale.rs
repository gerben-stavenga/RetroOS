//! Encode shared Unicode regional settings into legacy country structures.
use crate::kernel::text::Encoding;
use lib::locale::Locale;

fn currency(profile: &Locale, page: u16) -> &str {
    // Older OEM pages lack Euro and other modern symbols: use the ISO code,
    // preserving useful country metadata rather than returning a question mark.
    if Encoding::for_codepage(u32::from(page)).unwrap().encode(profile.currency, b'?').1 {
        profile.currency_iso
    } else { profile.currency }
}

fn field(output: &mut [u8], text: &str, page: u16) {
    let bytes = Encoding::for_codepage(u32::from(page)).unwrap().encode(text, b'?').0;
    let length = bytes.len().min(output.len().saturating_sub(1));
    output[..length].copy_from_slice(&bytes[..length]);
}

/// DOS AH=38h's first 32 bytes. The final two reserved bytes of the DOS 3+
/// structure are omitted because old callers allocate only a 32-byte buffer.
pub fn dos_country(profile: &Locale, page: u16) -> [u8; 32] {
    let mut data = [0; 32];
    data[..2].copy_from_slice(&profile.date_order.to_le_bytes());
    field(&mut data[2..7], currency(profile, page), page);
    field(&mut data[7..9], profile.thousands, page);
    field(&mut data[9..11], profile.decimal, page);
    field(&mut data[11..13], profile.date_separator, page);
    field(&mut data[13..15], ":", page);
    data[15] = profile.currency_format;
    data[16] = 2;
    data[17] = u8::from(profile.time24);
    field(&mut data[22..24], profile.list_separator, page);
    data // The DOS service fills the far case-map pointer at +18.
}

pub fn os2_country(profile: &Locale, page: u16) -> [u8; 44] {
    let mut data = [0; 44];
    data[..4].copy_from_slice(&u32::from(profile.country).to_le_bytes());
    data[4..8].copy_from_slice(&u32::from(page).to_le_bytes());
    data[8..12].copy_from_slice(&u32::from(profile.date_order).to_le_bytes());
    field(&mut data[12..17], currency(profile, page), page);
    field(&mut data[17..19], profile.thousands, page);
    field(&mut data[19..21], profile.decimal, page);
    field(&mut data[21..23], profile.date_separator, page);
    field(&mut data[23..25], ":", page);
    data[25] = profile.currency_format;
    data[26] = 2;
    data[27] = u8::from(profile.time24);
    field(&mut data[32..34], profile.list_separator, page);
    data
}

/// Only ordinary environment entries cross into programs. These directives
/// configure RetroOS before guests start; inheritance must not turn them into
/// apparent per-process locale settings.
pub fn process_environment(config: &[u8]) -> alloc::vec::Vec<u8> {
    let mut result = alloc::vec::Vec::new();
    for entry in config.split(|&byte| byte == 0).take_while(|entry| !entry.is_empty()) {
        let key = entry.split(|&byte| byte == b'=').next().unwrap_or_default();
        if [b"LOCALE".as_slice(), b"KEYBOARD", b"CODEPAGE"].iter().any(|name| key.eq_ignore_ascii_case(name)) { continue; }
        result.extend_from_slice(entry); result.push(0);
    }
    if result.is_empty() { result.push(0); }
    result.push(0);
    result
}

#[cfg(test)]
mod tests {
    #[test]
    fn locale_directives_are_configuration_not_environment() {
        assert_eq!(super::process_environment(b"locale=it-IT\0KEYBOARD=us\0Codepage=850\0HOME=C:\\CONFIG\0LOCALE_TEST=kept\0\0"),
            b"HOME=C:\\CONFIG\0LOCALE_TEST=kept\0\0");
        assert_eq!(super::process_environment(b"LOCALE=de-DE\0\0"),b"\0\0");
    }
}
