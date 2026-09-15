//! Keyboard input — scancode-to-ASCII conversion tables and key state
//!
//! Pure utility: scancode tables and shift-state tracking.
//! OS personalities (Linux TTY, DOS BIOS) call into this for conversion.

const LSHIFT: u8 = 0x2A;
const RSHIFT: u8 = 0x36;
const LCTRL: u8 = 0x1D;

/// US-layout printable-key map used in both directions.
#[rustfmt::skip]
const ASCII_KEYS: &[(u8, u8, u8)] = &[
    (0x02,b'1',b'!'),(0x03,b'2',b'@'),(0x04,b'3',b'#'),(0x05,b'4',b'$'),(0x06,b'5',b'%'),
    (0x07,b'6',b'^'),(0x08,b'7',b'&'),(0x09,b'8',b'*'),(0x0A,b'9',b'('),(0x0B,b'0',b')'),
    (0x0C,b'-',b'_'),(0x0D,b'=',b'+'),
    (0x10,b'q',b'Q'),(0x11,b'w',b'W'),(0x12,b'e',b'E'),(0x13,b'r',b'R'),(0x14,b't',b'T'),
    (0x15,b'y',b'Y'),(0x16,b'u',b'U'),(0x17,b'i',b'I'),(0x18,b'o',b'O'),(0x19,b'p',b'P'),
    (0x1A,b'[',b'{'),(0x1B,b']',b'}'),
    (0x1E,b'a',b'A'),(0x1F,b's',b'S'),(0x20,b'd',b'D'),(0x21,b'f',b'F'),(0x22,b'g',b'G'),
    (0x23,b'h',b'H'),(0x24,b'j',b'J'),(0x25,b'k',b'K'),(0x26,b'l',b'L'),(0x27,b';',b':'),
    (0x28,b'\'',b'"'),(0x29,b'`',b'~'),(0x2B,b'\\',b'|'),
    (0x2C,b'z',b'Z'),(0x2D,b'x',b'X'),(0x2E,b'c',b'C'),(0x2F,b'v',b'V'),(0x30,b'b',b'B'),
    (0x31,b'n',b'N'),(0x32,b'm',b'M'),(0x33,b',',b'<'),(0x34,b'.',b'>'),(0x35,b'/',b'?'),
];

/// Scancode-to-ASCII table (US layout, unshifted)
/// Negative values = special keys (ignored), 0 = undefined, positive = ASCII
#[rustfmt::skip]
const KBD_US: [i8; 128] = [
    0, 27,
    b'1' as i8, b'2' as i8, b'3' as i8, b'4' as i8, b'5' as i8,
    b'6' as i8, b'7' as i8, b'8' as i8, b'9' as i8, b'0' as i8,
    b'-' as i8, b'=' as i8, 8, b'\t' as i8,
    b'q' as i8, b'w' as i8, b'e' as i8, b'r' as i8, b't' as i8,
    b'y' as i8, b'u' as i8, b'i' as i8, b'o' as i8, b'p' as i8,
    b'[' as i8, b']' as i8, b'\n' as i8, -29,
    b'a' as i8, b's' as i8, b'd' as i8, b'f' as i8, b'g' as i8,
    b'h' as i8, b'j' as i8, b'k' as i8, b'l' as i8,
    b';' as i8, b'\'' as i8, b'`' as i8, -42, b'\\' as i8,
    b'z' as i8, b'x' as i8, b'c' as i8, b'v' as i8, b'b' as i8,
    b'n' as i8, b'm' as i8,
    b',' as i8, b'.' as i8, b'/' as i8, -54, b'*' as i8, -56, b' ' as i8,
    -58, -59, -60, -61, -62, -63, -64, -65, -66, -67, -68,
    -69, -70, -71, -72, -73, b'-' as i8, -75, 0, -77, b'+' as i8,
    -79, -80, -81, -82, -83, 0, 0, 0, -87, -88,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Scancode-to-ASCII table (US layout, shifted)
#[rustfmt::skip]
const KBD_US_SHIFT: [i8; 128] = [
    0, 27,
    b'!' as i8, b'@' as i8, b'#' as i8, b'$' as i8, b'%' as i8,
    b'^' as i8, b'&' as i8, b'*' as i8, b'(' as i8, b')' as i8,
    b'_' as i8, b'+' as i8, 8, b'\t' as i8,
    b'Q' as i8, b'W' as i8, b'E' as i8, b'R' as i8, b'T' as i8,
    b'Y' as i8, b'U' as i8, b'I' as i8, b'O' as i8, b'P' as i8,
    b'{' as i8, b'}' as i8, b'\n' as i8, -29,
    b'A' as i8, b'S' as i8, b'D' as i8, b'F' as i8, b'G' as i8,
    b'H' as i8, b'J' as i8, b'K' as i8, b'L' as i8,
    b':' as i8, b'"' as i8, b'~' as i8, -42, b'|' as i8,
    b'Z' as i8, b'X' as i8, b'C' as i8, b'V' as i8, b'B' as i8,
    b'N' as i8, b'M' as i8,
    b'<' as i8, b'>' as i8, b'?' as i8, -54, b'*' as i8, -56, b' ' as i8,
    -58, -59, -60, -61, -62, -63, -64, -65, -66, -67, -68,
    -69, -70, -71, -72, -73, b'-' as i8, -75, 0, -77, b'+' as i8,
    -79, -80, -81, -82, -83, 0, 0, 0, -87, -88,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Per-key up/down state (128 keys, 1 bit each = 16 bytes)
static mut KEY_STATE: [u8; 16] = [0; 16];

fn key_down(key: u8) -> bool {
    unsafe { KEY_STATE[(key >> 3) as usize] & (1 << (key & 7)) != 0 }
}

/// Update key up/down state from a raw scancode. Returns true if key was pressed (not released).
pub fn update_key_state(scancode: u8) -> bool {
    let key = scancode & 0x7F;
    let released = scancode & 0x80 != 0;
    unsafe {
        if released {
            KEY_STATE[(key >> 3) as usize] &= !(1 << (key & 7));
        } else {
            KEY_STATE[(key >> 3) as usize] |= 1 << (key & 7);
        }
    }
    !released
}

/// Convert a scancode to ASCII using current shift/ctrl state. Returns 0 for non-printable keys.
pub fn scancode_to_ascii(scancode: u8) -> u8 {
    let key = scancode & 0x7F;
    if key as usize >= KBD_US.len() { return 0; }
    let shift = key_down(LSHIFT) || key_down(RSHIFT);
    let c = if shift { KBD_US_SHIFT[key as usize] } else { KBD_US[key as usize] };
    if c <= 0 { return 0; }
    let c = c as u8;
    // Ctrl-A..Ctrl-Z → 0x01..0x1A; case-insensitive.
    if key_down(LCTRL) {
        let lower = c | 0x20;
        if lower.is_ascii_lowercase() { return lower - b'a' + 1; }
    }
    c
}

/// Convert one ASCII byte to a complete Set-1 make/break sequence. The fixed
/// result avoids allocating in serial-control input. Unsupported bytes return
/// a zero length.
pub fn ascii_to_scancodes(byte: u8) -> ([u8; 4], usize) {
    let tap = |scancode: u8| ([scancode, scancode | 0x80, 0, 0], 2);
    match byte {
        b'\r' | b'\n' => return tap(0x1C),
        0x08 | 0x7F => return tap(0x0E),
        b'\t' => return tap(0x0F),
        0x1B => return tap(0x01),
        b' ' => return tap(0x39),
        _ => {}
    }
    if (0x01..=0x1A).contains(&byte) {
        let letter = byte + b'a' - 1;
        if let Some(&(scancode, _, _)) = ASCII_KEYS.iter().find(|(_, plain, _)| *plain == letter) {
            return ([LCTRL, scancode, scancode | 0x80, LCTRL | 0x80], 4);
        }
    }
    for &(scancode, plain, shifted) in ASCII_KEYS {
        if byte == plain { return tap(scancode); }
        if byte == shifted {
            return ([LSHIFT, scancode, scancode | 0x80, LSHIFT | 0x80], 4);
        }
    }
    ([0; 4], 0)
}

#[cfg(test)]
mod reverse_tests {
    use super::ascii_to_scancodes;

    #[test]
    fn ascii_produces_complete_key_taps() {
        assert_eq!(ascii_to_scancodes(b'a'), ([0x1E, 0x9E, 0, 0], 2));
        assert_eq!(ascii_to_scancodes(b'A'), ([0x2A, 0x1E, 0x9E, 0xAA], 4));
        assert_eq!(ascii_to_scancodes(b'\n'), ([0x1C, 0x9C, 0, 0], 2));
    }
}
