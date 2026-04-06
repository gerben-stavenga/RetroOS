//! Keyboard input — scancode-to-ASCII conversion tables and key state
//!
//! Pure utility: scancode tables and shift-state tracking.
//! OS personalities (Linux TTY, DOS BIOS) call into this for conversion.

const LSHIFT: u8 = 0x2A;
const RSHIFT: u8 = 0x36;

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

/// Convert a scancode to ASCII using current shift state. Returns 0 for non-printable keys.
pub fn scancode_to_ascii(scancode: u8) -> u8 {
    let key = scancode & 0x7F;
    if key as usize >= KBD_US.len() { return 0; }
    let shift = key_down(LSHIFT) || key_down(RSHIFT);
    let c = if shift { KBD_US_SHIFT[key as usize] } else { KBD_US[key as usize] };
    if c <= 0 { 0 } else { c as u8 }
}
