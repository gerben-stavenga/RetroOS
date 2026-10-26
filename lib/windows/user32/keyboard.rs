//! The initial keyboard layout is US English. Translation is guest-side policy.
use crate::{state, text};
const KEYS: &[(u32, u32)] = &[
    (0x1b, 1),
    (b'1' as u32, 2),
    (b'2' as u32, 3),
    (b'3' as u32, 4),
    (b'4' as u32, 5),
    (b'5' as u32, 6),
    (b'6' as u32, 7),
    (b'7' as u32, 8),
    (b'8' as u32, 9),
    (b'9' as u32, 10),
    (b'0' as u32, 11),
    (0xbd, 12),
    (0xbb, 13),
    (8, 14),
    (9, 15),
    (81, 16),
    (87, 17),
    (69, 18),
    (82, 19),
    (84, 20),
    (89, 21),
    (85, 22),
    (73, 23),
    (79, 24),
    (80, 25),
    (0xdb, 26),
    (0xdd, 27),
    (13, 28),
    (0xa2, 29),
    (65, 30),
    (83, 31),
    (68, 32),
    (70, 33),
    (71, 34),
    (72, 35),
    (74, 36),
    (75, 37),
    (76, 38),
    (0xba, 39),
    (0xde, 40),
    (0xc0, 41),
    (0xa0, 42),
    (0xdc, 43),
    (90, 44),
    (88, 45),
    (67, 46),
    (86, 47),
    (66, 48),
    (78, 49),
    (77, 50),
    (0xbc, 51),
    (0xbe, 52),
    (0xbf, 53),
    (0xa1, 54),
    (0x6a, 55),
    (0xa4, 56),
    (32, 57),
    (0x14, 58),
    (0x70, 59),
    (0x71, 60),
    (0x72, 61),
    (0x73, 62),
    (0x74, 63),
    (0x75, 64),
    (0x76, 65),
    (0x77, 66),
    (0x78, 67),
    (0x79, 68),
    (0x90, 69),
    (0x91, 70),
    (0x67, 71),
    (0x68, 72),
    (0x69, 73),
    (0x6d, 74),
    (0x64, 75),
    (0x65, 76),
    (0x66, 77),
    (0x6b, 78),
    (0x61, 79),
    (0x62, 80),
    (0x63, 81),
    (0x60, 82),
    (0x6e, 83),
    (0x7a, 87),
    (0x7b, 88),
    (0xa3, 0xe01d),
    (0xa5, 0xe038),
    (0x24, 0xe047),
    (0x26, 0xe048),
    (0x21, 0xe049),
    (0x25, 0xe04b),
    (0x27, 0xe04d),
    (0x23, 0xe04f),
    (0x28, 0xe050),
    (0x22, 0xe051),
    (0x2d, 0xe052),
    (0x2e, 0xe053),
];
fn character(key: u32, shift: bool, caps: bool) -> u16 {
    match key {
        65..=90 => (if shift ^ caps { key } else { key + 32 }) as u16,
        48..=57 => {
            if shift {
                b")!@#$%^&*("[(key - 48) as usize] as u16
            } else {
                key as u16
            }
        }
        0x60..=0x69 => (key - 0x60 + 48) as u16,
        8 | 9 | 13 | 27 | 32 => key as u16,
        0xba => {
            if shift {
                58
            } else {
                59
            }
        }
        0xbb => {
            if shift {
                43
            } else {
                61
            }
        }
        0xbc => {
            if shift {
                60
            } else {
                44
            }
        }
        0xbd => {
            if shift {
                95
            } else {
                45
            }
        }
        0xbe => {
            if shift {
                62
            } else {
                46
            }
        }
        0xbf => {
            if shift {
                63
            } else {
                47
            }
        }
        0xc0 => {
            if shift {
                126
            } else {
                96
            }
        }
        0xdb => {
            if shift {
                123
            } else {
                91
            }
        }
        0xdc => {
            if shift {
                124
            } else {
                92
            }
        }
        0xdd => {
            if shift {
                125
            } else {
                93
            }
        }
        0xde => {
            if shift {
                34
            } else {
                39
            }
        }
        0x6a => 42,
        0x6b => 43,
        0x6d => 45,
        0x6e => 46,
        0x6f => 47,
        _ => 0,
    }
}
#[unsafe(no_mangle)]
pub extern "system" fn GetKeyboardLayout(_thread: u32) -> u32 {
    0x04090409
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetKeyboardLayoutNameA(out: *mut u8) -> i32 {
    if out.is_null() {
        return 0;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(b"00000409\0".as_ptr(), out, 9);
    }
    1
}
#[unsafe(no_mangle)]
pub extern "system" fn MapVirtualKeyExA(code: u32, kind: u32, _layout: u32) -> u32 {
    match kind {
        0 | 4 => {
            let code = match code {
                16 => 0xa0,
                17 => 0xa2,
                18 => 0xa4,
                _ => code,
            };
            KEYS.iter()
                .find(|p| p.0 == code)
                .map_or(0, |p| if kind == 0 { p.1 & 255 } else { p.1 })
        }
        1 | 3 => {
            let code = if matches!(code,0x47..=0x49|0x4b|0x4d|0x4f..=0x53) {
                code | 0xe000
            } else {
                code
            };
            let key = KEYS.iter().find(|p| p.1 == code).map_or(0, |p| p.0);
            if kind == 1 {
                match key {
                    0xa0 | 0xa1 => 16,
                    0xa2 | 0xa3 => 17,
                    0xa4 | 0xa5 => 18,
                    _ => key,
                }
            } else {
                key
            }
        }
        2 => u32::from(character(code, false, (65..=90).contains(&code))),
        _ => 0,
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetKeyNameTextA(bits: i32, out: u32, count: i32) -> i32 {
    if out != 0 && count > 0 {
        unsafe {
            (out as *mut u8).write(0);
        }
    }
    let scan = ((bits as u32 >> 16) & 255)
        | if bits as u32 & 0x1000000 != 0 {
            0xe000
        } else {
            0
        };
    let key = MapVirtualKeyExA(scan, 3, 0);
    let name = match key {
        8 => "Backspace",
        9 => "Tab",
        13 => "Enter",
        27 => "Esc",
        32 => "Space",
        0xa0 => "Shift",
        0xa1 => "Right Shift",
        0xa2 => "Ctrl",
        0xa3 => "Right Ctrl",
        0xa4 => "Alt",
        0xa5 => "Right Alt",
        0x14 => "Caps Lock",
        0x25 => "Left",
        0x26 => "Up",
        0x27 => "Right",
        0x28 => "Down",
        _ => "",
    };
    let value = if name.is_empty() {
        let c = MapVirtualKeyExA(key, 2, 0) as u16;
        if c == 0 {
            return 0;
        }
        alloc::vec![c]
    } else {
        name.encode_utf16().collect()
    };
    unsafe { text::write(out, count, &value, false) as i32 }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn ToUnicode(
    key: u32,
    scan: u32,
    keys: *const u8,
    out: *mut u16,
    count: i32,
    _flags: u32,
) -> i32 {
    if keys.is_null() || out.is_null() || count <= 0 {
        return state::error(87) as i32;
    }
    if scan & 0x8000 != 0 {
        return 0;
    }
    let shift = unsafe { keys.add(16).read() } & 0x80 != 0;
    let ctrl = unsafe { keys.add(17).read() } & 0x80 != 0;
    let alt = unsafe { keys.add(18).read() } & 0x80 != 0;
    let caps = unsafe { keys.add(20).read() } & 1 != 0;
    if alt {
        return 0;
    }
    let c = if ctrl {
        match key {
            65..=90 => (key - 64) as u16,
            13 if !shift => 10,
            8 => 127,
            32 => 32,
            0xdb => 27,
            0xdc => 28,
            0xdd => 29,
            _ => return 0,
        }
    } else {
        character(key, shift, caps)
    };
    if c == 0 {
        return 0;
    }
    unsafe {
        out.write_unaligned(c);
    }
    1
}

/// The transport supplies make/break scancodes, not Windows virtual keys.
pub fn input(s: &mut state::State, m: &mut crate::Message) {
    if m.message != 0x100 && m.message != 0x101 {
        return;
    }
    let scan = m.wparam;
    let key = MapVirtualKeyExA(scan, 1, 0);
    if key >= 256 {
        return;
    }
    let down = m.message == 0x100;
    let old = s.keyboard[key as usize];
    let toggle = if down && old & 0x80 == 0 && matches!(key, 20 | 144 | 145) {
        old ^ 1
    } else {
        old
    };
    s.keyboard[key as usize] = (toggle & 1) | if down { 0x80 } else { 0 };
    m.wparam = key;
    m.lparam = 1
        | ((scan & 255) << 16)
        | if down {
            if old & 0x80 != 0 { 1 << 30 } else { 0 }
        } else {
            3 << 30
        };
    let thread = s
        .windows
        .iter()
        .find(|w| w.hwnd == m.hwnd)
        .map(|w| w.thread);
    if let Some(focus) = s
        .inputs
        .iter()
        .find(|i| Some(i.thread) == thread && i.focus != 0)
        .map(|i| i.focus)
    {
        m.hwnd = focus;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn TranslateMessage(message: *const crate::Message) -> i32 {
    if message.is_null() {
        return 0;
    }
    let m = unsafe { message.read_unaligned() };
    if !matches!(m.message, 0x100 | 0x101 | 0x104 | 0x105) {
        return 0;
    }
    if m.message == 0x100 || m.message == 0x104 {
        let keys = state::with(|s| s.keyboard);
        let mut text = [0u16; 4];
        let n = unsafe {
            ToUnicode(
                m.wparam,
                (m.lparam >> 16) & 255,
                keys.as_ptr(),
                text.as_mut_ptr(),
                4,
                0,
            )
        };
        for &c in text.iter().take(n.max(0) as usize) {
            crate::message::PostMessageW(
                m.hwnd,
                if m.message == 0x104 { 0x106 } else { 0x102 },
                u32::from(c),
                m.lparam,
            );
        }
    }
    1
}
