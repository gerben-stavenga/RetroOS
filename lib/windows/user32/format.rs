//! USER32's bounded, integer-only Windows formatting APIs. The cdecl varargs
//! entry is a tiny assembly adapter to this explicit guest argument pointer.
use crate::text;
use alloc::vec::Vec;

unsafe fn next(args: &mut *const u32) -> u32 {
    let value = unsafe { args.read_unaligned() };
    *args = unsafe { args.add(1) };
    value
}
unsafe fn format(out: u32, fmt: u32, mut args: *const u32, wide: bool) -> i32 {
    let format = unsafe { text::read(fmt, wide) };
    let mut result: Vec<u16> = Vec::new();
    let mut i = 0;
    while i < format.len() && result.len() < 1023 {
        let c = format[i];
        i += 1;
        if c != b'%' as u16 {
            result.push(c);
            continue;
        }
        if format.get(i) == Some(&(b'%' as u16)) {
            i += 1;
            result.push(b'%' as u16);
            continue;
        }
        let (mut left, mut zero, mut alternate) = (false, false, false);
        loop {
            match format.get(i).copied().unwrap_or(0) as u8 {
                b'-' => left = true,
                b'0' => zero = true,
                b'#' => alternate = true,
                _ => break,
            }
            i += 1;
        }
        let mut width: usize = 0;
        while let Some(c) = format.get(i).copied().filter(|c| (48..=57).contains(c)) {
            width = (width * 10 + (c - 48) as usize).min(1024);
            i += 1;
        }
        let mut precision = None;
        if format.get(i) == Some(&46) {
            i += 1;
            let mut n = 0usize;
            while let Some(c) = format.get(i).copied().filter(|c| (48..=57).contains(c)) {
                n = (n * 10 + (c - 48) as usize).min(1024);
                i += 1;
            }
            precision = Some(n);
        }
        let mut length = 0;
        if matches!(format.get(i), Some(104 | 108 | 119)) {
            length = format[i];
            i += 1;
        }
        let int64 = format.get(i..i + 3) == Some(&[73, 54, 52]);
        if int64 {
            i += 3;
        }
        let Some(kind) = format.get(i).copied() else {
            break;
        };
        i += 1;
        let mut prefix = Vec::new();
        let mut value = Vec::new();
        match kind as u8 {
            b's' | b'S' | b'c' | b'C' => {
                let pointer = unsafe { next(&mut args) };
                let input_wide = match length {
                    104 => false,
                    108 | 119 => true,
                    _ => wide != (kind == 83 || kind == 67),
                };
                if kind == 115 || kind == 83 {
                    value = if pointer == 0 {
                        Vec::new()
                    } else {
                        unsafe { text::read(pointer, input_wide) }
                    };
                    if let Some(n) = precision {
                        value.truncate(n);
                    }
                } else if input_wide {
                    value.push(pointer as u16);
                } else {
                    let bytes = [pointer as u8, 0];
                    value = unsafe { text::read(bytes.as_ptr() as u32, false) };
                }
                zero = false;
            }
            b'd' | b'i' | b'u' | b'x' | b'X' | b'p' => {
                let low = unsafe { next(&mut args) };
                let mut number = if int64 {
                    u64::from(low) | (u64::from(unsafe { next(&mut args) }) << 32)
                } else {
                    u64::from(low)
                };
                let signed = kind == 100 || kind == 105;
                if signed {
                    let n = if int64 {
                        number as i64
                    } else {
                        i64::from(low as i32)
                    };
                    if n < 0 {
                        prefix.push(45);
                        number = n.unsigned_abs();
                    }
                }
                let hex = matches!(kind as u8, b'x' | b'X' | b'p');
                let upper = kind != 120;
                if alternate && hex && number != 0 {
                    prefix.extend_from_slice(if upper { &[48, 88] } else { &[48, 120] });
                }
                let base = if hex { 16 } else { 10 };
                let mut digits = [0u16; 64];
                let mut count = 0;
                loop {
                    let digit = (number % base) as u16;
                    digits[count] = if digit < 10 {
                        48 + digit
                    } else {
                        (if upper { 65 } else { 97 }) + digit - 10
                    };
                    count += 1;
                    number /= base;
                    if number == 0 {
                        break;
                    }
                }
                let minimum = if kind == 112 {
                    8
                } else {
                    precision.unwrap_or(0)
                };
                for _ in count..minimum {
                    value.push(48);
                }
                value.extend(digits[..count].iter().rev());
            }
            _ => {
                result.push(kind);
                continue;
            }
        }
        let padding = width.saturating_sub(prefix.len() + value.len());
        if !left && !zero {
            for _ in 0..padding {
                result.push(32);
            }
        }
        result.extend(prefix);
        if !left && zero {
            for _ in 0..padding {
                result.push(48);
            }
        }
        result.extend(value);
        if left {
            for _ in 0..padding {
                result.push(32);
            }
        }
    }
    unsafe { text::write(out, 1024, &result, wide) as i32 }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn wvsprintfA(out: u32, fmt: u32, args: *const u32) -> i32 {
    unsafe { format(out, fmt, args, false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn wvsprintfW(out: u32, fmt: u32, args: *const u32) -> i32 {
    unsafe { format(out, fmt, args, true) }
}
