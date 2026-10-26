use alloc::{string::String, vec, vec::Vec};

unsafe extern "system" {
    fn MultiByteToWideChar(
        cp: u32,
        flags: u32,
        input: *const u8,
        bytes: i32,
        output: *mut u16,
        count: i32,
    ) -> i32;
    fn WideCharToMultiByte(
        cp: u32,
        flags: u32,
        input: *const u16,
        count: i32,
        output: *mut u8,
        bytes: i32,
        default: u32,
        used: u32,
    ) -> i32;
}

pub unsafe fn read(address: u32, wide: bool) -> Vec<u16> {
    if address == 0 {
        return Vec::new();
    }
    if wide {
        let mut result = Vec::new();
        let mut p = address as *const u16;
        loop {
            let c = unsafe { p.read_unaligned() };
            if c == 0 {
                return result;
            }
            result.push(c);
            p = unsafe { p.add(1) };
        }
    }
    let n =
        unsafe { MultiByteToWideChar(0, 0, address as *const u8, -1, core::ptr::null_mut(), 0) };
    if n <= 0 {
        return Vec::new();
    }
    let mut result = vec![0; n as usize];
    unsafe {
        MultiByteToWideChar(0, 0, address as *const u8, -1, result.as_mut_ptr(), n);
    }
    result.pop();
    result
}
pub fn same(a: &[u16], b: &[u16]) -> bool {
    String::from_utf16_lossy(a).to_lowercase() == String::from_utf16_lossy(b).to_lowercase()
}
pub fn ansi(text: &[u16]) -> Vec<u8> {
    if text.is_empty() {
        return Vec::new();
    }
    let n = unsafe {
        WideCharToMultiByte(
            0,
            0,
            text.as_ptr(),
            text.len() as i32,
            core::ptr::null_mut(),
            0,
            0,
            0,
        )
    };
    let mut result = vec![0; n.max(0) as usize];
    if n > 0 {
        unsafe {
            WideCharToMultiByte(
                0,
                0,
                text.as_ptr(),
                text.len() as i32,
                result.as_mut_ptr(),
                n,
                0,
                0,
            );
        }
    }
    result
}
pub unsafe fn write(address: u32, capacity: i32, text: &[u16], wide: bool) -> u32 {
    if address == 0 || capacity <= 0 {
        return 0;
    }
    if wide {
        let n = text.len().min(capacity as usize - 1);
        for (i, &c) in text[..n].iter().enumerate() {
            unsafe {
                (address as *mut u16).add(i).write_unaligned(c);
            }
        }
        unsafe {
            (address as *mut u16).add(n).write_unaligned(0);
        }
        n as u32
    } else {
        let bytes = ansi(text);
        let n = bytes.len().min(capacity as usize - 1);
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, n);
            (address as *mut u8).add(n).write(0);
        }
        n as u32
    }
}

unsafe fn case(value: u32, wide: bool, upper: bool) -> u32 {
    if value == 0 {
        return 0;
    }
    let scalar = value <= 0xffff;
    let bytes = [value as u8, 0];
    let mut chars = if scalar {
        if wide {
            vec![value as u16]
        } else {
            unsafe { read(bytes.as_ptr() as u32, false) }
        }
    } else {
        unsafe { read(value, wide) }
    };
    for c in &mut chars {
        if let Some(ch) = char::from_u32(*c as u32) {
            let mapped = if upper {
                ch.to_uppercase().next().unwrap()
            } else {
                ch.to_lowercase().next().unwrap()
            };
            if mapped as u32 <= 0xffff {
                *c = mapped as u16;
            }
        }
    }
    if scalar {
        if wide {
            chars.first().copied().unwrap_or(0) as u32
        } else {
            ansi(&chars).first().copied().unwrap_or(0) as u32
        }
    } else {
        unsafe {
            write(value, (chars.len() + 1) as i32, &chars, wide);
        }
        value
    }
}
macro_rules! case_api {
    ($name:ident, $wide:expr, $upper:expr) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $name(value: u32) -> u32 {
            unsafe { case(value, $wide, $upper) }
        }
    };
}
case_api!(CharUpperA, false, true);
case_api!(CharUpperW, true, true);
case_api!(CharLowerA, false, false);
case_api!(CharLowerW, true, false);
