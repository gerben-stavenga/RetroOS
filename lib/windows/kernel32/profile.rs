//! INI parsing is guest-side KERNEL32 policy.
use alloc::{vec, vec::Vec};
unsafe extern "system" {
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: u32,
        creation: u32,
        flags: u32,
        template: u32,
    ) -> u32;
    fn ReadFile(h: u32, out: *mut u8, n: u32, read: *mut u32, overlapped: u32) -> i32;
    fn CloseHandle(h: u32) -> i32;
    fn MultiByteToWideChar(
        cp: u32,
        flags: u32,
        input: *const u8,
        n: i32,
        out: *mut u16,
        capacity: i32,
    ) -> i32;
}
unsafe fn string(p: *const u16) -> Vec<u16> {
    if p.is_null() {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut i = 0;
    loop {
        let c = unsafe { p.add(i).read_unaligned() };
        if c == 0 {
            break;
        }
        result.push(c);
        i += 1;
    }
    result
}
fn trim(s: &[u16]) -> &[u16] {
    let a = s.iter().position(|&c| c != 32 && c != 9).unwrap_or(s.len());
    let b = s
        .iter()
        .rposition(|&c| c != 32 && c != 9)
        .map_or(a, |i| i + 1);
    &s[a..b]
}
fn same(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(&a, &b)| {
            let lower = |c| if (65..=90).contains(&c) { c + 32 } else { c };
            lower(a) == lower(b)
        })
}
unsafe fn read(path: *const u16) -> Vec<u16> {
    let mut path = unsafe { string(path) };
    if path.is_empty() {
        path = "win.ini".encode_utf16().collect();
    }
    if !path.iter().any(|&c| c == 58 || c == 92 || c == 47) {
        let mut full: Vec<u16> = "C:\\WINDOWS\\".encode_utf16().collect();
        full.extend_from_slice(&path);
        path = full;
    }
    path.push(0);
    let h = unsafe { CreateFileW(path.as_ptr(), 0x80000000, 3, 0, 3, 0, 0) };
    if h == u32::MAX {
        return Vec::new();
    }
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let mut n = 0;
        if unsafe { ReadFile(h, buffer.as_mut_ptr(), buffer.len() as u32, &mut n, 0) } == 0
            || n == 0
        {
            break;
        }
        bytes.extend_from_slice(&buffer[..n as usize]);
    }
    unsafe {
        CloseHandle(h);
    }
    if bytes.starts_with(&[255, 254]) {
        return bytes[2..]
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
    }
    let mut result = vec![0u16; bytes.len()];
    let n = unsafe {
        MultiByteToWideChar(
            0,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            result.as_mut_ptr(),
            result.len() as i32,
        )
    };
    result.truncate(n.max(0) as usize);
    result
}
unsafe fn lookup(section: *const u16, key: *const u16, path: *const u16) -> Option<Vec<u16>> {
    let section_name = unsafe { string(section) };
    let key_name = unsafe { string(key) };
    let data = unsafe { read(path) };
    let mut matched = false;
    let mut list = Vec::new();
    for line in data.split(|&c| c == 10) {
        let line = trim(line.strip_suffix(&[13]).unwrap_or(line));
        if line.is_empty() || line[0] == 59 {
            continue;
        }
        if line[0] == 91 {
            if let Some(end) = line.iter().position(|&c| c == 93) {
                let name = trim(&line[1..end]);
                matched = same(name, &section_name);
                if section.is_null() {
                    list.extend_from_slice(name);
                    list.push(0);
                }
            }
            continue;
        }
        if !matched {
            continue;
        }
        let Some(equal) = line.iter().position(|&c| c == 61) else {
            continue;
        };
        let name = trim(&line[..equal]);
        if key.is_null() {
            list.extend_from_slice(name);
            list.push(0);
            continue;
        }
        if same(name, &key_name) {
            let value = trim(&line[equal + 1..]);
            return Some(
                if value.len() >= 2
                    && (value[0] == 34 || value[0] == 39)
                    && value.last() == Some(&value[0])
                {
                    value[1..value.len() - 1].to_vec()
                } else {
                    value.to_vec()
                },
            );
        }
    }
    if section.is_null() || key.is_null() {
        Some(list)
    } else {
        None
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetPrivateProfileStringW(
    section: *const u16,
    key: *const u16,
    default: *const u16,
    out: *mut u16,
    capacity: u32,
    path: *const u16,
) -> u32 {
    if out.is_null() || capacity == 0 {
        return 0;
    }
    let list = section.is_null() || key.is_null();
    let value = unsafe { lookup(section, key, path) }.unwrap_or_else(|| {
        let mut value = unsafe { string(default) };
        while value.last() == Some(&32) {
            value.pop();
        }
        value
    });
    // Lists already contain each name's terminator. Only a truncated list
    // needs two reserved slots; a complete list needs one additional NUL.
    let reserve = if list && value.len() >= capacity as usize {
        2
    } else {
        1
    };
    let n = value.len().min((capacity as usize).saturating_sub(reserve));
    unsafe {
        core::ptr::copy_nonoverlapping(value.as_ptr(), out, n);
        out.add(n).write(0);
        if list && n + 1 < capacity as usize {
            out.add(n + 1).write(0);
        }
    }
    n as u32
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetPrivateProfileIntW(
    section: *const u16,
    key: *const u16,
    default: i32,
    path: *const u16,
) -> u32 {
    let Some(value) = (unsafe { lookup(section, key, path) }) else {
        return default as u32;
    };
    let mut v = trim(&value);
    let negative = v.first() == Some(&45);
    if negative || v.first() == Some(&43) {
        v = &v[1..];
    }
    let radix = if v.starts_with(&[48, 120]) || v.starts_with(&[48, 88]) {
        v = &v[2..];
        16
    } else {
        10
    };
    let mut n = 0u32;
    for &c in v {
        let d = match c {
            48..=57 => u32::from(c - 48),
            65..=70 => u32::from(c - 65 + 10),
            97..=102 => u32::from(c - 97 + 10),
            _ => break,
        };
        if d >= radix {
            break;
        }
        n = n.wrapping_mul(radix).wrapping_add(d);
    }
    if negative { n.wrapping_neg() } else { n }
}
