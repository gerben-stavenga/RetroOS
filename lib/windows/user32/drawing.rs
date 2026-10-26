//! Text layout belongs to USER32; GDI supplies metrics and draws glyphs.
use crate::text;
use alloc::{vec, vec::Vec};
unsafe extern "system" {
    fn TextOutW(dc: u32, x: i32, y: i32, text: *const u16, count: i32) -> i32;
    fn GetTextExtentPoint32W(dc: u32, text: *const u16, count: i32, size: *mut [i32; 2]) -> i32;
    fn GetMapMode(dc: u32) -> i32;
}
#[repr(C)]
pub struct Parameters {
    size: u32,
    tab_length: i32,
    left: i32,
    right: i32,
    length: u32,
}
unsafe fn units(p: u32, count: i32, wide: bool) -> Vec<u16> {
    if p == 0 {
        return Vec::new();
    }
    if count < 0 {
        return unsafe { text::read(p, wide) };
    }
    if wide {
        unsafe { core::slice::from_raw_parts(p as *const u16, count as usize) }.to_vec()
    } else {
        let mut bytes =
            unsafe { core::slice::from_raw_parts(p as *const u8, count as usize) }.to_vec();
        bytes.push(0);
        unsafe { text::read(bytes.as_ptr() as u32, false) }
    }
}
fn extent(dc: u32, text: &[u16]) -> [i32; 2] {
    let mut size = [0; 2];
    unsafe {
        GetTextExtentPoint32W(dc, text.as_ptr(), text.len() as i32, &mut size);
    }
    size
}
unsafe fn draw(
    dc: u32,
    p: u32,
    count: i32,
    rect: *mut [i32; 4],
    flags: u32,
    parameters: *mut Parameters,
    wide: bool,
) -> i32 {
    if rect.is_null() || count < -1 {
        return 0;
    }
    let height = extent(dc, &[77])[1].max(1);
    if wide && p == 0 {
        return 0;
    }
    if count == 0 {
        if wide && p != 0 {
            if !parameters.is_null()
                && unsafe { (*parameters).size } != 20
                && unsafe { (p as *const u16).read_unaligned() } == 0
            {
                return 0;
            }
            return height;
        }
        return 0;
    }
    if p == 0 && count != -1 {
        return 0;
    }
    if !parameters.is_null() && unsafe { (*parameters).size } != 20 {
        return 0;
    }
    let input = unsafe { units(p, count, wide) };
    let mut r = unsafe { rect.read_unaligned() };
    let (left, right, tab) = if parameters.is_null() {
        (0, 0, 8)
    } else {
        unsafe {
            (
                (*parameters).left,
                (*parameters).right,
                (*parameters).tab_length.max(1),
            )
        }
    };
    if !parameters.is_null() {
        unsafe {
            (*parameters).length = input.len() as u32;
        }
    }
    if count == 0 {
        return 0;
    }
    let mut value = Vec::new();
    let mut i = 0;
    let tab = if flags & 0x80 != 0 {
        ((flags >> 8) & 255).max(1) as usize
    } else {
        tab as usize
    };
    while i < input.len() {
        let c = input[i];
        i += 1;
        if c == 38 && flags & 0x800 == 0 {
            if i < input.len() {
                value.push(input[i]);
                i += 1;
            }
            continue;
        }
        if c == 9 && flags & 0x40 != 0 {
            let spaces = tab - value.len() % tab;
            value.extend(core::iter::repeat_n(32, spaces));
        } else if flags & 0x20 != 0 && matches!(c, 10 | 13) {
            value.push(32);
        } else {
            value.push(c);
        }
    }
    let height = extent(dc, &[77])[1].max(1);
    let available = (r[2] - r[0] - left - right).max(1);
    let mut lines: Vec<Vec<u16>> = vec![Vec::new()];
    let mut i = 0;
    while i < value.len() {
        let c = value[i];
        i += 1;
        if flags & 0x20 == 0 && matches!(c, 10 | 13) {
            if c == 13 && value.get(i) == Some(&10) {
                i += 1;
            }
            lines.push(Vec::new());
            continue;
        }
        let line = lines.last_mut().unwrap();
        line.push(c);
        if flags & 0x10 != 0
            && flags & 0x20 == 0
            && line.len() > 1
            && extent(dc, line)[0] > available
        {
            let split = line[..line.len() - 1]
                .iter()
                .rposition(|&c| c == 32)
                .unwrap_or(line.len() - 1);
            let mut tail = line.split_off(split);
            if tail.first() == Some(&32) {
                tail.remove(0);
            }
            lines.push(tail);
        }
    }
    let total = height.saturating_mul(lines.len() as i32);
    if flags & 0x400 != 0 {
        let width = lines.iter().map(|l| extent(dc, l)[0]).max().unwrap_or(0);
        r[2] = r[0] + width + left + right;
        r[3] = r[1]
            + if input.is_empty() && flags & 0x20 == 0 {
                0
            } else if matches!(unsafe { GetMapMode(dc) }, 2..=6) {
                -total
            } else {
                total
            };
        unsafe {
            rect.write_unaligned(r);
        }
        return total;
    }
    let mut y = r[1];
    if flags & 0x20 != 0 {
        if flags & 4 != 0 {
            y += (r[3] - r[1] - height) / 2;
        } else if flags & 8 != 0 {
            y = r[3] - height;
        }
    }
    for mut line in lines {
        if flags & 0x8000 != 0 && extent(dc, &line)[0] > available {
            while !line.is_empty()
                && extent(dc, &line)[0] + extent(dc, &[46, 46, 46])[0] > available
            {
                line.pop();
            }
            line.extend_from_slice(&[46, 46, 46]);
        }
        let width = extent(dc, &line)[0];
        let x = if flags & 2 != 0 {
            r[2] - right - width
        } else if flags & 1 != 0 {
            r[0] + left + (available - width) / 2
        } else {
            r[0] + left
        };
        if flags & 0x100 != 0 || y < r[3] {
            unsafe {
                TextOutW(dc, x, y, line.as_ptr(), line.len() as i32);
            }
        }
        y += height;
    }
    total
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DrawTextExA(
    dc: u32,
    p: u32,
    n: i32,
    r: *mut [i32; 4],
    f: u32,
    d: *mut Parameters,
) -> i32 {
    unsafe { draw(dc, p, n, r, f, d, false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DrawTextExW(
    dc: u32,
    p: u32,
    n: i32,
    r: *mut [i32; 4],
    f: u32,
    d: *mut Parameters,
) -> i32 {
    unsafe { draw(dc, p, n, r, f, d, true) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DrawTextA(dc: u32, p: u32, n: i32, r: *mut [i32; 4], f: u32) -> i32 {
    unsafe { draw(dc, p, n, r, f, core::ptr::null_mut(), false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DrawTextW(dc: u32, p: u32, n: i32, r: *mut [i32; 4], f: u32) -> i32 {
    unsafe { draw(dc, p, n, r, f, core::ptr::null_mut(), true) }
}
unsafe fn tabbed(dc: u32, p: u32, n: i32, count: i32, tabs: *const i32, wide: bool) -> u32 {
    if n < 0 || count < 0 || count != 0 && tabs.is_null() {
        return 0;
    }
    let input = unsafe { units(p, n, wide) };
    let unit = extent(dc, &[32])[0];
    let mut parts = input.split(|&c| c == 9);
    let mut x = extent(dc, parts.next().unwrap_or(&[]))[0];
    let stops = if count == 0 {
        &[][..]
    } else {
        unsafe { core::slice::from_raw_parts(tabs, count as usize) }
    };
    for part in parts {
        let width = extent(dc, part)[0];
        let step = if count == 1 { stops[0] } else { unit * 8 };
        let stop = if count > 1 {
            stops.iter().copied().find(|&t| {
                if t < 0 {
                    -t > x + width && -t > x
                } else {
                    t > x
                }
            })
        } else {
            None
        };
        let stop = stop.unwrap_or_else(|| {
            let interval = step.saturating_abs().max(1);
            let next = if step < 0 {
                ((x + width).max(x) / interval + 1) * interval
            } else {
                (x / interval + 1) * interval
            };
            if step < 0 { -next } else { next }
        });
        x = if stop < 0 { -stop } else { stop + width };
    }
    (x as u32 & 0xffff) | ((extent(dc, &[32])[1] as u32 & 0xffff) << 16)
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetTabbedTextExtentA(
    dc: u32,
    p: u32,
    n: i32,
    c: i32,
    t: *const i32,
) -> u32 {
    unsafe { tabbed(dc, p, n, c, t, false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetTabbedTextExtentW(
    dc: u32,
    p: u32,
    n: i32,
    c: i32,
    t: *const i32,
) -> u32 {
    unsafe { tabbed(dc, p, n, c, t, true) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DrawStateA(
    dc: u32,
    _brush: u32,
    callback: u32,
    data: u32,
    w: u32,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    flags: u32,
) -> i32 {
    match flags & 15 {
        1 | 2 => {
            if data == 0 {
                return 0;
            }
            let text = unsafe { units(data, if w == 0 { -1 } else { w as i32 }, false) };
            unsafe { TextOutW(dc, x, y, text.as_ptr(), text.len() as i32) }
        }
        0 if callback != 0 => {
            let callback: unsafe extern "system" fn(u32, u32, u32, i32, i32) -> i32 =
                unsafe { core::mem::transmute(callback) };
            unsafe { callback(dc, data, w, width, height) }
        }
        _ => 0,
    }
}
