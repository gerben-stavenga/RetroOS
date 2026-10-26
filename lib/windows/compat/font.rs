//! Font objects describe requests; the raster backend currently supplies the
//! stock 8x16 bitmap font. Metrics report the font actually drawn.
use crate::{Rect, with};
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LogFont {
    height: i32,
    width: i32,
    escapement: i32,
    orientation: i32,
    weight: i32,
    italic: u8,
    underline: u8,
    strikeout: u8,
    charset: u8,
    out_precision: u8,
    clip_precision: u8,
    quality: u8,
    pitch: u8,
    face: [u16; 32],
}
fn stock() -> LogFont {
    let mut f = LogFont {
        height: 16,
        width: 8,
        escapement: 0,
        orientation: 0,
        weight: 400,
        italic: 0,
        underline: 0,
        strikeout: 0,
        charset: 0,
        out_precision: 0,
        clip_precision: 0,
        quality: 0,
        pitch: 1,
        face: [0; 32],
    };
    for (i, c) in "System".encode_utf16().enumerate() {
        f.face[i] = c;
    }
    f
}
unsafe extern "system" {
    fn RetroGdiSelectObject(dc: u32, object: u32) -> u32;
    fn RetroGdiObject(object: u32, size: u32, out: u32) -> i32;
    fn TextOutW(dc: u32, x: i32, y: i32, text: *const u16, count: i32) -> i32;
    fn MultiByteToWideChar(
        cp: u32,
        flags: u32,
        input: *const u8,
        count: i32,
        output: *mut u16,
        capacity: i32,
    ) -> i32;
}
pub fn is_font(h: u32) -> bool {
    h == 1
        || (0x3000a..=0x3000e).contains(&h)
        || h == 0x30010
        || h == 0x30011
        || with(|s| s.fonts.iter().any(|(id, _)| *id == h))
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn CreateFontIndirectW(p: *const LogFont) -> u32 {
    if p.is_null() {
        return 0;
    }
    let f = unsafe { p.read_unaligned() };
    with(|s| {
        let h = s.next;
        s.next += 1;
        s.fonts.push((h, f));
        h
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn CreateFontIndirectA(p: *const u8) -> u32 {
    if p.is_null() {
        return 0;
    }
    let mut f = stock();
    unsafe {
        core::ptr::copy_nonoverlapping(p, (&raw mut f).cast::<u8>(), 28);
    }
    let mut count = 0;
    while count < 32 && unsafe { p.add(28 + count).read() } != 0 {
        count += 1;
    }
    f.face = [0; 32];
    unsafe {
        MultiByteToWideChar(0, 0, p.add(28), count as i32, f.face.as_mut_ptr(), 31);
        CreateFontIndirectW(&f)
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn CreateFontW(
    h: i32,
    w: i32,
    e: i32,
    o: i32,
    weight: i32,
    i: u32,
    u: u32,
    s: u32,
    c: u32,
    op: u32,
    cp: u32,
    q: u32,
    p: u32,
    face: *const u16,
) -> u32 {
    let mut f = LogFont {
        height: h,
        width: w,
        escapement: e,
        orientation: o,
        weight,
        italic: i as u8,
        underline: u as u8,
        strikeout: s as u8,
        charset: c as u8,
        out_precision: op as u8,
        clip_precision: cp as u8,
        quality: q as u8,
        pitch: p as u8,
        face: [0; 32],
    };
    if !face.is_null() {
        for n in 0..31 {
            let c = unsafe { face.add(n).read_unaligned() };
            f.face[n] = c;
            if c == 0 {
                break;
            }
        }
    }
    unsafe { CreateFontIndirectW(&f) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SelectObject(dc: u32, obj: u32) -> u32 {
    if !is_font(obj) {
        return unsafe { RetroGdiSelectObject(dc, obj) };
    }
    let mut r = Rect::default();
    if unsafe { crate::RetroGdiBounds(dc, &mut r) } == 0 {
        return 0;
    }
    with(|s| {
        if let Some((_, old)) = s.selected_fonts.iter_mut().find(|(h, _)| *h == dc) {
            let r = *old;
            *old = obj;
            r
        } else {
            s.selected_fonts.push((dc, obj));
            0x3000d
        }
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetObjectW(h: u32, size: i32, out: u32) -> i32 {
    if !is_font(h) {
        return unsafe { RetroGdiObject(h, size.max(0) as u32, out) };
    }
    if out == 0 {
        return 92;
    }
    if size < 92 {
        return 0;
    }
    let font = with(|s| {
        s.fonts
            .iter()
            .find(|(id, _)| *id == h)
            .map_or_else(stock, |(_, f)| *f)
    });
    unsafe {
        (out as *mut LogFont).write_unaligned(font);
    }
    92
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn TextOutA(dc: u32, x: i32, y: i32, p: *const u8, n: i32) -> i32 {
    if n < 0 || p.is_null() && n != 0 {
        return 0;
    }
    let mut units = alloc::vec![0u16;n as usize];
    let n = unsafe { MultiByteToWideChar(0, 0, p, n, units.as_mut_ptr(), n) };
    unsafe { TextOutW(dc, x, y, units.as_ptr(), n) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetTextMetricsA(dc: u32, out: *mut u8) -> i32 {
    let mut r = Rect::default();
    if out.is_null() || unsafe { crate::RetroGdiBounds(dc, &mut r) } == 0 {
        return 0;
    }
    let metrics = [16i32, 12, 4, 0, 0, 8, 8, 400, 0, 96, 96];
    unsafe {
        core::ptr::copy_nonoverlapping(metrics.as_ptr().cast::<u8>(), out, 44);
        core::ptr::copy_nonoverlapping(
            [32u8, 255, 63, 32, 0, 0, 0, 1, 0, 0, 0, 0].as_ptr(),
            out.add(44),
            12,
        );
    }
    1
}
#[unsafe(no_mangle)]
pub extern "system" fn SetMapMode(dc: u32, mode: i32) -> i32 {
    if !(1..=8).contains(&mode) {
        return 0;
    }
    with(|s| {
        if let Some((_, old)) = s.map_modes.iter_mut().find(|(h, _)| *h == dc) {
            let r = *old;
            *old = mode;
            r
        } else {
            s.map_modes.push((dc, mode));
            1
        }
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn GetMapMode(dc: u32) -> i32 {
    with(|s| {
        s.map_modes
            .iter()
            .find(|(h, _)| *h == dc)
            .map_or(1, |(_, m)| *m)
    })
}
