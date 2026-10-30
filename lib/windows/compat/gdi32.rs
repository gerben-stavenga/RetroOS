//! Region algebra is guest-side GDI policy. The kernel consumes a rectangle list
//! only when it is selected as a drawing clip.
#![no_std]
#![allow(non_snake_case)]
#![deny(unsafe_op_in_unsafe_fn)]
extern crate alloc;
mod font;
mod palette;
#[allow(dead_code)]
#[path = "../user32/runtime.rs"]
mod runtime;
use alloc::{vec, vec::Vec};
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Rect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}
impl Rect {
    fn empty(self) -> bool {
        self.left >= self.right || self.top >= self.bottom
    }
    fn contains(self, x: i32, y: i32) -> bool {
        self.left <= x && x < self.right && self.top <= y && y < self.bottom
    }
}
struct State {
    palettes: Vec<(u32, Vec<u32>)>,
    primary_palette: u32,
    device_palette: palette::Device,
    selected_palettes: Vec<(u32, u32)>,
    bitmap_sizes: Vec<(u32, [i32; 2])>,
    patterns: Vec<(u32, usize, usize, u32, Vec<u8>)>,
    bitmap_formats: Vec<(u32, usize, usize, u32, Vec<u8>)>,
    bitmap_drawn: Vec<u32>,
    poly_modes: Vec<(u32, i32)>,
    bk_modes: Vec<(u32, i32)>,
    fonts: Vec<(u32, font::LogFont)>,
    selected_fonts: Vec<(u32, u32)>,
    map_modes: Vec<(u32, i32)>,
    brush_origins: Vec<(u32, [i32; 2])>,
    text_align: Vec<(u32,u32)>,
    next: u32,
    regions: Vec<(u32, Vec<Rect>)>,
    clips: Vec<(u32, Vec<Rect>)>,
}
struct Global {
    lock: AtomicBool,
    state: UnsafeCell<State>,
}
unsafe impl Sync for Global {}
static GLOBAL: Global = Global {
    lock: AtomicBool::new(false),
    state: UnsafeCell::new(State {
        primary_palette: 0x3000f,
        device_palette: palette::Device::new(),
        palettes: Vec::new(), selected_palettes: Vec::new(),
        bitmap_drawn: Vec::new(),
        patterns: Vec::new(),
        bitmap_formats: Vec::new(), bitmap_sizes: Vec::new(), poly_modes: Vec::new(), bk_modes: Vec::new(),
        fonts: Vec::new(),
        selected_fonts: Vec::new(),
        map_modes: Vec::new(),
        brush_origins: Vec::new(),
        text_align: Vec::new(),
        next: 0x5000_0000,
        regions: Vec::new(),
        clips: Vec::new(),
    }),
};
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        GLOBAL.lock.store(false, Ordering::Release);
    }
}
fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    while GLOBAL
        .lock
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        unsafe {
            runtime::Sleep(0);
        }
    }
    let _guard = Guard;
    f(unsafe { &mut *GLOBAL.state.get() })
}
unsafe extern "system" {
    fn RetroGdiDeleteDC(dc: u32) -> i32;
    fn RetroGdiDeleteObject(object: u32) -> i32;
    fn RetroGdiClip(dc: u32, rects: *const Rect, count: i32) -> i32;
    fn RetroGdiRop(dc: u32, value: i32) -> i32;
    fn RetroGdiBounds(dc: u32, rect: *mut Rect) -> i32;
}
fn kind(rects: &[Rect]) -> i32 {
    match rects.len() {
        0 => 1,
        1 => 2,
        _ => 3,
    }
}
fn bounds(rects: &[Rect]) -> Rect {
    let Some(mut b) = rects.first().copied() else {
        return Rect::default();
    };
    for r in rects {
        b.left = b.left.min(r.left);
        b.top = b.top.min(r.top);
        b.right = b.right.max(r.right);
        b.bottom = b.bottom.max(r.bottom);
    }
    b
}
fn region(s: &State, h: u32) -> Option<&[Rect]> {
    s.regions
        .iter()
        .find(|(id, _)| *id == h)
        .map(|(_, r)| r.as_slice())
}
fn store(s: &mut State, h: u32, r: Vec<Rect>) -> i32 {
    let Some((_, target)) = s.regions.iter_mut().find(|(id, _)| *id == h) else {
        return 0;
    };
    let result = kind(&r);
    *target = r;
    result
}
fn combine(a: &[Rect], b: &[Rect], mode: u32) -> Vec<Rect> {
    let mut ys: Vec<i32> = a.iter().chain(b).flat_map(|r| [r.top, r.bottom]).collect();
    ys.sort_unstable();
    ys.dedup();
    let mut result: Vec<Rect> = Vec::new();
    let mut previous: Vec<(i32, i32, usize)> = Vec::new();
    for band in ys.windows(2) {
        let (top, bottom) = (band[0], band[1]);
        let mut xs: Vec<i32> = a
            .iter()
            .chain(b)
            .filter(|r| r.top <= top && r.bottom >= bottom)
            .flat_map(|r| [r.left, r.right])
            .collect();
        xs.sort_unstable();
        xs.dedup();
        let mut spans: Vec<(i32, i32)> = Vec::new();
        for cell in xs.windows(2) {
            let (x, right) = (cell[0], cell[1]);
            let aa = a.iter().any(|r| r.contains(x, top));
            let bb = b.iter().any(|r| r.contains(x, top));
            if match mode {
                1 => aa && bb,
                2 => aa || bb,
                3 => aa != bb,
                4 => aa && !bb,
                5 => aa,
                _ => false,
            } {
                if let Some(last) = spans.last_mut().filter(|p| p.1 == x) {
                    last.1 = right;
                } else {
                    spans.push((x, right));
                }
            }
        }
        // Coalesce complete equal bands, preserving the RGNDATA band ordering.
        if previous.len() == spans.len()
            && previous
                .iter()
                .zip(&spans)
                .all(|(&(l, r, i), &(nl, nr))| l == nl && r == nr && result[i].bottom == top)
        {
            for &(_, _, i) in &previous {
                result[i].bottom = bottom;
            }
        } else {
            previous.clear();
            for (left, right) in spans {
                previous.push((left, right, result.len()));
                result.push(Rect {
                    left,
                    top,
                    right,
                    bottom,
                });
            }
        }
    }
    result
}
#[unsafe(no_mangle)]
pub extern "system" fn CreateRectRgn(left: i32, top: i32, right: i32, bottom: i32) -> u32 {
    let rect = Rect {
        left: left.min(right),
        top: top.min(bottom),
        right: left.max(right),
        bottom: top.max(bottom),
    };
    with(|s| {
        let h = s.next;
        s.next += 1;
        s.regions
            .push((h, if rect.empty() { Vec::new() } else { vec![rect] }));
        h
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn CreateRectRgnIndirect(r: *const Rect) -> u32 {
    if r.is_null() {
        return 0;
    }
    let r = unsafe { r.read_unaligned() };
    CreateRectRgn(r.left, r.top, r.right, r.bottom)
}
#[unsafe(no_mangle)]
pub extern "system" fn SetRectRgn(h: u32, left: i32, top: i32, right: i32, bottom: i32) -> i32 {
    let r = Rect {
        left: left.min(right),
        top: top.min(bottom),
        right: left.max(right),
        bottom: top.max(bottom),
    };
    with(|s| i32::from(store(s, h, if r.empty() { Vec::new() } else { vec![r] }) != 0))
}
#[unsafe(no_mangle)]
pub extern "system" fn CombineRgn(dst: u32, a: u32, b: u32, mode: u32) -> i32 {
    if !(1..=5).contains(&mode) {
        return 0;
    }
    with(|s| {
        let Some(aa) = region(s, a) else {
            return 0;
        };
        let bb = if mode == 5 {
            &[][..]
        } else {
            let Some(r) = region(s, b) else {
                return 0;
            };
            r
        };
        let result = combine(aa, bb, mode);
        store(s, dst, result)
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn EqualRgn(a: u32, b: u32) -> i32 {
    with(|s| match (region(s, a), region(s, b)) {
        (Some(a), Some(b)) => i32::from(a == b),
        _ => 0,
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetRgnBox(h: u32, out: *mut Rect) -> i32 {
    if out.is_null() {
        return 0;
    }
    with(|s| {
        let Some(r) = region(s, h) else {
            return 0;
        };
        unsafe {
            out.write_unaligned(bounds(r));
        }
        kind(r)
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn OffsetRgn(h: u32, x: i32, y: i32) -> i32 {
    with(|s| {
        let Some(r) = region(s, h) else {
            return 0;
        };
        let r = r
            .iter()
            .map(|r| Rect {
                left: r.left.wrapping_add(x),
                right: r.right.wrapping_add(x),
                top: r.top.wrapping_add(y),
                bottom: r.bottom.wrapping_add(y),
            })
            .collect();
        store(s, h, r)
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn PtInRegion(h: u32, x: i32, y: i32) -> i32 {
    with(|s| i32::from(region(s, h).is_some_and(|r| r.iter().any(|r| r.contains(x, y)))))
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RectInRegion(h: u32, rect: *const Rect) -> i32 {
    if rect.is_null() {
        return 0;
    }
    let b = unsafe { rect.read_unaligned() };
    with(|s| i32::from(region(s, h).is_some_and(|a| !combine(a, &[b], 1).is_empty())))
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetRegionData(h: u32, size: u32, out: *mut u8) -> u32 {
    with(|s| {
        let Some(r) = region(s, h) else {
            return 0;
        };
        let need = 32 + r.len() as u32 * 16;
        if out.is_null() {
            return need;
        }
        if size < need {
            return 0;
        }
        let values = [32u32, 1, r.len() as u32, r.len() as u32 * 16];
        unsafe {
            for (i, v) in values.iter().enumerate() {
                out.add(i * 4).cast::<u32>().write_unaligned(*v);
            }
            out.add(16).cast::<Rect>().write_unaligned(bounds(r));
            for (i, v) in r.iter().enumerate() {
                out.add(32 + i * 16).cast::<Rect>().write_unaligned(*v);
            }
        }
        need
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn DeleteObject(h: u32) -> i32 {
    let found = with(|s| {
        if let Some(i) = s.palettes.iter().position(|(id,_)| *id == h) {
            if s.selected_palettes.iter().any(|(_,p)| *p == h) {return false;}
            s.palettes.remove(i); s.device_palette.remove(h); true
        } else if let Some(i) = s.regions.iter().position(|(id, _)| *id == h) {
            s.regions.remove(i);
            true
        } else if let Some(i) = s.fonts.iter().position(|(id, _)| *id == h) {
            if s.selected_fonts.iter().any(|(_, font)| *font == h) {
                return false;
            }
            s.fonts.remove(i);
            true
        } else {
            false
        }
    });
    if found {
        1
    } else if (0x5000_0000..0x6000_0000).contains(&h) {
        0
    } else {
        let result=unsafe { RetroGdiDeleteObject(h) };
        if result!=0 {with(|s| {s.patterns.retain(|(id,_,_,_,_)|*id!=h);s.bitmap_formats.retain(|(id,_,_,_,_)|*id!=h);s.bitmap_drawn.retain(|id|*id!=h);s.bitmap_sizes.retain(|(id,_)|*id!=h);});}
        result
    }
}
#[unsafe(no_mangle)]
pub extern "system" fn SelectClipRgn(dc: u32, h: u32) -> i32 {
    with(|s| {
        let r = if h == 0 {
            None
        } else {
            let Some(r) = region(s, h) else {
                return 0;
            };
            Some(r.to_vec())
        };
        let result = unsafe {
            RetroGdiClip(
                dc,
                r.as_ref().map_or(core::ptr::null(), |r| r.as_ptr()),
                r.as_ref().map_or(-1, |r| r.len() as i32),
            )
        };
        if result == 0 {
            return 0;
        }
        s.clips.retain(|(id, _)| *id != dc);
        if let Some(r) = r {
            let result = kind(&r);
            s.clips.push((dc, r));
            result
        } else {
            2
        }
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn GetClipRgn(dc: u32, h: u32) -> i32 {
    with(|s| {
        if region(s, h).is_none() {
            return -1;
        }
        let Some((_, r)) = s.clips.iter().find(|(id, _)| *id == dc) else {
            return 0;
        };
        let r = r.clone();
        store(s, h, r);
        1
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetClipBox(dc: u32, out: *mut Rect) -> i32 {
    if out.is_null() {
        return 0;
    }
    let mut b = Rect::default();
    if unsafe { RetroGdiBounds(dc, &raw mut b) } == 0 {
        return 0;
    }
    with(|s| {
        let r = s
            .clips
            .iter()
            .find(|(id, _)| *id == dc)
            .map_or_else(|| vec![b], |(_, r)| combine(r, &[b], 1));
        unsafe {
            out.write_unaligned(bounds(&r));
        }
        kind(&r)
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn GetRandomRgn(dc: u32, h: u32, which: u32) -> i32 {
    if which == 1 {
        return GetClipRgn(dc, h);
    }
    if which == 2 {
        return 0;
    }
    if !matches!(which, 3 | 4) {
        return -1;
    }
    let mut b = Rect::default();
    if unsafe { GetClipBox(dc, &raw mut b) } == 0 {
        return -1;
    }
    with(|s| i32::from(store(s, h, if b.empty() { Vec::new() } else { vec![b] }) != 0))
}
#[unsafe(no_mangle)]
pub extern "system" fn GetROP2(dc: u32) -> i32 {
    unsafe { RetroGdiRop(dc, 0) }
}
#[unsafe(no_mangle)]
pub extern "system" fn SetROP2(dc: u32, value: i32) -> i32 {
    if !(1..=16).contains(&value) {
        return 0;
    }
    unsafe { RetroGdiRop(dc, value) }
}

#[unsafe(no_mangle)]
pub extern "system" fn DeleteDC(dc: u32) -> i32 {
    let result = unsafe { RetroGdiDeleteDC(dc) };
    if result != 0 {
        with(|s| {
            s.clips.retain(|(h, _)| *h != dc);
            s.selected_fonts.retain(|(h, _)| *h != dc);
            s.map_modes.retain(|(h, _)| *h != dc);
            s.brush_origins.retain(|(h, _)| *h != dc);
            s.text_align.retain(|(h, _)| *h != dc);
            s.selected_palettes.retain(|(h,_)| *h != dc);
            s.bk_modes.retain(|(h,_)| *h != dc);
            s.poly_modes.retain(|(h,_)| *h != dc);
        });
    }
    result
}

unsafe extern "system" {
    fn RetroGdiBitmap(width: u32, height: u32, pixels: *const u32) -> u32;
}
#[unsafe(no_mangle)]
pub extern "system" fn GetDeviceCaps(_dc: u32, index: i32) -> i32 {
    match index {
        0 => 0x300,
        2 => 1,
        8 => 1024,
        10 => 768,
        12 => 8,
        14 => 1,
        24 | 104 => 256,
        38 => 0x100 | 1 | 0x80 | 0x200 | 0x800,
        88 | 90 => 96,
        106 => 20,
        _ => 0,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn CreateCompatibleBitmap(dc: u32, width: i32, height: i32) -> u32 {
    let selected = unsafe { RetroGdiCurrentObject(dc, 7) };
    // A fresh memory DC contains the stock monochrome bitmap. A window DC
    // uses the virtual display's depth; selecting a bitmap overrides it.
    let depth = if dc == 0 || selected == 1 { 1 } else {
        with(|s| s.bitmap_formats.iter().find(|(h, _, _, _, _)| *h == selected)
            .map_or(8, |(_, _, _, depth, _)| *depth))
    };
    let bitmap = unsafe { CreateBitmap(width, height, 1, depth, core::ptr::null()) };
    if bitmap != 0 {
        // There is no uploaded image to replay: later GDI drawing owns these
        // pixels. SetBitmapBits explicitly supplies a new upload when used.
        with(|s| s.bitmap_drawn.push(bitmap));
    }
    bitmap
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn CreateBitmap(
    width: i32,
    height: i32,
    planes: u32,
    depth: u32,
    source: *const u8,
) -> u32 {
    if !(0..=2048).contains(&width)
        || !(0..=2048).contains(&height)
        || planes != 1
        || !matches!(depth, 1 | 4 | 8 | 24 | 32)
    {
        return 0;
    }
    let (width, height) = (width.max(1) as usize, height.max(1) as usize);
    let mut pixels = vec![0u32; width * height];
    let stride = (width * depth as usize).div_ceil(16) * 2;
    let mut bytes = vec![0; stride * height];
    if !source.is_null() {
        unsafe { core::ptr::copy_nonoverlapping(source, bytes.as_mut_ptr(), bytes.len()); }
        let colors = with(|s| s.device_palette.colors);
        decode_bitmap(&bytes, width, height, depth, &colors, &mut pixels);
    }
    let handle = unsafe { RetroGdiBitmap(width as u32, height as u32, pixels.as_ptr()) };
    if handle != 0 {
        with(|s| s.bitmap_formats.push((handle, width, height, depth, bytes)));
    }
    handle

}

unsafe extern "system" {
    fn CreateCompatibleDC(dc: u32) -> u32;
    fn RetroGdiBitBlt(
        dst: u32,
        x: i32,
        y: i32,
        w: i32,
        h: i32,
        src: u32,
        sx: i32,
        sy: i32,
        rop: u32,
    ) -> i32;
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SetDIBitsToDevice(
    dc: u32,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    sx: i32,
    sy: i32,
    start: u32,
    lines: u32,
    bits: *const u8,
    info: *const u8,
    usage: u32,
) -> i32 {
    if bits.is_null() || info.is_null() || usage != 0 {
        return 0;
    }
    let word = |offset| unsafe { info.add(offset).cast::<u16>().read_unaligned() };
    let dword = |offset| unsafe { info.add(offset).cast::<u32>().read_unaligned() };
    let header = dword(0);
    if header < 40 {
        return 0;
    }
    let w = dword(4) as i32;
    let h = dword(8) as i32;
    let depth = word(14);
    if w <= 0
        || w > 2048
        || h == 0
        || h.unsigned_abs() > 2048
        || word(12) != 1
        || dword(16) != 0
        || !matches!(depth, 1 | 4 | 8 | 24 | 32)
    {
        return 0;
    }
    let h_abs = h.unsigned_abs();
    if start >= h_abs {
        return 0;
    }
    let lines = lines.min(h_abs - start);
    let stride = (w as usize * depth as usize).div_ceil(32) * 4;
    let colors = if depth <= 8 {
        if dword(32) == 0 {
            1u32 << depth
        } else {
            dword(32).min(1 << depth)
        }
    } else {
        0
    };
    let mut pixels = vec![0u32; w as usize * lines as usize];
    for row in 0..lines as usize {
        for column in 0..w as usize {
            let src = unsafe { bits.add(row * stride) };
            let color = if depth <= 8 {
                let index = match depth {
                    1 => (unsafe { src.add(column / 8).read() } >> (7 - column % 8)) & 1,
                    4 => {
                        (unsafe { src.add(column / 2).read() }
                            >> if column % 2 == 0 { 4 } else { 0 })
                            & 15
                    }
                    _ => unsafe { src.add(column).read() },
                } as u32;
                if index >= colors {
                    0
                } else {
                    let c = dword(header as usize + index as usize * 4);
                    ((c >> 16) & 255) | (c & 0xff00) | ((c & 255) << 16)
                }
            } else {
                let p = unsafe { src.add(column * (depth as usize / 8)) };
                unsafe {
                    u32::from(p.add(2).read())
                        | (u32::from(p.add(1).read()) << 8)
                        | (u32::from(p.read()) << 16)
                }
            };
            let destination = if h > 0 { lines as usize - 1 - row } else { row };
            pixels[destination * w as usize + column] = color;
        }
    }
    let bitmap = unsafe { RetroGdiBitmap(w as u32, lines, pixels.as_ptr()) };
    if bitmap == 0 {
        return 0;
    }
    let source = unsafe { CreateCompatibleDC(dc) };
    if source == 0 {
        DeleteObject(bitmap);
        return 0;
    }
    let old = unsafe { font::SelectObject(source, bitmap) };
    // Source coordinates are DIB coordinates, measured from its lower edge for
    // bottom-up DIBs; the temporary bitmap is normalized to top-down scanlines.
    let source_y = if h > 0 {
        h_abs as i32 - sy - height as i32 - (h_abs - start - lines) as i32
    } else {
        sy - start as i32
    };
    let result = unsafe {
        BitBlt(
            dc,
            x,
            y,
            width.min(2048) as i32,
            height.min(lines) as i32,
            source,
            sx,
            source_y,
            0x00cc0020,
        )
    };
    unsafe {
        font::SelectObject(source, old);
    }
    DeleteDC(source);
    DeleteObject(bitmap);
    if result != 0 { lines as i32 } else { 0 }
}

unsafe extern "system" {
    fn RetroGdiCurrentObject(dc: u32, kind: u32) -> u32;
    fn RetroGdiSolidFillRect(dc: u32, rect: *const [i32; 4], brush: u32) -> i32;
    fn Polygon(dc: u32, points: *const [i32; 2], count: i32) -> i32;
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn CreatePatternBrush(bitmap: u32) -> u32 {
    unsafe extern "system" { fn CreateSolidBrush(color: u32) -> u32; }
    let mut object = [0u32; 6];
    if unsafe { font::GetObjectW(bitmap, 24, object.as_mut_ptr() as u32) } != 24 {
        return 0;
    }
    let (width, height, depth) = (object[1] as usize, object[2] as usize, object[4] >> 16);
    if width == 0 || height == 0 || width > 2048 || height > 2048
        || !matches!(depth, 1 | 4 | 8 | 24 | 32) { return 0; }
    let size = (width * depth as usize).div_ceil(16) * 2 * height;
    // An uploaded indexed bitmap already has exact palette indices. Preserve
    // them even when the currently realized palette has duplicate colours.
    let uploaded = with(|s| {
        if s.bitmap_drawn.contains(&bitmap) || !matches!(depth, 4 | 8) { return None; }
        s.bitmap_formats.iter().find(|(h, _, _, _, _)| *h == bitmap)
            .map(|(_, _, _, _, bytes)| bytes.clone())
    });
    let bytes = if let Some(bytes) = uploaded { bytes } else {
        let mut bytes = vec![0; size];
        if unsafe { GetBitmapBits(bitmap, size as i32, bytes.as_mut_ptr()) } != size as i32 {
            return 0;
        }
        bytes
    };
    // The native handle supplies ordinary selection/lifetime behavior. The
    // immutable pattern snapshot and its interpretation belong to guest GDI.
    let brush = unsafe { CreateSolidBrush(0) };
    if brush != 0 { with(|s| s.patterns.push((brush, width, height, depth, bytes))); }
    brush
}

unsafe fn pattern_fill(dc: u32, rect: [i32; 4], brush: u32, rop: u32) -> Option<i32> {
    let (width, height, depth, bytes, palette, origin) = with(|s| {
        let (_, w, h, depth, bytes) = s.patterns.iter().find(|(id, _, _, _, _)| *id == brush)?;
        let colors = s.device_palette.colors.to_vec();
        let origin = s.brush_origins.iter().find(|(h, _)| *h == dc).map_or([0; 2], |(_, p)| *p);
        Some((*w, *h, *depth, bytes.clone(), colors, origin))
    })?;
    let mut bounds = Rect::default();
    if unsafe { RetroGdiBounds(dc, &mut bounds) } == 0 { return Some(0); }
    let [left, top, right, bottom] = rect;
    let (left, top) = (left.max(bounds.left), top.max(bounds.top));
    let (right, bottom) = (right.min(bounds.right), bottom.min(bounds.bottom));
    if right <= left || bottom <= top { return Some(1); }
    let mut pattern = vec![0; width * height];
    decode_bitmap(&bytes, width, height, depth, &palette, &mut pattern);
    if depth == 1 {
        unsafe extern "system" { fn GetTextColor(dc: u32) -> u32; fn GetBkColor(dc: u32) -> u32; }
        let text = unsafe { GetTextColor(dc) };
        let background = unsafe { GetBkColor(dc) };
        for pixel in &mut pattern { *pixel = if *pixel == 0 { text } else { background }; }
    }
    let (w, h) = ((right - left) as usize, (bottom - top) as usize);
    let mut pixels = vec![0; w * h];
    for y in 0..h {
        let py = (i64::from(top) + y as i64 - i64::from(origin[1])).rem_euclid(height as i64) as usize;
        for x in 0..w {
            let px = (i64::from(left) + x as i64 - i64::from(origin[0])).rem_euclid(width as i64) as usize;
            pixels[y * w + x] = pattern[py * width + px];
        }
    }
    // Expand once in guest memory and submit one blit, including the native
    // destination clip and ROP. No syscall per pattern tile or pixel.
    let bitmap = unsafe { RetroGdiBitmap(w as u32, h as u32, pixels.as_ptr()) };
    if bitmap == 0 { return Some(0); }
    let source = unsafe { CreateCompatibleDC(dc) };
    if source == 0 { DeleteObject(bitmap); return Some(0); }
    let old = unsafe { font::SelectObject(source, bitmap) };
    // The requested operation uses P and D; the temporary bitmap supplies P
    // through S. Replicate the resulting S,D truth table for both P values.
    let truth = (rop >> 16) as u8;
    let sd = (truth & 3) | ((truth >> 2) & 12);
    let mapped = u32::from(sd | (sd << 4)) << 16;
    let result = unsafe { RetroGdiBitBlt(dc, left, top, w as i32, h as i32, source, 0, 0, mapped) };
    unsafe { font::SelectObject(source, old); }
    DeleteDC(source);
    DeleteObject(bitmap);
    if result != 0 { mark_bitmap_drawn(dc); }
    Some(result)
}

fn mark_bitmap_drawn(dc: u32) {
    let bitmap = unsafe { RetroGdiCurrentObject(dc, 7) };
    with(|s| {
        if s.bitmap_formats.iter().any(|(h, _, _, _, _)| *h == bitmap)
            && !s.bitmap_drawn.contains(&bitmap) { s.bitmap_drawn.push(bitmap); }
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroGdiFillRect(dc: u32, rect: *const [i32; 4], brush: u32) -> i32 {
    if rect.is_null() { return 0; }
    if let Some(result) = unsafe { pattern_fill(dc, rect.read_unaligned(), brush, 0x00f00021) } {
        return result;
    }
    let result = unsafe { RetroGdiSolidFillRect(dc, rect, brush) };
    if result != 0 { mark_bitmap_drawn(dc); }
    result
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Rectangle(
    dc: u32,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
) -> i32 {
    let (l, r) = (left.min(right), left.max(right));
    let (t, b) = (top.min(bottom), top.max(bottom));
    let brush = unsafe { RetroGdiCurrentObject(dc, 2) };
    if brush == 0 {
        return 0;
    }
    if l == r || t == b {
        return 1;
    }
    unsafe {
        RetroGdiFillRect(dc, &[l, t, r, b], brush);
        Polygon(
            dc,
            [[l, t], [r - 1, t], [r - 1, b - 1], [l, b - 1]].as_ptr(),
            4,
        )
    }
}

unsafe extern "system" {
    fn GetObjectType(object: u32) -> u32;
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SetBrushOrgEx(dc: u32, x: i32, y: i32, old: *mut [i32; 2]) -> i32 {
    let mut bounds = Rect::default();
    if unsafe { RetroGdiBounds(dc, &mut bounds) } == 0 {
        return 0;
    }
    with(|s| {
        let prev = s
            .brush_origins
            .iter()
            .find(|(h, _)| *h == dc)
            .map_or([0; 2], |(_, p)| *p);
        if !old.is_null() {
            unsafe {
                old.write_unaligned(prev);
            }
        }
        if let Some((_, p)) = s.brush_origins.iter_mut().find(|(h, _)| *h == dc) {
            *p = [x, y];
        } else {
            s.brush_origins.push((dc, [x, y]));
        }
    });
    1
}
#[unsafe(no_mangle)]
pub extern "system" fn UnrealizeObject(object: u32) -> i32 {
    // Solid brushes are used directly; there is no device realization to drop.
    i32::from(unsafe { GetObjectType(object) } == 2)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn SetTextAlign(dc: u32, align: u32) -> u32 {
    let mut bounds=Rect::default();
    if unsafe { RetroGdiBounds(dc,&mut bounds) }==0 || align & !0x11f != 0 { return u32::MAX; }
    with(|s| {
        if let Some((_,old))=s.text_align.iter_mut().find(|(h,_)|*h==dc) {
            let previous=*old;*old=align;previous
        } else {s.text_align.push((dc,align));0}
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn GetTextAlign(dc: u32) -> u32 {
    with(|s|s.text_align.iter().find(|(h,_)|*h==dc).map_or(0,|(_,a)|*a))
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn ExtFloodFill(dc: u32, x: i32, y: i32, color: u32, kind: u32) -> i32 {
    unsafe extern "system" {fn GetPixel(dc:u32,x:i32,y:i32)->u32;}
    let mut bounds=Rect::default();
    if kind>1 || unsafe {RetroGdiBounds(dc,&mut bounds)}==0 || !bounds.contains(x,y) {return 0;}
    let brush=unsafe {RetroGdiCurrentObject(dc,2)};
    if brush==0 {return 0;}
    let clips=with(|s|s.clips.iter().find(|(h,_)|*h==dc).map(|(_,r)|r.clone()));
    let allowed=|x,y|bounds.contains(x,y) && clips.as_ref().is_none_or(|r|r.iter().any(|r|r.contains(x,y)));
    let matches=|pixel| pixel!=u32::MAX && if kind==1 {pixel==color} else {pixel!=color};
    if !allowed(x,y) || !matches(unsafe {GetPixel(dc,x,y)}) {return 0;}
    let width=(bounds.right-bounds.left) as usize;
    let height=(bounds.bottom-bounds.top) as usize;
    let mut visited=vec![false;width*height];
    let mut pending=vec![(x,y)];
    visited[(y-bounds.top) as usize*width+(x-bounds.left) as usize]=true;
    while let Some((x,y))=pending.pop() {
        if !matches(unsafe {GetPixel(dc,x,y)}) {continue;}
        unsafe {RetroGdiFillRect(dc,&[x,y,x+1,y+1],brush);}
        for (nx,ny) in [(x-1,y),(x+1,y),(x,y-1),(x,y+1)] {
            if allowed(nx,ny) {
                let at=(ny-bounds.top) as usize*width+(nx-bounds.left) as usize;
                if !visited[at] {visited[at]=true;pending.push((nx,ny));}
            }
        }
    }
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn PatBlt(dc:u32,x:i32,y:i32,width:i32,height:i32,rop:u32)->i32 {
    let truth=(rop>>16) as u8;
    // A pattern operation cannot depend on the source operand. Reuse the
    // shared raster operation and clipping with an identical source view.
    if ((truth >> 2) ^ truth) & 0x33 != 0 {return 0;}
    let brush = unsafe { RetroGdiCurrentObject(dc, 2) };
    if let Some(result) = unsafe { pattern_fill(dc,
        [x, y, x.saturating_add(width), y.saturating_add(height)], brush, rop) } {
        return result;
    }
    unsafe {BitBlt(dc,x,y,width,height,dc,x,y,rop)}
}

#[unsafe(no_mangle)]
pub extern "system" fn GetBkMode(dc: u32) -> i32 {
    with(|s| s.bk_modes.iter().find(|(h,_)| *h == dc).map_or(2, |(_,m)| *m))
}
fn mode(modes: &mut Vec<(u32,i32)>, dc: u32, value: i32, default: i32) -> i32 {
    if let Some((_, m)) = modes.iter_mut().find(|(h,_)| *h == dc) {
        core::mem::replace(m,value)
    } else { modes.push((dc,value)); default }
}
#[unsafe(no_mangle)]
pub extern "system" fn SetBkMode(dc: u32, value: i32) -> i32 {
    if !(1..=2).contains(&value) { return 0; }
    with(|s| mode(&mut s.bk_modes,dc,value,2))
}
#[unsafe(no_mangle)]
pub extern "system" fn SetPolyFillMode(dc: u32, value: i32) -> i32 {
    if !(1..=2).contains(&value) { return 0; }
    with(|s| mode(&mut s.poly_modes,dc,value,1))
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetBitmapDimensionEx(bitmap:u32, out:*mut [i32;2])->i32 {
    if out.is_null() { return 0; }
    let size=with(|s|s.bitmap_sizes.iter().find(|(h,_)|*h==bitmap).map_or([0,0],|(_,v)|*v));
    unsafe {out.write_unaligned(size);} 1
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SetBitmapDimensionEx(bitmap:u32,x:i32,y:i32,out:*mut [i32;2])->i32 {
    unsafe { if !out.is_null() {GetBitmapDimensionEx(bitmap,out);} }
    with(|s|if let Some((_,v))=s.bitmap_sizes.iter_mut().find(|(h,_)|*h==bitmap){*v=[x,y]}else{s.bitmap_sizes.push((bitmap,[x,y]))});1
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn CreatePalette(p:*const u8)->u32 {
    if p.is_null() {return 0;}
    let version=unsafe{p.cast::<u16>().read_unaligned()};
    let n=unsafe{p.add(2).cast::<u16>().read_unaligned()} as usize;
    if version!=0x300 || n==0 || n>256 {return 0;}
    let entries=(0..n).map(|i|unsafe{p.add(4+i*4).cast::<u32>().read_unaligned()}).collect();
    with(|s|{let h=s.next;s.next+=1;s.palettes.push((h,entries));h})
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetPaletteEntries(handle:u32,start:u32,count:u32,out:*mut u32)->u32 {
    with(|s| {
        let entries=if handle==0x3000f {&palette::STATIC[..]}
            else if let Some((_,v))=s.palettes.iter().find(|(h,_)|*h==handle) {&v[..]}
            else {return 0;};
        if out.is_null() {return entries.len() as u32;}
        let Some(entries)=entries.get(start as usize..) else {return 0;};
        let count=(count as usize).min(entries.len());
        for (i,&entry) in entries[..count].iter().enumerate() {unsafe {out.add(i).write_unaligned(entry);}}
        count as u32
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SetPaletteEntries(palette:u32,start:u32,n:u32,p:*const u32)->u32 {
    if p.is_null(){return 0;}
    with(|s|{let Some((_,v))=s.palettes.iter_mut().find(|(h,_)|*h==palette) else{return 0;};
        let start=start as usize;if start>=v.len(){return 0;}
        let n=(n as usize).min(v.len()-start);
        for i in 0..n {v[start+i]=unsafe{p.add(i).read_unaligned()};}n as u32})
}
/// Return a logical entry index, independent of the realized device slots.
#[unsafe(no_mangle)]
pub extern "system" fn GetNearestPaletteIndex(handle:u32,color:u32)->u32 {
    with(|s| {
        let entries = if handle == 0x3000f { &palette::STATIC[..] }
            else if let Some((_, entries)) = s.palettes.iter().find(|(h,_)|*h==handle) { &entries[..] }
            else { return u32::MAX; };
        entries.iter().enumerate().min_by_key(|(_, entry)| {
            [0,8,16].iter().map(|shift| {
                let delta=((color>>shift)&255) as i32 - ((**entry>>shift)&255) as i32;
                delta*delta
            }).sum::<i32>()
        }).map_or(u32::MAX,|(i,_)| i as u32)
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn SelectPalette(dc:u32,palette:u32,background:u32)->u32 {
    with(|s|{if palette != 0x3000f && !s.palettes.iter().any(|(h,_)|*h==palette){return 0;}
        if background == 0 { s.primary_palette = palette; }
        if let Some((_,p))=s.selected_palettes.iter_mut().find(|(h,_)|*h==dc){core::mem::replace(p,palette)}
        else{s.selected_palettes.push((dc,palette));0x3000f}})
}
#[unsafe(no_mangle)]
pub extern "system" fn RealizePalette(dc:u32)->u32 {
    with(|s| {
        let id = s.selected_palettes.iter().find(|(h,_)|*h==dc).map_or(0x3000f,|(_,p)|*p);
        let Some((_, entries)) = s.palettes.iter().find(|(h,_)|*h==id) else { return 0; };
        s.device_palette.realize(id, entries, id == s.primary_palette)
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn AnimatePalette(palette:u32,start:u32,n:u32,p:*const u32)->i32 {
    if p.is_null() || n > 256 { return 0; }
    let entries: Vec<u32> = (0..n as usize).map(|i| unsafe {p.add(i).read_unaligned()}).collect();
    with(|s| {
        let Some((_, logical)) = s.palettes.iter_mut().find(|(h,_)|*h==palette) else {return 0;};
        s.device_palette.animate(palette, logical, start as usize, &entries);
        1
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetSystemPaletteEntries(_dc:u32,start:u32,n:u32,p:*mut u32)->u32 {
    if p.is_null(){return 256;}
    let count=n.min(256u32.saturating_sub(start));
    let colors = with(|s| s.device_palette.colors);
    for i in 0..count {let index=start+i;
        let c=colors[index as usize];
        unsafe{p.add(i as usize).write_unaligned(c);}}
    count
}

unsafe extern "system" {fn RetroGdiBitmapWrite(bitmap:u32,pixels:*const u32,count:u32)->i32;}
unsafe extern "system" {
    fn RetroGdiBitmapRead(bitmap: u32, pixels: *mut u32, count: u32) -> i32;
}

unsafe fn bitmap_object(bitmap: u32, size: i32, out: u32) -> Option<i32> {
    let format = with(|s| s.bitmap_formats.iter().find(|(h, _, _, _, _)| *h == bitmap)
        .map(|(_, w, h, depth, _)| (*w, *h, *depth)))?;
    if out == 0 { return Some(24); }
    if size < 24 { return Some(0); }
    let (width, height, depth) = format;
    let object = [0, width as u32, height as u32,
        ((width * depth as usize).div_ceil(16) * 2) as u32, 1 | (depth << 16), 0];
    unsafe { core::ptr::copy_nonoverlapping(object.as_ptr().cast::<u8>(), out as *mut u8, 24); }
    Some(24)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetBitmapBits(bitmap: u32, count: i32, out: *mut u8) -> i32 {
    let format = with(|s| s.bitmap_formats.iter()
        .find(|(h, _, _, _, _)| *h == bitmap).cloned());
    let (width, height, depth, original) = if let Some((_, w, h, d, bytes)) = format {
        (w, h, d, bytes)
    } else {
        // Bitmaps made by the native surface primitive are true colour.
        let mut object = [0u32; 6];
        if unsafe { font::GetObjectW(bitmap, 24, object.as_mut_ptr() as u32) } != 24 {
            return 0;
        }
        (object[1] as usize, object[2] as usize, 32, Vec::new())
    };
    let stride = (width * depth as usize).div_ceil(16) * 2;
    let total = stride * height;
    if out.is_null() { return total as i32; }
    if count <= 0 { return 0; }
    let rows = (count as usize / stride).min(height);
    if rows == 0 { return 0; }
    let mut pixels = vec![0; width * height];
    if unsafe { RetroGdiBitmapRead(bitmap, pixels.as_mut_ptr(), pixels.len() as u32) } == 0 {
        return 0;
    }
    let palette = with(|s| s.device_palette.colors);
    let colors: Vec<u32> = if depth <= 8 {
        (0..1u32 << depth).map(|i| {
            if depth == 1 { if i == 0 { 0 } else { 0xffffff } }
            else { bitmap_color(i as usize, depth, &palette) }
        }).collect()
    } else { Vec::new() };
    let mut bytes = vec![0u8; rows * stride];
    for y in 0..rows {
        for x in 0..width {
            let c = pixels[y * width + x] & 0xffffff;
            let row = y * stride;
            if depth <= 8 {
                let old = match depth {
                    1 => original.get(row + x / 8).map(|v| (v >> (7 - x % 8)) & 1),
                    4 => original.get(row + x / 2).map(|v| (v >> (4 * (1 - x % 2))) & 15),
                    _ => original.get(row + x).copied(),
                };
                // Preserve identical-colour palette indices when possible.
                let index = old.filter(|i| colors[*i as usize] == c).unwrap_or_else(|| {
                    colors.iter().enumerate().min_by_key(|(_, color)| {
                        [0, 8, 16].iter().map(|shift| {
                            let d = ((c >> shift) & 255) as i32 - ((*color >> shift) & 255) as i32;
                            d * d
                        }).sum::<i32>()
                    }).map_or(0, |(i, _)| i as u8)
                });
                match depth {
                    1 => bytes[row + x / 8] |= index << (7 - x % 8),
                    4 => bytes[row + x / 2] |= index << (4 * (1 - x % 2)),
                    _ => bytes[row + x] = index,
                }
            } else {
                let at = row + x * (depth as usize / 8);
                bytes[at] = (c >> 16) as u8;
                bytes[at + 1] = (c >> 8) as u8;
                bytes[at + 2] = c as u8;
            }
        }
    }
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()); }
    bytes.len() as i32
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn SetBitmapBits(bitmap:u32,count:u32,source:*const u8)->i32 {
    if source.is_null() || count==0 || count>i32::MAX as u32 {return 0;}
    let Some((width,height,depth,bytes,n))=with(|s|{
        s.bitmap_drawn.retain(|h|*h!=bitmap);
        let (_,width,height,depth,bytes)=s.bitmap_formats.iter_mut().find(|(h,_,_,_,_)|*h==bitmap)?;
        let n=(count as usize).min(bytes.len());
        unsafe{core::ptr::copy_nonoverlapping(source,bytes.as_mut_ptr(),n);}
        Some((*width,*height,*depth,bytes.clone(),n))
    }) else{return 0;};
    let mut pixels = vec![0; width * height];
    let colors = with(|s| s.device_palette.colors);
        decode_bitmap(&bytes, width, height, depth, &colors, &mut pixels);
    if unsafe{RetroGdiBitmapWrite(bitmap,pixels.as_ptr(),pixels.len() as u32)}!=0 {n as i32}else{0}
}

// Device-dependent bitmap rows are WORD aligned and stored top down.
fn decode_bitmap(bytes: &[u8], width: usize, height: usize, depth: u32, palette: &[u32], pixels: &mut [u32]) {
    let stride = (width * depth as usize).div_ceil(16) * 2;
    for y in 0..height {
        for x in 0..width {
            let row = y * stride;
            pixels[y * width + x] = match depth {
                1 => if bytes[row + x / 8] & (0x80 >> (x & 7)) != 0 { 0xffffff } else { 0 },
                4 | 8 => {
                    let index = if depth == 8 { bytes[row + x] } else {
                        let value = bytes[row + x / 2];
                        if x & 1 == 0 { value >> 4 } else { value & 15 }
                    } as usize;
                    bitmap_color(index, depth, palette)
                }
                _ => {
                    let at = row + x * (depth as usize / 8);
                    u32::from(bytes[at + 2]) | u32::from(bytes[at + 1]) << 8 | u32::from(bytes[at]) << 16
                }
            };
        }
    }
}
fn bitmap_color(index: usize, depth: u32, palette: &[u32]) -> u32 {
    // A four-bit DDB uses the standard 16-color palette. Its bright half
    // corresponds to the final eight static slots of the 256-color device.
    let slot = if depth == 4 && index >= 8 { index + 240 } else { index };
    palette.get(slot).copied().unwrap_or(0) & 0xffffff
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn BitBlt(dst: u32, x: i32, y: i32, width: i32, height: i32, src: u32, sx: i32, sy: i32, rop: u32) -> i32 {
    let bitmap = unsafe { RetroGdiCurrentObject(src, 7) };
    // Keep source indices intact: each blit resolves them using the
    // current device palette, including changes made by AnimatePalette.
    let indexed = with(|s| {
        if s.bitmap_drawn.contains(&bitmap) { return None; }
        let (_, w, h, depth, bytes) = s.bitmap_formats.iter().find(|(id, _, _, depth, _)| *id == bitmap && matches!(depth, 4 | 8))?;
        let palette = s.device_palette.colors.to_vec();
        Some((*w, *h, *depth, bytes.clone(), palette))
    });
    if let Some((w, h, depth, bytes, palette)) = &indexed {
        let mut pixels = vec![0; w * h];
        decode_bitmap(bytes, *w, *h, *depth, palette, &mut pixels);
        if unsafe { RetroGdiBitmapWrite(bitmap, pixels.as_ptr(), pixels.len() as u32) } == 0 { return 0; }
    }
    let result = unsafe { RetroGdiBitBlt(dst, x, y, width, height, src, sx, sy, rop) };
    if result != 0 && !(dst == src && x == sx && y == sy && rop == 0x00cc0020) {
        let target = unsafe { RetroGdiCurrentObject(dst, 7) };
        // A complete indexed SRCCOPY preserves indices, including entries
        // which currently have identical RGB values during a palette fade.
        // Converting this intermediate image to RGB permanently would lose
        // those identities before its next blit to the window.
        let preserved = if let Some((sw, sh, 8, bytes, _)) = &indexed {
            with(|s| {
                if rop != 0x00cc0020 || x != 0 || y != 0 || sx < 0 || sy < 0
                    || width <= 0 || height <= 0 { return false; }
                if s.clips.iter().find(|(h, _)| *h == dst).is_some_and(|(_, clips)| {
                    !clips.iter().any(|r| r.left <= 0 && r.top <= 0 && r.right >= width && r.bottom >= height)
                }) { return false; }
                let Some((_, dw, dh, 8, output)) = s.bitmap_formats.iter_mut()
                    .find(|(h, _, _, _, _)| *h == target) else { return false; };
                if (*dw, *dh) != (width as usize, height as usize)
                    || sx as usize + *dw > *sw || sy as usize + *dh > *sh { return false; }
                let source_stride = sw.div_ceil(2) * 2;
                let destination_stride = dw.div_ceil(2) * 2;
                for row in 0..*dh {
                    let from = (sy as usize + row) * source_stride + sx as usize;
                    output[row * destination_stride..row * destination_stride + *dw]
                        .copy_from_slice(&bytes[from..from + *dw]);
                }
                s.bitmap_drawn.retain(|h| *h != target);
                true
            })
        } else { false };
        if preserved { return result; }
        // The destination now contains rendered pixels. Do not overwrite a
        // composed image with the bytes originally supplied to CreateBitmap
        // when that image is subsequently used as a blit source.
        with(|s| {
            if s.bitmap_formats.iter().any(|(h, _, _, _, _)| *h == target)
                && !s.bitmap_drawn.contains(&target) { s.bitmap_drawn.push(target); }
        });
    }
    result
}
