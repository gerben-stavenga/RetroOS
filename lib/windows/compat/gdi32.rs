//! Region algebra is guest-side GDI policy. The kernel consumes a rectangle list
//! only when it is selected as a drawing clip.
#![no_std]
#![allow(non_snake_case)]
#![deny(unsafe_op_in_unsafe_fn)]
extern crate alloc;
mod font;
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
    fonts: Vec<(u32, font::LogFont)>,
    selected_fonts: Vec<(u32, u32)>,
    map_modes: Vec<(u32, i32)>,
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
        fonts: Vec::new(),
        selected_fonts: Vec::new(),
        map_modes: Vec::new(),
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
        if let Some(i) = s.regions.iter().position(|(id, _)| *id == h) {
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
        unsafe { RetroGdiDeleteObject(h) }
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
        });
    }
    result
}

unsafe extern "system" {
    fn RetroGdiBitmap(width: u32, height: u32, pixels: *const u32) -> u32;
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
        || !matches!(depth, 1 | 24 | 32)
    {
        return 0;
    }
    let (width, height) = (width.max(1) as usize, height.max(1) as usize);
    let mut pixels = vec![0u32; width * height];
    let stride = (width * depth as usize).div_ceil(16) * 2;
    if !source.is_null() {
        for y in 0..height {
            for x in 0..width {
                pixels[y * width + x] = if depth == 1 {
                    if unsafe { source.add(y * stride + x / 8).read() } & (0x80 >> (x & 7)) != 0 {
                        0xffffff
                    } else {
                        0
                    }
                } else {
                    let p = unsafe { source.add(y * stride + x * (depth as usize / 8)) };
                    unsafe {
                        u32::from(p.add(2).read())
                            | (u32::from(p.add(1).read()) << 8)
                            | (u32::from(p.read()) << 16)
                    }
                };
            }
        }
    }
    unsafe { RetroGdiBitmap(width as u32, height as u32, pixels.as_ptr()) }
}

unsafe extern "system" {
    fn CreateCompatibleDC(dc: u32) -> u32;
    fn BitBlt(
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
    fn RetroGdiFillRect(dc: u32, rect: *const [i32; 4], brush: u32) -> i32;
    fn Polygon(dc: u32, points: *const [i32; 2], count: i32) -> i32;
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
