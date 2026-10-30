//! Scrollbar state, painting and input are shared USER policy.
use crate::{input, paint, state};
#[derive(Clone, Copy)]
pub struct Info {
    minimum: i32,
    maximum: i32,
    position: i32,
    pressed: bool,
    tracking: Option<(i32, i32)>, // pointer offset within thumb, tracked value
}
impl Default for Info {
    fn default() -> Self {
        Self {
            minimum: 0,
            maximum: 100,
            position: 0,
            pressed: false,
            tracking: None,
        }
    }
}
unsafe extern "system" {
    fn FillRect(dc: u32, rect: *const [i32; 4], brush: u32) -> i32;
    fn GetStockObject(index: u32) -> u32;
}
fn change(hwnd: u32, bar: i32, f: impl FnOnce(&mut Info) -> i32) -> Option<i32> {
    let index = usize::try_from(bar).ok().filter(|&i| i < 3)?;
    state::with(|s| {
        s.windows
            .iter_mut()
            .find(|w| w.hwnd == hwnd)
            .map(|w| f(&mut w.control.scroll[index]))
    })
}
fn repaint(hwnd: u32, bar: i32, redraw: i32) {
    if redraw != 0 {
        if bar != 2 {
            crate::frame::paint(hwnd);
            return;
        }
        unsafe {
            paint::InvalidateRect(hwnd, 0, 0);
        }
    }
}
#[unsafe(no_mangle)]
pub extern "system" fn SetScrollPos(hwnd: u32, bar: i32, position: i32, redraw: i32) -> i32 {
    let old = change(hwnd, bar, |s| {
        let old = s.position;
        s.position = position.clamp(s.minimum, s.maximum);
        old
    });
    if old.is_some() {
        repaint(hwnd, bar, redraw);
    }
    old.unwrap_or(0)
}
#[unsafe(no_mangle)]
pub extern "system" fn GetScrollPos(hwnd: u32, bar: i32) -> i32 {
    change(hwnd, bar, |s| s.position).unwrap_or(0)
}
#[unsafe(no_mangle)]
pub extern "system" fn SetScrollRange(
    hwnd: u32,
    bar: i32,
    minimum: i32,
    maximum: i32,
    redraw: i32,
) -> i32 {
    if minimum > maximum {
        return 0;
    }
    let result = change(hwnd, bar, |s| {
        s.minimum = minimum;
        s.maximum = maximum;
        s.position = s.position.clamp(minimum, maximum);
        1
    });
    if result.is_some() {
        repaint(hwnd, bar, redraw);
    }
    result.unwrap_or(0)
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetScrollRange(
    hwnd: u32,
    bar: i32,
    minimum: *mut i32,
    maximum: *mut i32,
) -> i32 {
    change(hwnd, bar, |s| {
        unsafe {
            if !minimum.is_null() {
                minimum.write_unaligned(s.minimum);
            }
            if !maximum.is_null() {
                maximum.write_unaligned(s.maximum);
            }
        }
        1
    })
    .unwrap_or(0)
}
fn geometry(width: i32, height: i32, vertical: bool, s: Info) -> (i32, i32, i32, i32) {
    let (length, cross) = if vertical {
        (height, width)
    } else {
        (width, height)
    };
    let arrow = cross.min(length / 2).max(0);
    let thumb = cross.min((length - 2 * arrow).max(0)).max(0);
    let travel = (length - 2 * arrow - thumb).max(0);
    let position = s.tracking.map_or(s.position, |(_, p)| p);
    let span = i64::from(s.maximum) - i64::from(s.minimum);
    let offset = if span > 0 {
        ((i64::from(position) - i64::from(s.minimum)) * i64::from(travel) / span) as i32
    } else {
        0
    };
    (length, arrow, thumb, arrow + offset)
}
fn rect(vertical: bool, a: i32, b: i32, c: i32, d: i32) -> [i32; 4] {
    if vertical { [b, a, d, c] } else { [a, b, c, d] }
}
fn fill(dc: u32, r: [i32; 4], brush: u32) {
    unsafe {
        FillRect(dc, &r, GetStockObject(brush));
    }
}
pub fn draw(dc: u32, hwnd: u32, width: i32, height: i32, style: u32) {
    let Some(info) = state::with(|s| {
        s.windows
            .iter()
            .find(|w| w.hwnd == hwnd)
            .map(|w| w.control.scroll[2])
    }) else {
        return;
    };
    draw_at(dc, [0, 0, width, height], style & 1 != 0, info);
}
fn draw_at(dc: u32, area: [i32; 4], vertical: bool, info: Info) {
    let [x, y, right, bottom] = area;
    let (width, height) = (right - x, bottom - y);
    let translate = |r: [i32; 4]| [r[0] + x, r[1] + y, r[2] + x, r[3] + y];
    let fill = |dc, r, brush| fill(dc, translate(r), brush);
    let cross = if vertical { width } else { height };
    let (length, arrow, thumb, start) = geometry(width, height, vertical, info);
    fill(dc, [0, 0, width, height], 1);
    for (a, b) in [(0, arrow), (length - arrow, length), (start, start + thumb)] {
        if b <= a {
            continue;
        }
        let r = rect(vertical, a, 0, b, cross);
        fill(dc, r, 1);
        crate::frame::bevel(dc, translate(r));
    }
    if arrow >= 5 && cross >= 5 {
        let center = cross / 2;
        let radius = (arrow.min(cross) / 4).max(1);
        for i in 0..radius {
            fill(
                dc,
                rect(
                    vertical,
                    arrow / 2 - radius / 2 + i,
                    center - i,
                    arrow / 2 - radius / 2 + i + 1,
                    center + i + 1,
                ),
                4,
            );
            fill(
                dc,
                rect(
                    vertical,
                    length - arrow / 2 + radius / 2 - i - 1,
                    center - i,
                    length - arrow / 2 + radius / 2 - i,
                    center + i + 1,
                ),
                4,
            );
        }
    }
}
fn notify(hwnd: u32, bar: i32, code: u32, position: i32) {
    let target = state::with(|s| {
        s.windows.iter().find(|w| w.hwnd == hwnd).map(|w| {
            if bar == 2 {
                (w.parent, w.style & 1 != 0)
            } else {
                (hwnd, bar == 1)
            }
        })
    });
    if let Some((parent, vertical)) = target {
        unsafe {
            crate::SendMessageW(
                parent,
                if vertical { 0x115 } else { 0x114 },
                code | ((position as u16 as u32) << 16),
                if bar == 2 { hwnd } else { 0 },
            );
        }
    }
}
pub unsafe fn message(hwnd: u32, msg: u32, wp: u32, lp: u32) -> Option<i32> {
    match msg {
        0xe0 => return Some(SetScrollPos(hwnd, 2, wp as i32, lp as i32)),
        0xe1 => return Some(GetScrollPos(hwnd, 2)),
        0xe2 | 0xe6 => {
            SetScrollRange(hwnd, 2, wp as i32, lp as i32, i32::from(msg == 0xe6));
            return Some(0);
        }
        0xe3 => {
            unsafe {
                GetScrollRange(hwnd, 2, wp as *mut i32, lp as *mut i32);
            }
            return Some(0);
        }
        0x201 | 0x200 | 0x202 => {}
        _ => return None,
    }
    let (width, height, style, info) = state::with(|s| {
        s.windows.iter().find(|w| w.hwnd == hwnd).map(|w| {
            let r = crate::frame::client(s, w);
            (r[2] - r[0], r[3] - r[1], w.style, w.control.scroll[2])
        })
    })?;
    let vertical = style & 1 != 0;
    let coordinate = if vertical {
        (lp >> 16) as u16 as i16 as i32
    } else {
        lp as u16 as i16 as i32
    };
    pointer_message(hwnd, 2, width, height, vertical, info, msg, coordinate)
}
#[allow(clippy::too_many_arguments)]
fn pointer_message(
    hwnd: u32,
    bar: i32,
    width: i32,
    height: i32,
    vertical: bool,
    info: Info,
    msg: u32,
    coordinate: i32,
) -> Option<i32> {
    let (length, arrow, thumb, start) = geometry(width, height, vertical, info);
    if msg == 0x201 {
        change(hwnd, bar, |s| {
            s.pressed = true;
            s.tracking = None;
            0
        });
        unsafe {
            input::SetFocus(hwnd);
        }
        unsafe {
            input::SetCapture(hwnd);
        }
        if coordinate >= start && coordinate < start + thumb && info.minimum < info.maximum {
            change(hwnd, bar, |s| {
                s.tracking = Some((coordinate - start, s.position));
                0
            });
        } else {
            let code = if coordinate < arrow {
                0
            } else if coordinate >= length - arrow {
                1
            } else if coordinate < start {
                2
            } else {
                3
            };
            notify(hwnd, bar, code, 0);
        }
    } else if msg == 0x200 {
        if let Some((offset, _)) = info.tracking {
            let travel = (length - 2 * arrow - thumb).max(0);
            let p = if travel > 0 {
                i64::from(info.minimum)
                    + (i64::from((coordinate - offset - arrow).clamp(0, travel))
                        * (i64::from(info.maximum) - i64::from(info.minimum))
                        / i64::from(travel))
            } else {
                i64::from(info.minimum)
            } as i32;
            change(hwnd, bar, |s| {
                s.tracking = Some((offset, p));
                0
            });
            repaint(hwnd, bar, 1);
            notify(hwnd, bar, 5, p);
        }
    } else if input::GetCapture() == hwnd {
        change(hwnd, bar, |s| {
            s.tracking = None;
            s.pressed = false;
            0
        });
        unsafe {
            input::ReleaseCapture();
        }
        if let Some((_, p)) = info.tracking {
            notify(hwnd, bar, 4, p);
        }
        notify(hwnd, bar, 8, 0);
        repaint(hwnd, bar, 1);
    }
    Some(0)
}

/// Standard scroll bars occupy the frame, sharing state with SB_HORZ/SB_VERT.
pub fn area(s: &state::State, w: &state::Window, bar: i32) -> Option<[i32; 4]> {
    let mask = if bar == 0 { 0x00100000 } else { 0x00200000 };
    if w.style & mask == 0 {
        return None;
    }
    let r = crate::frame::client(s, w);
    let m = crate::frame::margins(w.style, w.ex_style, false);
    let a = if bar == 0 {
        [r[0], r[3], r[2], (r[3] + 16).min(w.height - m[3])]
    } else {
        [r[2], r[1], (r[2] + 16).min(w.width - m[2]), r[3]]
    };
    (a[0] < a[2] && a[1] < a[3]).then_some(a)
}
pub fn draw_frame(dc: u32, hwnd: u32) {
    let bars = state::with(|s| {
        s.windows
            .iter()
            .find(|w| w.hwnd == hwnd)
            .map(|w| [0, 1].map(|bar| area(s, w, bar).map(|a| (a, w.control.scroll[bar as usize]))))
    });
    if let Some(bars) = bars {
        for (bar, entry) in bars.into_iter().enumerate() {
            if let Some((a, info)) = entry {
                draw_at(dc, a, bar == 1, info);
            }
        }
    }
}
pub fn frame_message(hwnd: u32, msg: u32, hit: u32, lp: u32) -> Option<i32> {
    if msg == 0x215 {
        let changed = state::with(|s| {
            s.windows
                .iter_mut()
                .find(|w| w.hwnd == hwnd)
                .is_some_and(|w| {
                    let changed = w.control.scroll[..2].iter().any(|i| i.pressed);
                    for i in &mut w.control.scroll[..2] {
                        i.pressed = false;
                        i.tracking = None;
                    }
                    changed
                })
        });
        if changed {
            crate::frame::paint(hwnd);
        }
        return None;
    }
    if !matches!(msg, 0xa0..=0xa2 | 0x200 | 0x202) {
        return None;
    }
    let captured = input::GetCapture() == hwnd;
    let (bar, a, info, origin) = state::with(|s| {
        let w = s.windows.iter().find(|w| w.hwnd == hwnd)?;
        let bar = if matches!(msg, 0xa0..=0xa2) && (hit == 6 || hit == 7) {
            hit as i32 - 6
        } else if matches!(msg, 0x200 | 0x202) && captured {
            (0..2).find(|&b| w.control.scroll[b].pressed)? as i32
        } else {
            return None;
        };
        let origin = if msg < 0x200 {
            crate::frame::origin(s, hwnd, false)?
        } else {
            let c = crate::frame::client(s, w);
            (-c[0], -c[1])
        };
        Some((
            bar,
            area(s, w, bar)?,
            w.control.scroll[bar as usize],
            origin,
        ))
    })?;
    let x = (lp as u16 as i16) as i32 - origin.0 - a[0];
    let y = ((lp >> 16) as u16 as i16) as i32 - origin.1 - a[1];
    pointer_message(
        hwnd,
        bar,
        a[2] - a[0],
        a[3] - a[1],
        bar == 1,
        info,
        if msg < 0x200 { msg + 0x160 } else { msg },
        if bar == 1 { y } else { x },
    )
}
#[unsafe(no_mangle)]
pub extern "system" fn ShowScrollBar(hwnd: u32, bar: i32, show: i32) -> i32 {
    if !(0..=3).contains(&bar) {
        return state::error(87) as i32;
    }
    if crate::window::IsWindow(hwnd) == 0 {
        return state::error(1400) as i32;
    }
    if bar == 2 {
        if show == 0 {
            change(hwnd, 2, |s| {
                s.pressed = false;
                s.tracking = None;
                0
            });
            if input::GetCapture() == hwnd {
                unsafe { input::ReleaseCapture(); }
            }
        }
        crate::window::ShowWindow(hwnd, if show != 0 { 5 } else { 0 });
        return 1;
    }
    let mask = match bar {
        0 => 0x00100000,
        1 => 0x00200000,
        _ => 0x00300000,
    };
    let Some((changed, cancelled)) = state::with(|s| {
        let w = s.windows.iter_mut().find(|w| w.hwnd == hwnd)?;
        let old = w.style;
        if show != 0 {
            w.style |= mask;
        } else {
            w.style &= !mask;
        }
        let mut cancelled = false;
        if show == 0 {
            for b in 0..2 {
                if bar == 3 || bar == b {
                    let info = &mut w.control.scroll[b as usize];
                    cancelled |= info.pressed;
                    info.pressed = false;
                    info.tracking = None;
                }
            }
        }
        Some((old != w.style, cancelled))
    }) else {
        return 0;
    };
    if cancelled && input::GetCapture() == hwnd {
        unsafe {
            input::ReleaseCapture();
        }
    }
    if changed {
        crate::window::SetWindowPos(hwnd, 0, 0, 0, 0, 0, 0x37);
        let size = state::with(|s| {
            s.windows.iter().find(|w| w.hwnd == hwnd).map(|w| {
                let r = crate::frame::client(s, w);
                let kind = if w.style & 0x20000000 != 0 {
                    1
                } else if w.style & 0x01000000 != 0 {
                    2
                } else {
                    0
                };
                (kind, crate::frame::pack(r[2] - r[0], r[3] - r[1]))
            })
        });
        if let Some((kind, size)) = size {
            unsafe {
                paint::InvalidateRect(hwnd, 0, 1);
                crate::SendMessageW(hwnd, 5, kind, size);
            }
        }
    }
    1
}
