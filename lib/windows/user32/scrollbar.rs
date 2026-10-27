//! Scrollbar state, painting and input are shared USER policy.
use crate::{input, paint, state};
#[derive(Clone, Copy)]
pub struct Info {
    minimum: i32,
    maximum: i32,
    position: i32,
    tracking: Option<(i32, i32)>, // pointer offset within thumb, tracked value
}
impl Default for Info {
    fn default() -> Self {
        Self {
            minimum: 0,
            maximum: 100,
            position: 0,
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
fn repaint(hwnd: u32, redraw: i32) {
    if redraw != 0 {
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
        repaint(hwnd, redraw);
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
        repaint(hwnd, redraw);
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
    let vertical = style & 1 != 0;
    let cross = if vertical { width } else { height };
    let (length, arrow, thumb, start) = geometry(width, height, vertical, info);
    fill(dc, [0, 0, width, height], 1);
    for (a, b) in [(0, arrow), (length - arrow, length), (start, start + thumb)] {
        if b <= a {
            continue;
        }
        let r = rect(vertical, a, 0, b, cross);
        fill(dc, r, 1);
        crate::frame::bevel(dc, r);
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
fn notify(hwnd: u32, code: u32, position: i32) {
    let target = state::with(|s| {
        s.windows
            .iter()
            .find(|w| w.hwnd == hwnd)
            .map(|w| (w.parent, w.style & 1 != 0))
    });
    if let Some((parent, vertical)) = target {
        unsafe {
            crate::SendMessageW(
                parent,
                if vertical { 0x115 } else { 0x114 },
                code | ((position as u16 as u32) << 16),
                hwnd,
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
    let (length, arrow, thumb, start) = geometry(width, height, vertical, info);
    if msg == 0x201 {
        unsafe {
            input::SetFocus(hwnd);
        }
        unsafe {
            input::SetCapture(hwnd);
        }
        if coordinate >= start && coordinate < start + thumb && info.minimum < info.maximum {
            change(hwnd, 2, |s| {
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
            notify(hwnd, code, 0);
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
            change(hwnd, 2, |s| {
                s.tracking = Some((offset, p));
                0
            });
            repaint(hwnd, 1);
            notify(hwnd, 5, p);
        }
    } else if input::GetCapture() == hwnd {
        change(hwnd, 2, |s| {
            s.tracking = None;
            0
        });
        unsafe {
            input::ReleaseCapture();
        }
        if let Some((_, p)) = info.tracking {
            notify(hwnd, 4, p);
        }
        notify(hwnd, 8, 0);
        repaint(hwnd, 1);
    }
    Some(0)
}
