//! Caret ownership and blinking are shared USER policy, including Win16.
use crate::{message, paint, runtime, state, window};

#[derive(Clone, Copy)]
pub struct Caret {
    thread: u32,
    hwnd: u32,
    bitmap: u32,
    position: [i32; 2],
    size: [i32; 2],
    hidden: i32,
    painted: bool,
    timer: u32,
}
unsafe extern "system" {
    fn PatBlt(dc: u32, x: i32, y: i32, w: i32, h: i32, rop: u32) -> i32;
    fn BitBlt(dc: u32, x: i32, y: i32, w: i32, h: i32, src: u32, sx: i32, sy: i32, rop: u32)
    -> i32;
    fn CreateCompatibleDC(dc: u32) -> u32;
    fn SelectObject(dc: u32, obj: u32) -> u32;
    fn DeleteDC(dc: u32) -> i32;
    fn GetObjectW(object: u32, bytes: i32, out: *mut u32) -> i32;
}
fn thread() -> u32 {
    unsafe { runtime::GetCurrentThreadId() }
}
fn invert(c: Caret) {
    let dc = unsafe { paint::GetDC(c.hwnd) };
    if dc == 0 {
        return;
    }
    let [x, y] = c.position;
    let [w, h] = c.size;
    unsafe {
        if c.bitmap > 1 {
            let src = CreateCompatibleDC(dc);
            if src != 0 {
                let old = SelectObject(src, c.bitmap);
                BitBlt(dc, x, y, w, h, src, 0, 0, 0x00660046);
                SelectObject(src, old);
                DeleteDC(src);
            }
        } else if c.bitmap == 1 {
            for row in 0..h {
                for col in 0..w {
                    if (row + col) & 1 == 0 {
                        PatBlt(dc, x + col, y + row, 1, 1, 0x00550009);
                    }
                }
            }
        } else {
            PatBlt(dc, x, y, w, h, 0x00550009);
        }
    }
    paint::ReleaseDC(c.hwnd, dc);
}
unsafe extern "system" fn blink(_: u32, _: u32, id: u32, _: u32) {
    let owner = thread();
    let c = state::with(|s| {
        let c = s
            .carets
            .iter_mut()
            .find(|c| c.thread == owner && c.timer == id && c.hidden == 0)?;
        c.painted = !c.painted;
        Some(*c)
    });
    if let Some(c) = c {
        invert(c);
    }
}
#[unsafe(no_mangle)]
pub extern "system" fn CreateCaret(hwnd: u32, bitmap: u32, width: i32, height: i32) -> i32 {
    let owner = thread();
    if !state::with(|s| {
        s.windows
            .iter()
            .any(|w| w.hwnd == hwnd && w.thread == owner)
    }) {
        return 0;
    }
    let mut size = [width.max(1), height.max(1)];
    if bitmap > 1 {
        let mut object = [0; 6];
        if unsafe { GetObjectW(bitmap, 24, object.as_mut_ptr()) } != 24 {
            return 0;
        }
        size = [object[1] as i32, object[2] as i32];
    }
    DestroyCaret();
    let timer = message::SetTimer(0, 0, GetCaretBlinkTime(), blink as *const () as u32);
    state::with(|s| {
        s.carets.push(Caret {
            thread: owner,
            hwnd,
            bitmap,
            position: [0, 0],
            size,
            hidden: 1,
            painted: false,
            timer,
        })
    });
    1
}
#[unsafe(no_mangle)]
pub extern "system" fn DestroyCaret() -> i32 {
    let owner = thread();
    let c = state::with(|s| {
        s.carets
            .iter()
            .position(|c| c.thread == owner)
            .map(|i| s.carets.remove(i))
    });
    let Some(c) = c else {
        return 0;
    };
    message::KillTimer(0, c.timer);
    if c.painted && window::IsWindow(c.hwnd) != 0 {
        invert(c);
    }
    1
}
pub fn destroy_window(hwnd: u32) {
    if state::with(|s| s.carets.iter().any(|c| c.hwnd == hwnd)) {
        DestroyCaret();
    }
}
fn visibility(hwnd: u32, show: bool) -> i32 {
    let owner = thread();
    let change = state::with(|s| {
        let c = s
            .carets
            .iter_mut()
            .find(|c| c.thread == owner && (hwnd == 0 || c.hwnd == hwnd))?;
        if show {
            c.hidden = c.hidden.saturating_sub(1).max(0);
        } else {
            c.hidden = c.hidden.saturating_add(1);
        }
        let paint = c.hidden == 0;
        let changed = c.painted != paint;
        c.painted = paint;
        Some((*c, changed))
    });
    let Some((c, changed)) = change else {
        return 0;
    };
    if changed {
        invert(c);
    }
    1
}
#[unsafe(no_mangle)]
pub extern "system" fn ShowCaret(hwnd: u32) -> i32 {
    visibility(hwnd, true)
}
#[unsafe(no_mangle)]
pub extern "system" fn HideCaret(hwnd: u32) -> i32 {
    visibility(hwnd, false)
}
#[unsafe(no_mangle)]
pub extern "system" fn SetCaretPos(x: i32, y: i32) -> i32 {
    let owner = thread();
    let pair = state::with(|s| {
        let c = s.carets.iter_mut().find(|c| c.thread == owner)?;
        let old = *c;
        c.position = [x, y];
        Some((old, *c))
    });
    let Some((old, new)) = pair else {
        return 0;
    };
    if old.painted {
        invert(old);
        invert(new);
    }
    1
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetCaretPos(out: *mut [i32; 2]) -> i32 {
    if out.is_null() {
        return 0;
    }
    let owner = thread();
    let Some(pos) = state::with(|s| {
        s.carets
            .iter()
            .find(|c| c.thread == owner)
            .map(|c| c.position)
    }) else {
        return 0;
    };
    unsafe {
        out.write_unaligned(pos);
    }
    1
}
#[unsafe(no_mangle)]
pub extern "system" fn GetCaretBlinkTime() -> u32 {
    state::with(|s| s.caret_interval)
}
#[unsafe(no_mangle)]
pub extern "system" fn SetCaretBlinkTime(ms: u32) -> i32 {
    if ms == 0 {
        return 0;
    }
    let owner = thread();
    let timer = state::with(|s| {
        s.caret_interval = ms;
        s.carets.iter().find(|c| c.thread == owner).map(|c| c.timer)
    });
    if let Some(id) = timer {
        message::SetTimer(0, id, ms, blink as *const () as u32);
    }
    1
}
