//! Thread input state and hook chains are USER32 policy.
use crate::{runtime, state, window};
use alloc::vec::Vec;
#[derive(Default)]
pub struct Input {
    pub thread: u32,
    pub focus: u32,
    active: u32,
    pub capture: u32,
}
pub struct Hook {
    handle: u32,
    kind: i32,
    proc: u32,
    thread: u32,
}
pub struct Chain {
    thread: u32,
    handles: Vec<u32>,
    next: usize,
}
fn current() -> u32 {
    unsafe { runtime::GetCurrentThreadId() }
}
fn input(s: &mut state::State, thread: u32) -> &mut Input {
    if let Some(i) = s.inputs.iter().position(|i| i.thread == thread) {
        return &mut s.inputs[i];
    }
    s.inputs.push(Input {
        thread,
        ..Input::default()
    });
    s.inputs.last_mut().unwrap()
}
#[unsafe(no_mangle)]
pub extern "system" fn GetFocus() -> u32 {
    state::with(|s| input(s, current()).focus)
}
#[unsafe(no_mangle)]
pub extern "system" fn GetActiveWindow() -> u32 {
    state::with(|s| input(s, current()).active)
}
#[unsafe(no_mangle)]
pub extern "system" fn GetCapture() -> u32 {
    state::with(|s| input(s, current()).capture)
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SetFocus(h: u32) -> u32 {
    if h != 0 && (window::IsWindow(h) == 0 || window::IsWindowEnabled(h) == 0) {
        return 0;
    }
    let old = GetFocus();
    if old == h {
        return old;
    }
    if unsafe { hooks(5, 9, h, old) } != 0 {
        return 0;
    }
    state::with(|s| input(s, current()).focus = h);
    unsafe {
        if old != 0 {
            crate::SendMessageW(old, 8, h, 0);
        }
        if h != 0 && GetFocus() == h {
            crate::SendMessageW(h, 7, old, 0);
        }
    }
    old
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SetActiveWindow(h: u32) -> u32 {
    if h != 0 && window::IsWindow(h) == 0 {
        return 0;
    }
    let old = GetActiveWindow();
    if old == h {
        return old;
    }
    let data = [0u32, old];
    if unsafe { hooks(5, 5, h, data.as_ptr() as u32) } != 0 {
        return 0;
    }
    state::with(|s| input(s, current()).active = h);
    unsafe {
        if old != 0 {
            crate::SendMessageW(old, 6, 0, h);
        }
        if h != 0 {
            crate::SendMessageW(h, 6, 1, old);
        }
    }
    old
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SetCapture(h: u32) -> u32 {
    if h != 0 && window::IsWindow(h) == 0 {
        return 0;
    }
    let old = state::with(|s| {
        let i = input(s, current());
        let old = i.capture;
        i.capture = h;
        old
    });
    if old != 0 && old != h {
        unsafe {
            crate::SendMessageW(old, 0x215, 0, h);
        }
    }
    old
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn ReleaseCapture() -> i32 {
    unsafe {
        SetCapture(0);
    }
    1
}
#[unsafe(no_mangle)]
pub extern "system" fn SetWindowsHookExA(kind: i32, proc: u32, module: u32, thread: u32) -> u32 {
    if !(-1..=14).contains(&kind) {
        return state::error(1426);
    }
    if proc == 0 {
        return state::error(87);
    }
    if thread == 0 && module == 0 && kind != 13 && kind != 14 {
        return state::error(1428);
    }
    state::with(|s| {
        let handle = s.next_resource;
        s.next_resource += 1;
        s.hooks.push(Hook {
            handle,
            kind,
            proc,
            thread,
        });
        handle
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn SetWindowsHookExW(k: i32, p: u32, m: u32, t: u32) -> u32 {
    SetWindowsHookExA(k, p, m, t)
}
#[unsafe(no_mangle)]
pub extern "system" fn UnhookWindowsHookEx(h: u32) -> i32 {
    state::with(|s| {
        let Some(i) = s.hooks.iter().position(|v| v.handle == h) else {
            return state::error(1404) as i32;
        };
        s.hooks.remove(i);
        1
    })
}
pub unsafe fn hooks(kind: i32, code: i32, w: u32, l: u32) -> i32 {
    let thread = current();
    state::with(|s| {
        let handles = s
            .hooks
            .iter()
            .rev()
            .filter(|h| h.kind == kind && (h.thread == 0 || h.thread == thread))
            .map(|h| h.handle)
            .collect();
        s.chains.push(Chain {
            thread,
            handles,
            next: 0,
        });
    });
    let result = unsafe { CallNextHookEx(0, code, w, l) };
    state::with(|s| {
        if let Some(i) = s.chains.iter().rposition(|c| c.thread == thread) {
            s.chains.remove(i);
        }
    });
    result
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn CallNextHookEx(_h: u32, code: i32, w: u32, l: u32) -> i32 {
    let thread = current();
    let proc = state::with(|s| {
        let chain = s.chains.iter_mut().rev().find(|c| c.thread == thread)?;
        while let Some(&h) = chain.handles.get(chain.next) {
            chain.next += 1;
            if let Some(h) = s.hooks.iter().find(|v| v.handle == h) {
                return Some(h.proc);
            }
        }
        None
    });
    let Some(proc) = proc else {
        return 0;
    };
    let proc: unsafe extern "system" fn(i32, u32, u32) -> i32 =
        unsafe { core::mem::transmute(proc) };
    unsafe { proc(code, w, l) }
}
#[unsafe(no_mangle)]
pub extern "system" fn GetTopWindow(h: u32) -> u32 {
    state::with(|s| {
        s.windows
            .iter()
            .find(|w| w.parent == h)
            .map_or(0, |w| w.hwnd)
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn GetShellWindow() -> u32 {
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn EnumThreadWindows(thread: u32, proc: u32, data: u32) -> i32 {
    if proc == 0 {
        return 0;
    }
    let handles = state::with(|s| {
        s.windows
            .iter()
            .filter(|w| w.thread == thread && w.parent == 0)
            .map(|w| w.hwnd)
            .collect::<Vec<_>>()
    });
    let proc: unsafe extern "system" fn(u32, u32) -> i32 = unsafe { core::mem::transmute(proc) };
    for h in handles {
        if window::IsWindow(h) != 0 && unsafe { proc(h, data) } == 0 {
            return 0;
        }
    }
    1
}
fn navigation(h: u32, start: u32, previous: bool, tab: bool) -> u32 {
    if previous && (start == 0 || start == h) {
        return 0;
    }
    state::with(|s| {
        fn flatten(s: &state::State, parent: u32, out: &mut Vec<(u32, u32)>, depth: usize) {
            if depth > s.windows.len() {
                return;
            }
            for w in s.windows.iter().filter(|w| w.parent == parent) {
                if w.ex_style & 0x10000 != 0 {
                    if w.style & 0x18000000 == 0x10000000 {
                        flatten(s, w.hwnd, out, depth + 1);
                    }
                } else {
                    out.push((w.hwnd, w.style));
                }
            }
        }
        let mut controls = Vec::new();
        flatten(s, h, &mut controls, 0);
        if controls.is_empty() {
            return 0;
        }
        if !previous && start != 0 && start != h && !controls.iter().any(|v| v.0 == start) {
            if let Some(w) = s.windows.iter().find(|w| w.hwnd == start) {
                controls.clear();
                flatten(s, w.parent, &mut controls, 0);
            }
        }
        let index = controls.iter().position(|v| v.0 == start);
        let (lo, hi) = if tab || index.is_none() {
            (0, controls.len())
        } else {
            let i = index.unwrap();
            let lo = (0..=i)
                .rev()
                .find(|&n| controls[n].1 & 0x20000 != 0)
                .unwrap_or(0);
            let hi = (i + 1..controls.len())
                .find(|&n| controls[n].1 & 0x20000 != 0)
                .unwrap_or(controls.len());
            (
                if hi == controls.len() && !previous {
                    0
                } else {
                    lo
                },
                hi,
            )
        };
        let n = hi - lo;
        let origin = index
            .map(|i| i - lo)
            .unwrap_or(if previous { 0 } else { n - 1 });
        for step in 1..=n {
            let j = lo
                + if previous {
                    (origin + n - step) % n
                } else {
                    (origin + step) % n
                };
            let (handle, style) = controls[j];
            if style & 0x18000000 == 0x10000000 && (!tab || style & 0x10000 != 0) {
                return handle;
            }
        }
        if tab { 0 } else { start }
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn GetNextDlgTabItem(h: u32, c: u32, p: u32) -> u32 {
    navigation(h, c, p != 0, true)
}
#[unsafe(no_mangle)]
pub extern "system" fn GetNextDlgGroupItem(h: u32, c: u32, p: u32) -> u32 {
    navigation(h, c, p != 0, false)
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn IsDialogMessageW(h: u32, msg: *const crate::Message) -> i32 {
    if msg.is_null() {
        return 0;
    }
    let m = unsafe { msg.read_unaligned() };
    if m.hwnd != h && window::IsChild(h, m.hwnd) == 0 {
        return 0;
    }
    if m.message == 0x100 && m.wparam == 9 {
        unsafe {
            crate::dialog::focus_control(GetNextDlgTabItem(h, GetFocus(), 0));
        }
        return 1;
    }
    if m.message == 0x100 && matches!(m.wparam, 13 | 27) {
        let focus = GetFocus();
        let id = if m.wparam == 27 {
            2
        } else {
            let button = unsafe { crate::SendMessageW(focus, 0x87, 0, 0) } & 0x2000 != 0;
            if button {
                window::GetDlgCtrlID(focus) as u32
            } else {
                let d = unsafe { crate::SendMessageW(h, 0x400, 0, 0) } as u32;
                if d >> 16 == 0x534b { d & 0xffff } else { 1 }
            }
        };
        unsafe {
            crate::SendMessageW(h, 0x111, id, window::GetDlgItem(h, id as i32));
        }
        return 1;
    }
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn IsDialogMessageA(h: u32, m: *const crate::Message) -> i32 {
    unsafe { IsDialogMessageW(h, m) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn SystemParametersInfoW(
    action: u32,
    _parameter: u32,
    out: u32,
    _flags: u32,
) -> i32 {
    if out == 0 {
        return state::error(87) as i32;
    }
    match action {
        0x30 => {
            unsafe {
                (out as *mut [i32; 4]).write_unaligned([0, 0, 1024, 768]);
            }
            1
        }
        0x29 => {
            let size = unsafe { (out as *const u32).read_unaligned() };
            if size != 500 && size != 504 {
                return state::error(87) as i32;
            }
            unsafe {
                core::ptr::write_bytes((out + 4) as *mut u8, 0, (size - 4) as usize);
            }
            for (offset, value) in [
                (4, 1),
                (8, 16),
                (12, 16),
                (16, 18),
                (20, 18),
                (116, 16),
                (120, 16),
                (216, 18),
                (220, 18),
            ] {
                unsafe {
                    ((out + offset) as *mut u32).write_unaligned(value);
                }
            }
            for offset in [24, 124, 224, 316, 408] {
                unsafe {
                    ((out + offset) as *mut i32).write_unaligned(16);
                    ((out + offset + 4) as *mut i32).write_unaligned(8);
                    ((out + offset + 16) as *mut i32).write_unaligned(400);
                }
                let face: [u16; 7] = [83, 121, 115, 116, 101, 109, 0];
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        face.as_ptr(),
                        (out + offset + 28) as *mut u16,
                        7,
                    );
                }
            }
            1
        }
        _ => state::error(120) as i32,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetCursorPos(out: *mut [i32; 2]) -> i32 {
    if out.is_null() {
        return 0;
    }
    let position = state::with(|s| s.cursor);
    unsafe {
        out.write_unaligned(position);
    }
    1
}
#[unsafe(no_mangle)]
pub extern "system" fn SetCursorPos(x: i32, y: i32) -> i32 {
    state::with(|s| {
        let r = s.cursor_clip.unwrap_or([0, 0, 1024, 768]);
        s.cursor = [x.clamp(r[0], r[2] - 1), y.clamp(r[1], r[3] - 1)];
    });
    1
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn ClipCursor(rect: *const [i32; 4]) -> i32 {
    let rect = if rect.is_null() {
        None
    } else {
        let r = unsafe { rect.read_unaligned() };
        if r[0] >= r[2] || r[1] >= r[3] {
            return state::error(87) as i32;
        }
        Some(r)
    };
    let position = state::with(|s| {
        s.cursor_clip = rect;
        s.cursor
    });
    SetCursorPos(position[0], position[1])
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn mouse_event(flags: u32, dx: u32, dy: u32, data: u32, extra: u32) {
    let position = state::with(|s| s.cursor);
    let next = if flags & 1 == 0 {
        position
    } else if flags & 0x8000 != 0 {
        [
            (u64::from(dx) * 1024 / 65536) as i32,
            (u64::from(dy) * 768 / 65536) as i32,
        ]
    } else {
        [
            position[0].saturating_add(dx as i32),
            position[1].saturating_add(dy as i32),
        ]
    };
    let mut messages = Vec::new();
    for (flag, msg) in [
        (1, 0x200),
        (2, 0x201),
        (4, 0x202),
        (8, 0x204),
        (16, 0x205),
        (32, 0x207),
        (64, 0x208),
        (0x800, 0x20a),
    ] {
        if flags & flag != 0 {
            messages.push(msg);
        }
    }
    for msg in messages {
        let details = [
            next[0] as u32,
            next[1] as u32,
            data << 16,
            1,
            unsafe { runtime::GetTickCount() },
            extra,
        ];
        if unsafe { hooks(14, 0, msg, details.as_ptr() as u32) } != 0 {
            continue;
        }
        if flags & 1 != 0 {
            SetCursorPos(next[0], next[1]);
        }
        let target = if GetCapture() != 0 {
            GetCapture()
        } else if GetFocus() != 0 {
            GetFocus()
        } else {
            GetActiveWindow()
        };
        if target != 0 {
            let p = state::with(|s| s.cursor);
            crate::message::PostMessageW(
                target,
                msg,
                if msg == 0x20a { data << 16 } else { 0 },
                (p[0] as u32 & 0xffff) | ((p[1] as u32 & 0xffff) << 16),
            );
        }
    }
}
