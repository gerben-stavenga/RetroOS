//! Window policy and callback sequencing in guest code. Kernel surfaces contain
//! pixels and placement, never application procedures or class metadata.
use crate::{
    CreateStruct, SendMessageW, class, runtime,
    state::{self, Window},
    text,
};
use alloc::{vec, vec::Vec};

const CHILD: u32 = 0x4000_0000;
const VISIBLE: u32 = 0x1000_0000;
unsafe extern "system" {
    fn GetSystemMetrics(index: u32) -> u32;
    fn RetroSurfaceCreate(x: i32, y: i32, width: i32, height: i32, parent: u32) -> u32;
    fn RetroSurfaceUpdate(
        hwnd: u32,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        parent: u32,
        visible: u32,
    ) -> u32;
    fn RetroReleaseWindow(hwnd: u32) -> u32;
}
pub(crate) fn update(hwnd: u32) {
    let info = state::with(|s| {
        s.windows.iter().find(|w| w.hwnd == hwnd).map(|w| {
            let r = s
                .windows
                .iter()
                .find(|p| p.hwnd == w.parent)
                .map_or([0; 4], |p| crate::frame::client(s, p));
            (
                w.x + r[0],
                w.y + r[1],
                w.width,
                w.height,
                w.parent,
                u32::from(w.style & VISIBLE != 0),
            )
        })
    });
    if let Some((x, y, width, height, parent, visible)) = info {
        unsafe {
            RetroSurfaceUpdate(hwnd, x, y, width, height, parent, visible);
        }
    }
}
pub unsafe fn create(mut cs: CreateStruct, wide: bool) -> u32 {
    crate::controls::ensure();
    if crate::message::ensure_queue() == 0 {
        return 0;
    }
    let class = state::with(|s| {
        let i = if cs.instance == 0 {
            let value = if cs.class > 0xffff {
                unsafe { text::read(cs.class, wide) }
            } else {
                alloc::vec::Vec::new()
            };
            s.classes.iter().rposition(|c| {
                if cs.class <= 0xffff {
                    c.atom == cs.class
                } else {
                    text::same(&c.name, &value)
                }
            })
        } else {
            unsafe { class::find(&s.classes, cs.class, cs.instance, wide) }
        }?;
        s.classes[i].live += 1;
        Some(s.classes[i].clone())
    });
    let Some(class) = class else {
        return state::error(1411);
    };
    let parent = if cs.style & CHILD != 0 { cs.parent } else { 0 };
    if parent != 0 && IsWindow(parent) == 0 {
        release_class(class.atom);
        return state::error(1400);
    };
    if cs.style & CHILD != 0 && parent == 0 {
        release_class(class.atom);
        return state::error(1406);
    };
    if cs.x == i32::MIN {
        cs.x = 0;
        cs.y = 0;
    }
    if cs.width == i32::MIN {
        cs.width = 640;
        cs.height = 480;
    }
    cs.width = cs.width.clamp(0, 2048);
    cs.height = cs.height.clamp(0, 2048);
    let hwnd = unsafe { RetroSurfaceCreate(cs.x, cs.y, cs.width, cs.height, parent) };
    if hwnd == 0 {
        release_class(class.atom);
        return state::error(8);
    };
    let thread = unsafe { runtime::GetCurrentThreadId() };
    let title = unsafe { text::read(cs.title, wide) };
    let show = cs.style & VISIBLE != 0;
    state::with(|s| {
        s.windows.push(Window {
            hwnd,
            class: class.atom,
            thread,
            proc: crate::controls::variant(class.proc, wide),
            instance: cs.instance,
            parent,
            owner: if parent == 0 { cs.parent } else { 0 },
            id: cs.menu,
            style: cs.style & !VISIBLE,
            ex_style: cs.ex_style,
            user: 0,
            extra: vec![0; class.window_extra],
            title,
            x: cs.x,
            y: cs.y,
            width: cs.width,
            height: cs.height,
            normal_rect: None,
            needs_size: true,
            destroying: false,
            wide: if crate::controls::builtin(class.proc) {
                wide
            } else {
                class.wide
            },
            control: crate::controls::Control::default(),
        })
    });
    if parent == 0 {
        let menu = if cs.menu != 0 {
            cs.menu
        } else if class.menu != 0 {
            if class.wide {
                unsafe { crate::menu::LoadMenuW(class.instance, class.menu) }
            } else {
                unsafe { crate::menu::LoadMenuA(class.instance, class.menu) }
            }
        } else {
            0
        };
        if menu != 0 {
            crate::menu::SetMenu(hwnd, menu);
        }
    }
    update(hwnd);
    let address = (&raw mut cs) as u32;
    let nc = unsafe { SendMessageW(hwnd, 0x81, 0, address) } != 0;
    if IsWindow(hwnd) == 0 {
        return 0;
    }
    let accepted = nc && unsafe { SendMessageW(hwnd, 1, 0, address) } != -1;
    if IsWindow(hwnd) == 0 {
        return 0;
    }
    if !accepted {
        if nc {
            DestroyWindow(hwnd);
        } else {
            unsafe {
                SendMessageW(hwnd, 0x82, 0, 0);
            }
            remove(hwnd);
        }
        return 0;
    }
    // Child and popup windows receive their initial size at creation;
    // overlapped windows receive it when first shown.
    if cs.style & (CHILD | 0x8000_0000) != 0 {
        let initial = state::with(|s| {
            let w = s.windows.iter().find(|w| w.hwnd == hwnd)?;
            let r = crate::frame::client(s, w);
            Some((
                crate::frame::pack(r[2] - r[0], r[3] - r[1]),
                crate::frame::pack(w.x + r[0], w.y + r[1]),
            ))
        });
        if let Some((size, position)) = initial {
            state::with(|s| {
                if let Some(w) = s.windows.iter_mut().find(|w| w.hwnd == hwnd) {
                    w.needs_size = false;
                }
            });
            unsafe {
                SendMessageW(hwnd, 5, 0, size);
                SendMessageW(hwnd, 3, 0, position);
            }
        }
        if IsWindow(hwnd) == 0 {
            return 0;
        }
    }
    if show {
        ShowWindow(hwnd, 5);
    }
    hwnd
}
fn release_class(atom: u32) {
    state::with(|s| {
        if let Some(c) = s.classes.iter_mut().find(|c| c.atom == atom) {
            c.live -= 1;
        }
    });
}
fn remove(hwnd: u32) {
    let parent = state::with(|s| {
        s.windows
            .iter()
            .find(|w| w.hwnd == hwnd)
            .map(|w| (w.parent, [w.x, w.y, w.x + w.width, w.y + w.height]))
    });
    if crate::input::GetFocus() == hwnd {
        unsafe {
            crate::input::SetFocus(0);
        }
    }
    if crate::input::GetCapture() == hwnd {
        unsafe {
            crate::input::ReleaseCapture();
        }
    }
    crate::menu::destroy_window(hwnd);
    crate::paint::destroy(hwnd);
    state::with(|s| {
        s.timers.retain(|t| t.hwnd != hwnd);
        if s.menu_popup.as_ref().is_some_and(|p| p.hwnd == hwnd) {
            s.menu_popup = None;
        }
        for q in &mut s.queues {
            q.messages.retain(|m| m.hwnd != hwnd);
            q.input.retain(|m| m.hwnd != hwnd);
        }
        if let Some(i) = s.windows.iter().position(|w| w.hwnd == hwnd) {
            let window = s.windows.remove(i);
            if let Some(c) = s.classes.iter_mut().find(|c| c.atom == window.class) {
                c.live -= 1;
            }
        }
    });
    unsafe {
        RetroReleaseWindow(hwnd);
        if let Some((parent, rect)) = parent.filter(|p| p.0 != 0) {
            crate::paint::InvalidateRect(parent, rect.as_ptr() as u32, 1);
        }
    }
}
#[unsafe(no_mangle)]
pub extern "system" fn DestroyWindow(hwnd: u32) -> i32 {
    let thread = unsafe { runtime::GetCurrentThreadId() };
    let ready = state::with(|s| {
        let Some(w) = s.windows.iter_mut().find(|w| w.hwnd == hwnd) else {
            return state::error(1400);
        };
        if w.thread != thread {
            return state::error(5);
        };
        if w.destroying {
            return 0;
        };
        w.destroying = true;
        1
    });
    if ready == 0 {
        return 0;
    }
    unsafe {
        SendMessageW(hwnd, 2, 0, 0);
    }
    loop {
        let child = state::with(|s| {
            s.windows
                .iter()
                .find(|w| w.parent == hwnd || w.owner == hwnd)
                .map(|w| w.hwnd)
        });
        let Some(child) = child else { break };
        if DestroyWindow(child) == 0 {
            break;
        }
    }
    if IsWindow(hwnd) != 0 {
        unsafe {
            SendMessageW(hwnd, 0x82, 0, 0);
        }
    }
    remove(hwnd);
    1
}
#[unsafe(no_mangle)]
pub extern "system" fn IsWindow(hwnd: u32) -> i32 {
    state::with(|s| i32::from(s.windows.iter().any(|w| w.hwnd == hwnd)))
}
#[unsafe(no_mangle)]
pub extern "system" fn IsWindowUnicode(hwnd: u32) -> i32 {
    state::with(|s| {
        s.windows
            .iter()
            .find(|w| w.hwnd == hwnd)
            .map_or(0, |w| i32::from(w.wide))
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn IsWindowVisible(hwnd: u32) -> i32 {
    state::with(|s| {
        let mut handle = hwnd;
        for _ in 0..=s.windows.len() {
            let Some(w) = s.windows.iter().find(|w| w.hwnd == handle) else {
                return 0;
            };
            if w.style & VISIBLE == 0 {
                return 0;
            };
            if w.parent == 0 {
                return 1;
            };
            handle = w.parent;
        }
        0
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn IsWindowEnabled(hwnd: u32) -> i32 {
    state::with(|s| {
        s.windows
            .iter()
            .find(|w| w.hwnd == hwnd)
            .map_or(0, |w| i32::from(w.style & 0x0800_0000 == 0))
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn EnableWindow(hwnd: u32, enable: i32) -> i32 {
    let was = state::with(|s| {
        let Some(w) = s.windows.iter_mut().find(|w| w.hwnd == hwnd) else {
            return None;
        };
        let disabled = w.style & 0x0800_0000 != 0;
        if enable != 0 {
            w.style &= !0x0800_0000;
        } else {
            w.style |= 0x0800_0000;
        }
        Some(disabled)
    });
    let Some(was) = was else {
        return state::error(1400) as i32;
    };
    if enable == 0
        && (crate::input::GetFocus() == hwnd || IsChild(hwnd, crate::input::GetFocus()) != 0)
    {
        unsafe {
            crate::input::SetFocus(0);
        }
    }
    if was == (enable != 0) {
        unsafe {
            SendMessageW(hwnd, 0x0a, u32::from(enable != 0), 0);
        }
    }
    i32::from(was)
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WindowPos {
    hwnd: u32,
    after: u32,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    flags: u32,
}
#[unsafe(no_mangle)]
pub extern "system" fn SetWindowPos(
    hwnd: u32,
    after: u32,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    flags: u32,
) -> i32 {
    let old = state::with(|s| {
        s.windows
            .iter()
            .find(|w| w.hwnd == hwnd)
            .map(|w| (w.x, w.y, w.width, w.height, w.style))
    });
    let Some(old) = old else {
        return state::error(1400) as i32;
    };
    let mut pos = WindowPos {
        hwnd,
        after,
        x,
        y,
        width,
        height,
        flags,
    };
    if flags & 0x400 == 0 {
        unsafe {
            SendMessageW(hwnd, 0x46, 0, (&raw mut pos) as u32);
        }
    }
    let done = state::with(|s| {
        let Some(w) = s.windows.iter_mut().find(|w| w.hwnd == hwnd) else {
            return false;
        };
        if pos.flags & 2 == 0 {
            w.x = pos.x;
            w.y = pos.y;
        } else {
            pos.x = w.x;
            pos.y = w.y;
        }
        if pos.flags & 1 == 0 {
            w.needs_size = false;
            w.width = pos.width.clamp(0, 2048);
            w.height = pos.height.clamp(0, 2048);
        }
        pos.width = w.width;
        pos.height = w.height;
        if pos.flags & 0x40 != 0 {
            w.style |= VISIBLE;
        }
        if pos.flags & 0x80 != 0 {
            w.style &= !VISIBLE;
        }
        true
    });
    if !done {
        return 0;
    }
    if pos.flags & 4 == 0 {
        state::with(|s| {
            let Some(i) = s.windows.iter().position(|w| w.hwnd == hwnd) else {
                return;
            };
            let parent = s.windows[i].parent;
            if pos.after == hwnd {
                return;
            }
            let w = s.windows.remove(i);
            let at = if pos.after == 1 {
                s.windows
                    .iter()
                    .rposition(|v| v.parent == parent)
                    .map_or(s.windows.len(), |i| i + 1)
            } else if pos.after == 0 || pos.after >= 0xfffffffe {
                s.windows
                    .iter()
                    .position(|v| v.parent == parent)
                    .unwrap_or(s.windows.len())
            } else {
                s.windows
                    .iter()
                    .position(|v| v.hwnd == pos.after && v.parent == parent)
                    .map_or(i.min(s.windows.len()), |i| i + 1)
            };
            s.windows.insert(at, w);
        });
    }
    update(hwnd);
    crate::frame::paint(hwnd);
    let visible = state::with(|s| {
        s.windows
            .iter()
            .find(|w| w.hwnd == hwnd)
            .is_some_and(|w| w.style & VISIBLE != 0)
    });
    if visible && (old.4 & VISIBLE == 0 || pos.flags & (1 | 8) == 0) {
        unsafe {
            crate::paint::InvalidateRect(hwnd, 0, 1);
        }
    }
    if visible != (old.4 & VISIBLE != 0) {
        unsafe {
            SendMessageW(hwnd, 0x18, u32::from(visible), 0);
        }
    }
    unsafe {
        SendMessageW(hwnd, 0x47, 0, (&raw mut pos) as u32);
    }
    1
}
#[unsafe(no_mangle)]
pub extern "system" fn MoveWindow(h: u32, x: i32, y: i32, w: i32, t: i32, repaint: i32) -> i32 {
    SetWindowPos(
        h,
        0,
        x,
        y,
        w,
        t,
        4 | 0x10 | if repaint == 0 { 8 } else { 0 },
    )
}
#[unsafe(no_mangle)]
pub extern "system" fn ShowWindow(hwnd: u32, command: u32) -> i32 {
    let screen = unsafe { [GetSystemMetrics(0) as i32, GetSystemMetrics(1) as i32] };
    let placement = state::with(|s| {
        let index = s.windows.iter().position(|w| w.hwnd == hwnd)?;
        let parent = s.windows[index].parent;
        let extent = if s.windows[index].style & CHILD != 0 {
            s.windows
                .iter()
                .find(|w| w.hwnd == parent)
                .map(|w| {
                    let r = crate::frame::client(s, w);
                    [r[2] - r[0], r[3] - r[1]]
                })
                .unwrap_or(screen)
        } else {
            screen
        };
        let w = &mut s.windows[index];
        let visible = w.style & VISIBLE != 0;
        let mut rect = [w.x, w.y, w.width, w.height];
        let mut resize = w.needs_size && command != 0;
        match command {
            2 | 6 | 7 | 11 => w.style = (w.style & !0x0100_0000) | 0x2000_0000,
            3 => {
                if w.normal_rect.is_none() {
                    w.normal_rect = Some(rect);
                }
                w.style = (w.style & !0x2000_0000) | 0x0100_0000;
                rect = [0, 0, extent[0], extent[1]];
                resize = true;
            }
            1 | 9 => {
                w.style &= !0x2100_0000;
                if let Some(normal) = w.normal_rect.take() {
                    rect = normal;
                    resize = true;
                }
            }
            _ => {}
        }
        Some((visible, rect, resize))
    });
    let Some((old, rect, resize)) = placement else {
        return state::error(1400) as i32;
    };
    SetWindowPos(
        hwnd,
        0,
        rect[0],
        rect[1],
        rect[2],
        rect[3],
        (if resize { 4 } else { 7 }) | if command == 0 { 0x80 } else { 0x40 },
    );
    i32::from(old)
}

#[unsafe(no_mangle)]
pub extern "system" fn GetParent(hwnd: u32) -> u32 {
    state::with(|s| {
        s.windows.iter().find(|w| w.hwnd == hwnd).map_or(0, |w| {
            if w.style & CHILD != 0 {
                w.parent
            } else {
                w.owner
            }
        })
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn IsChild(parent: u32, hwnd: u32) -> i32 {
    state::with(|s| {
        let mut h = hwnd;
        for _ in 0..s.windows.len() {
            let Some(w) = s.windows.iter().find(|w| w.hwnd == h) else {
                return 0;
            };
            h = w.parent;
            if h == 0 {
                return 0;
            };
            if h == parent {
                return 1;
            };
        }
        0
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn SetParent(hwnd: u32, parent: u32) -> u32 {
    if parent == hwnd || parent != 0 && (IsWindow(parent) == 0 || IsChild(hwnd, parent) != 0) {
        return state::error(87);
    };
    let old = state::with(|s| {
        let Some(w) = s.windows.iter_mut().find(|w| w.hwnd == hwnd) else {
            return None;
        };
        let old = w.parent;
        w.parent = parent;
        Some(old)
    });
    let Some(old) = old else {
        return state::error(1400);
    };
    update(hwnd);
    old
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetWindowThreadProcessId(hwnd: u32, pid: *mut u32) -> u32 {
    let thread = state::with(|s| s.windows.iter().find(|w| w.hwnd == hwnd).map(|w| w.thread));
    let Some(thread) = thread else {
        return state::error(1400);
    };
    if !pid.is_null() {
        unsafe {
            pid.write_unaligned(runtime::GetCurrentProcessId());
        }
    }
    thread
}
// Win16 window words occupy two bytes, including the last extra-byte slot.
pub unsafe fn word(hwnd: u32, index: i32, value: Option<u32>) -> u32 {
    if index < 0 {
        return if matches!(index, -6 | -8 | -12) {
            unsafe { long(hwnd, index, value, false) }
        } else {
            state::error(1413)
        };
    }
    state::with(|s| {
        let Some(w) = s.windows.iter_mut().find(|w| w.hwnd == hwnd) else {
            return state::error(1400);
        };
        let Some(slot) = w.extra.get_mut(index as usize..index as usize + 2) else {
            return state::error(1413);
        };
        let old = u16::from_le_bytes([slot[0], slot[1]]) as u32;
        if let Some(v) = value {
            slot.copy_from_slice(&(v as u16).to_le_bytes());
        }
        old
    })
}
unsafe fn long(hwnd: u32, index: i32, value: Option<u32>, wide: bool) -> u32 {
    state::with(|s| {
        let Some(w) = s.windows.iter_mut().find(|w| w.hwnd == hwnd) else {
            return state::error(1400);
        };
        if index >= 0 {
            let i = index as usize;
            if i.checked_add(4).is_none_or(|end| end > w.extra.len()) {
                return state::error(1413);
            };
            let old = u32::from_le_bytes(w.extra[i..i + 4].try_into().unwrap());
            if let Some(v) = value {
                w.extra[i..i + 4].copy_from_slice(&v.to_le_bytes());
            }
            return old;
        }
        if index == -4 {
            let edit = s
                .classes
                .iter()
                .find(|c| c.atom == w.class)
                .is_some_and(|c| c.name == [69, 100, 105, 116]);
            let old = if w.wide != wide && (!crate::controls::builtin(w.proc) || edit) {
                let entry = (w.proc, w.wide);
                let i = if let Some(i) = s.procedures.iter().position(|p| *p == entry) {
                    i
                } else {
                    s.procedures.push(entry);
                    s.procedures.len() - 1
                };
                0xffff0000 | (i as u32 + 1)
            } else {
                crate::controls::variant(w.proc, wide)
            };
            if let Some(v) = value {
                let entry = if v >> 16 == 0xffff {
                    s.procedures
                        .get((v & 0xffff).wrapping_sub(1) as usize)
                        .copied()
                } else {
                    Some((v, wide))
                };
                if let Some((address, encoding)) = entry {
                    w.proc = address;
                    w.wide = encoding;
                } else {
                    return state::error(87);
                }
            }
            return old;
        }
        let slot = match index {
            -6 => &mut w.instance,
            -8 => {
                if w.style & CHILD != 0 {
                    &mut w.parent
                } else {
                    &mut w.owner
                }
            }
            -12 => &mut w.id,
            -16 => &mut w.style,
            -20 => &mut w.ex_style,
            -21 => &mut w.user,
            _ => return state::error(1413),
        };
        let old = if index == -4 {
            crate::controls::variant(*slot, wide)
        } else {
            *slot
        };
        if let Some(v) = value {
            *slot = v;
        }
        old
    })
}
macro_rules! long_api {
    ($get:ident,$set:ident,$wide:expr) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $get(h: u32, i: i32) -> u32 {
            unsafe { long(h, i, None, $wide) }
        }
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $set(h: u32, i: i32, v: u32) -> u32 {
            let old = unsafe { long(h, i, Some(v), $wide) };
            update(h);
            old
        }
    };
}
long_api!(GetWindowLongA, SetWindowLongA, false);
long_api!(GetWindowLongW, SetWindowLongW, true);
#[unsafe(no_mangle)]
pub extern "system" fn GetDlgItem(parent: u32, id: i32) -> u32 {
    if parent == 0 {
        return 0;
    }
    state::with(|s| {
        s.windows
            .iter()
            .find(|w| w.parent == parent && w.id == id as u32)
            .map_or(0, |w| w.hwnd)
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn GetDlgCtrlID(hwnd: u32) -> i32 {
    state::with(|s| {
        s.windows
            .iter()
            .find(|w| w.hwnd == hwnd)
            .map_or(0, |w| w.id as i32)
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn GetWindow(hwnd: u32, relation: u32) -> u32 {
    state::with(|s| {
        let Some(w) = s.windows.iter().find(|w| w.hwnd == hwnd) else {
            return 0;
        };
        if relation == 4 {
            return w.owner;
        };
        if relation == 5 {
            return s
                .windows
                .iter()
                .rev()
                .find(|c| c.parent == hwnd)
                .map_or(0, |c| c.hwnd);
        };
        let siblings: Vec<u32> = s
            .windows
            .iter()
            .rev()
            .filter(|c| c.parent == w.parent)
            .map(|c| c.hwnd)
            .collect();
        let at = siblings.iter().position(|&h| h == hwnd).unwrap();
        match relation {
            0 => siblings[0],
            1 => *siblings.last().unwrap(),
            2 => siblings.get(at + 1).copied().unwrap_or(0),
            3 => at.checked_sub(1).map_or(0, |i| siblings[i]),
            _ => 0,
        }
    })
}
type EnumProc = unsafe extern "system" fn(u32, u32) -> i32;
#[unsafe(no_mangle)]
pub unsafe extern "system" fn EnumWindows(proc: EnumProc, data: u32) -> i32 {
    let handles = state::with(|s| {
        s.windows
            .iter()
            .rev()
            .filter(|w| w.parent == 0)
            .map(|w| w.hwnd)
            .collect::<Vec<_>>()
    });
    for h in handles {
        if IsWindow(h) != 0 && unsafe { proc(h, data) } == 0 {
            return 0;
        }
    }
    1
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn EnumChildWindows(parent: u32, proc: EnumProc, data: u32) -> i32 {
    let handles = state::with(|s| s.windows.iter().map(|w| w.hwnd).collect::<Vec<_>>());
    for h in handles {
        if IsChild(parent, h) != 0 && unsafe { proc(h, data) } == 0 {
            return 0;
        }
    }
    1
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetClassNameW(hwnd: u32, out: u32, count: i32) -> u32 {
    unsafe { class_name(hwnd, out, count, true) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetClassNameA(hwnd: u32, out: u32, count: i32) -> u32 {
    unsafe { class_name(hwnd, out, count, false) }
}
unsafe fn class_name(hwnd: u32, out: u32, count: i32, wide: bool) -> u32 {
    let name = state::with(|s| {
        s.windows
            .iter()
            .find(|w| w.hwnd == hwnd)
            .and_then(|w| s.classes.iter().find(|c| c.atom == w.class))
            .map(|c| c.name.clone())
    });
    let Some(name) = name else {
        return state::error(1400);
    };
    unsafe { text::write(out, count, &name, wide) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DefWindowProcW(h: u32, m: u32, w: u32, l: u32) -> i32 {
    unsafe { default_proc(h, m, w, l, true) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DefWindowProcA(h: u32, m: u32, w: u32, l: u32) -> i32 {
    unsafe { default_proc(h, m, w, l, false) }
}
unsafe fn default_proc(h: u32, m: u32, w: u32, l: u32, wide: bool) -> i32 {
    if let Some(result) = crate::frame::message(h, m, w, l) {
        return result;
    }
    match m {
        0x14 => {
            let brush = state::with(|s| {
                s.windows
                    .iter()
                    .find(|v| v.hwnd == h)
                    .and_then(|v| s.classes.iter().find(|c| c.atom == v.class))
                    .map_or(0, |c| c.background)
            });
            if brush == 0 {
                return 0;
            }
            let mut rect = [0i32; 4];
            unsafe extern "system" {
                fn FillRect(dc: u32, rect: *const [i32; 4], brush: u32) -> i32;
            }
            unsafe {
                GetClientRect(h, rect.as_mut_ptr().cast());
                FillRect(w, &rect, brush)
            }
        }
        0xf => {
            let mut ps = [0u32; 16];
            unsafe {
                crate::paint::BeginPaint(h, ps.as_mut_ptr() as u32);
                crate::paint::EndPaint(h, ps.as_ptr() as u32);
            }
            0
        }
        0x81 => 1,
        0x10 => {
            DestroyWindow(h);
            0
        }
        0x0c => {
            let title = unsafe { text::read(l, wide) };
            state::with(|s| {
                let Some(w) = s.windows.iter_mut().find(|w| w.hwnd == h) else {
                    return 0;
                };
                w.title = title;
                1
            });
            crate::frame::paint(h);
            1
        }
        0x0d | 0x0e => {
            let title = state::with(|s| {
                s.windows
                    .iter()
                    .find(|w| w.hwnd == h)
                    .map(|w| w.title.clone())
            });
            let Some(title) = title else { return 0 };
            if m == 0x0d {
                (unsafe { text::write(l, w as i32, &title, wide) }) as i32
            } else if wide {
                title.len() as i32
            } else {
                text::ansi(&title).len() as i32
            }
        }
        0x47 => {
            let pos = unsafe { (l as *const WindowPos).read_unaligned() };
            if pos.flags & 2 == 0 {
                unsafe {
                    SendMessageW(
                        h,
                        3,
                        0,
                        (pos.x as u32 & 0xffff) | ((pos.y as u32 & 0xffff) << 16),
                    );
                }
            }
            if pos.flags & 1 == 0 {
                unsafe {
                    SendMessageW(
                        h,
                        5,
                        state::with(|s| {
                            s.windows.iter().find(|w| w.hwnd == h).map_or(0, |w| {
                                if w.style & 0x2000_0000 != 0 {
                                    1
                                } else if w.style & 0x0100_0000 != 0 {
                                    2
                                } else {
                                    0
                                }
                            })
                        }),
                        state::with(|s| {
                            s.windows.iter().find(|w| w.hwnd == h).map_or(0, |w| {
                                let r = crate::frame::client(s, w);
                                crate::frame::pack(r[2] - r[0], r[3] - r[1])
                            })
                        }),
                    );
                }
            }
            0
        }
        _ => 0,
    }
}
macro_rules! text_api {
    ($get:ident,$length:ident,$set:ident,$send:ident) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $get(h: u32, p: u32, n: i32) -> i32 {
            unsafe { crate::$send(h, 0x0d, n as u32, p) }
        }
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $length(h: u32) -> i32 {
            unsafe { crate::$send(h, 0x0e, 0, 0) }
        }
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $set(h: u32, p: u32) -> i32 {
            unsafe { crate::$send(h, 0x0c, 0, p) }
        }
    };
}
text_api!(
    GetWindowTextA,
    GetWindowTextLengthA,
    SetWindowTextA,
    SendMessageA
);
text_api!(
    GetWindowTextW,
    GetWindowTextLengthW,
    SetWindowTextW,
    SendMessageW
);

fn origin(hwnd: u32) -> Option<(i32, i32)> {
    state::with(|s| crate::frame::origin(s, hwnd, true))
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetClientRect(hwnd: u32, out: *mut crate::rect::Rect) -> i32 {
    if out.is_null() {
        return state::error(87) as i32;
    }
    let size = state::with(|s| {
        s.windows.iter().find(|w| w.hwnd == hwnd).map(|w| {
            let r = crate::frame::client(s, w);
            (r[2] - r[0], r[3] - r[1])
        })
    });
    let Some((width, height)) = size else {
        return state::error(1400) as i32;
    };
    unsafe { crate::rect::SetRect(out, 0, 0, width, height) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetWindowRect(hwnd: u32, out: *mut crate::rect::Rect) -> i32 {
    if out.is_null() {
        return 0;
    }
    let rect = state::with(|s| {
        let w = s.windows.iter().find(|w| w.hwnd == hwnd)?;
        let (x, y) = crate::frame::origin(s, hwnd, false)?;
        Some((x, y, w.width, w.height))
    });
    let Some((x, y, width, height)) = rect else {
        return state::error(1400) as i32;
    };
    unsafe { crate::rect::SetRect(out, x, y, x + width, y + height) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn MapWindowPoints(
    from: u32,
    to: u32,
    points: *mut crate::rect::Point,
    count: u32,
) -> u32 {
    let (Some(a), Some(b)) = (origin(from), origin(to)) else {
        return state::error(1400);
    };
    if count != 0 && points.is_null() {
        return state::error(87);
    }
    let (dx, dy) = (a.0.wrapping_sub(b.0), a.1.wrapping_sub(b.1));
    for i in 0..count as usize {
        let p = unsafe { points.add(i) };
        let mut value = unsafe { p.read_unaligned() };
        value.x = value.x.wrapping_add(dx);
        value.y = value.y.wrapping_add(dy);
        unsafe {
            p.write_unaligned(value);
        }
    }
    (dx as u32 & 0xffff) | ((dy as u32 & 0xffff) << 16)
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn ClientToScreen(hwnd: u32, point: *mut crate::rect::Point) -> i32 {
    if point.is_null() {
        return state::error(87) as i32;
    }
    if origin(hwnd).is_none() {
        return state::error(1400) as i32;
    }
    unsafe {
        MapWindowPoints(hwnd, 0, point, 1);
    }
    1
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn ScreenToClient(hwnd: u32, point: *mut crate::rect::Point) -> i32 {
    if point.is_null() {
        return state::error(87) as i32;
    }
    if origin(hwnd).is_none() {
        return state::error(1400) as i32;
    }
    unsafe {
        MapWindowPoints(0, hwnd, point, 1);
    }
    1
}

#[unsafe(no_mangle)]
pub extern "system" fn IsIconic(hwnd: u32) -> i32 {
    state::with(|s| {
        i32::from(
            s.windows
                .iter()
                .any(|w| w.hwnd == hwnd && w.style & 0x20000000 != 0),
        )
    })
}
