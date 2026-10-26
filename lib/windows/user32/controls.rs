//! Built-in class procedures share window storage, text, painting, and ordinary
//! callback delivery. Controls never call applications with USER state locked.
use crate::{state, text, window};
use alloc::{vec, vec::Vec};
#[derive(Default)]
pub struct Control {
    check: u32,
    pressed: bool,
    start: usize,
    end: usize,
    items: Vec<Vec<u16>>,
    selected: Option<usize>,
    image: u32,
    font: u32,
    minimum: i32,
    maximum: i32,
    position: i32,
}
pub fn ensure() {
    state::with(|s| {
        if s.builtins {
            return;
        }
        s.builtins = true;
        for (i, name) in [
            "Button",
            "Edit",
            "Static",
            "ListBox",
            "ComboBox",
            "ComboLBox",
            "ScrollBar",
            "MDIClient",
            "#32768",
            "#32769",
            "#32770",
            "#32771",
            "#32772",
        ]
        .iter()
        .enumerate()
        {
            let atom = if i >= 8 {
                0x8000 + (i - 8) as u32
            } else {
                0xc000 + i as u32
            };
            s.classes.push(state::Class {
                global: true,
                atom,
                name: name.encode_utf16().collect(),
                style: [
                    0x8b, 0x88, 0x88, 0x88, 0x8b, 0x808, 0x8b, 0, 0x20808, 8, 0x808, 0x803, 0,
                ][i],
                proc: proc_a as *const () as u32,
                extra: Vec::new(),
                window_extra: if *name == "#32770" { 30 } else { 8 },
                instance: unsafe { crate::runtime::GetModuleHandleA(c"USER32".as_ptr() as u32) },
                icon: 0,
                cursor: 0,
                background: 0,
                menu: 0,
                small_icon: 0,
                wide: false,
                live: 0,
            });
        }
        s.next_atom = s.next_atom.max(0xc100);
    });
}
pub fn builtin(address: u32) -> bool {
    [
        proc_a as *const () as u32,
        proc_w as *const () as u32,
        window::DefWindowProcA as *const () as u32,
        window::DefWindowProcW as *const () as u32,
    ]
    .contains(&address)
}
pub fn variant(address: u32, wide: bool) -> u32 {
    if address == proc_a as *const () as u32 || address == proc_w as *const () as u32 {
        if wide {
            proc_w as *const () as u32
        } else {
            proc_a as *const () as u32
        }
    } else if address == window::DefWindowProcA as *const () as u32
        || address == window::DefWindowProcW as *const () as u32
    {
        if wide {
            window::DefWindowProcW as *const () as u32
        } else {
            window::DefWindowProcA as *const () as u32
        }
    } else {
        address
    }
}
unsafe extern "system" {
    fn FillRect(dc: u32, rect: *const [i32; 4], brush: u32) -> i32;
    fn TextOutW(dc: u32, x: i32, y: i32, text: *const u16, count: i32) -> i32;
    fn GetStockObject(index: u32) -> u32;
    fn SetBkMode(dc: u32, mode: u32) -> i32;
}
unsafe fn notify(hwnd: u32, code: u32) {
    let target = state::with(|s| {
        s.windows
            .iter()
            .find(|w| w.hwnd == hwnd)
            .map(|w| (w.parent, w.id))
    });
    if let Some((parent, id)) = target.filter(|t| t.0 != 0) {
        unsafe {
            crate::SendMessageW(parent, 0x111, (code << 16) | (id & 0xffff), hwnd);
        }
    }
}
unsafe fn paint(hwnd: u32, kind: &[u16], style: u32) -> i32 {
    let mut ps = [0u32; 16];
    let dc = unsafe { crate::paint::BeginPaint(hwnd, ps.as_mut_ptr() as u32) };
    let info = state::with(|s| {
        s.windows.iter().find(|w| w.hwnd == hwnd).map(|w| {
            (
                w.parent,
                w.width,
                w.height,
                w.title.clone(),
                w.control.image,
            )
        })
    });
    if let Some((parent, width, height, title, image)) = info {
        let static_control = kind == [83, 116, 97, 116, 105, 99];
        let bitmap = static_control && matches!(style & 0x1f, 3 | 14);
        let etched = static_control && matches!(style & 0x1f, 16 | 17);
        if (!bitmap || image != 0) && (!etched || ps[1] != 0) {
            let brush = if parent != 0 {
                unsafe {
                    crate::SendMessageW(
                        parent,
                        if static_control { 0x138 } else { 0x135 },
                        dc,
                        hwnd,
                    ) as u32
                }
            } else {
                0
            };
            let brush = if brush == 0 {
                unsafe { GetStockObject(0) }
            } else {
                brush
            };
            let rect = [0, 0, width, height];
            unsafe {
                FillRect(dc, &rect, brush);
                SetBkMode(dc, 1);
            }
            if !bitmap && !etched && !title.is_empty() {
                unsafe {
                    TextOutW(dc, 0, 0, title.as_ptr(), title.len() as i32);
                }
            }
        }
    }
    if kind == [83, 116, 97, 116, 105, 99] && matches!(style & 0x1f, 16 | 17) {
        let vertical = style & 0x1f == 17;
        let rect = if vertical {
            [0, 0, 1, ps[5] as i32]
        } else {
            [0, 0, ps[4] as i32, 1]
        };
        unsafe {
            FillRect(dc, &rect, GetStockObject(3));
        }
        let rect = if vertical {
            [1, 0, 2, ps[5] as i32]
        } else {
            [0, 1, ps[4] as i32, 2]
        };
        unsafe {
            FillRect(dc, &rect, GetStockObject(0));
        }
    }
    unsafe {
        crate::paint::EndPaint(hwnd, ps.as_ptr() as u32);
    }
    0
}
unsafe fn control(hwnd: u32, message: u32, wparam: u32, lparam: u32, wide: bool) -> i32 {
    let info = state::with(|s| {
        s.windows.iter().find(|w| w.hwnd == hwnd).and_then(|w| {
            s.classes
                .iter()
                .find(|c| c.atom == w.class)
                .map(|c| (c.name.clone(), w.style))
        })
    });
    let Some((kind, style)) = info else {
        return 0;
    };
    let button = kind == [66, 117, 116, 116, 111, 110];
    let edit = kind == [69, 100, 105, 116];
    let list = kind == [76, 105, 115, 116, 66, 111, 120]
        || kind == [67, 111, 109, 98, 111, 76, 66, 111, 120];
    let combo = kind == [67, 111, 109, 98, 111, 66, 111, 120];
    let scroll = kind == [83, 99, 114, 111, 108, 108, 66, 97, 114];
    if kind == [35, 51, 50, 55, 55, 48] {
        return unsafe {
            if wide {
                crate::dialog::DefDlgProcW(hwnd, message, wparam, lparam)
            } else {
                crate::dialog::DefDlgProcA(hwnd, message, wparam, lparam)
            }
        };
    }
    if edit && matches!(message, 7 | 8) {
        unsafe {
            notify(hwnd, if message == 7 { 0x100 } else { 0x200 });
        }
    }
    if message == 0xf {
        return unsafe { paint(hwnd, &kind, style) };
    }
    if button && (message == 0xf5 || message == 0x202) {
        state::with(|s| {
            if let Some(w) = s.windows.iter_mut().find(|w| w.hwnd == hwnd) {
                match style & 15 {
                    3 => w.control.check ^= 1,
                    6 => w.control.check = (w.control.check + 1) % 3,
                    9 => w.control.check = 1,
                    _ => {}
                }
                w.control.pressed = false;
            }
        });
        unsafe {
            notify(hwnd, 0);
            crate::paint::InvalidateRect(hwnd, 0, 0);
        }
        return 0;
    }
    if message == 0xc {
        let value = unsafe {
            if wide {
                window::DefWindowProcW(hwnd, message, wparam, lparam)
            } else {
                window::DefWindowProcA(hwnd, message, wparam, lparam)
            }
        };
        unsafe {
            crate::paint::InvalidateRect(hwnd, 0, 0);
        }
        return value;
    }
    if message == 0x30 || message == 0x31 {
        return state::with(|s| {
            let w = s.windows.iter_mut().find(|w| w.hwnd == hwnd).unwrap();
            if message == 0x30 {
                w.control.font = wparam;
                0
            } else {
                w.control.font as i32
            }
        });
    }
    if message == 0x170 || message == 0x172 || message == 0x171 || message == 0x173 {
        return state::with(|s| {
            let w = s.windows.iter_mut().find(|w| w.hwnd == hwnd).unwrap();
            let old = w.control.image;
            if message == 0x170 {
                w.control.image = wparam;
            }
            if message == 0x172 {
                w.control.image = lparam;
            }
            old as i32
        });
    }
    if button && (0xf0..=0xf4).contains(&message) {
        return state::with(|s| {
            let w = s.windows.iter_mut().find(|w| w.hwnd == hwnd).unwrap();
            match message {
                0xf0 => w.control.check as i32,
                0xf1 => {
                    w.control.check = wparam.min(2);
                    if matches!(w.style & 15, 4 | 9) {
                        if wparam == 0 {
                            w.style &= !0x10000;
                        } else {
                            w.style |= 0x10000;
                        }
                    }
                    0
                }
                0xf2 => (w.control.check | if w.control.pressed { 4 } else { 0 }) as i32,
                0xf3 => {
                    w.control.pressed = wparam != 0;
                    0
                }
                0xf4 => {
                    w.style = (w.style & !0xf) | (wparam & 0xf);
                    0
                }
                _ => 0,
            }
        });
    }
    if edit && matches!(message, 0xb0 | 0xb1 | 0xc2 | 0x102) {
        let insertion = if message == 0xc2 {
            unsafe { text::read(lparam, wide) }
        } else if message == 0x102 && wparam >= 32 {
            vec![wparam as u16]
        } else {
            Vec::new()
        };
        let changed = message == 0xc2 || message == 0x102;
        let result = state::with(|s| {
            let w = s.windows.iter_mut().find(|w| w.hwnd == hwnd).unwrap();
            let c = &mut w.control;
            match message {
                0xb0 => {
                    unsafe {
                        if wparam != 0 {
                            (wparam as *mut u32).write_unaligned(c.start as u32);
                        }
                        if lparam != 0 {
                            (lparam as *mut u32).write_unaligned(c.end as u32);
                        }
                    }
                    ((c.end as u32 & 0xffff) << 16 | c.start as u32 & 0xffff) as i32
                }
                0xb1 => {
                    if wparam == u32::MAX {
                        c.start = c.end;
                    } else {
                        c.start = (wparam as usize).min(w.title.len());
                        c.end = (lparam as usize).min(w.title.len());
                    }
                    0
                }
                _ => {
                    let start = c.start.min(c.end).min(w.title.len());
                    let end = c.start.max(c.end).min(w.title.len());
                    let start = if message == 0x102 && wparam == 8 && start == end {
                        start.saturating_sub(1)
                    } else {
                        start
                    };
                    w.title.splice(start..end, insertion.iter().copied());
                    c.start = start + insertion.len();
                    c.end = c.start;
                    1
                }
            }
        });
        if changed {
            unsafe {
                notify(hwnd, 0x300);
                crate::paint::InvalidateRect(hwnd, 0, 0);
            }
        }
        return result;
    }
    if list || combo {
        let normalized = if combo {
            match message {
                0x143 => 0x180,
                0x14a => 0x181,
                0x144 => 0x182,
                0x14b => 0x184,
                0x146 => 0x188,
                0x147 => 0x187,
                0x14e => 0x186,
                0x148 => 0x189,
                0x149 => 0x18a,
                _ => 0,
            }
        } else {
            message
        };
        if matches!(
            normalized,
            0x180 | 0x181 | 0x182 | 0x184 | 0x186 | 0x187 | 0x188 | 0x189 | 0x18a
        ) {
            let string = if normalized == 0x180 || normalized == 0x181 {
                unsafe { text::read(lparam, wide) }
            } else {
                Vec::new()
            };
            return state::with(|s| {
                let w = s.windows.iter_mut().find(|w| w.hwnd == hwnd).unwrap();
                let c = &mut w.control;
                match normalized {
                    0x180 | 0x181 => {
                        let at = if normalized == 0x181 && wparam as usize <= c.items.len() {
                            wparam as usize
                        } else {
                            c.items.len()
                        };
                        c.items.insert(at, string);
                        at as i32
                    }
                    0x182 => {
                        if wparam as usize >= c.items.len() {
                            return -1;
                        }
                        c.items.remove(wparam as usize);
                        c.items.len() as i32
                    }
                    0x184 => {
                        c.items.clear();
                        c.selected = None;
                        0
                    }
                    0x186 => {
                        c.selected = if (wparam as usize) < c.items.len() {
                            Some(wparam as usize)
                        } else {
                            None
                        };
                        c.selected.map_or(-1, |i| i as i32)
                    }
                    0x187 => c.selected.map_or(-1, |i| i as i32),
                    0x188 => c.items.len() as i32,
                    0x189 | 0x18a => {
                        let Some(value) = c.items.get(wparam as usize) else {
                            return -1;
                        };
                        if normalized == 0x18a {
                            if wide {
                                value.len() as i32
                            } else {
                                text::ansi(value).len() as i32
                            }
                        } else {
                            unsafe { text::write(lparam, i32::MAX, value, wide) as i32 }
                        }
                    }
                    _ => -1,
                }
            });
        }
    }
    if scroll && matches!(message, 0xe0..=0xe3) {
        return state::with(|s| {
            let w = s.windows.iter_mut().find(|w| w.hwnd == hwnd).unwrap();
            let c = &mut w.control;
            match message {
                0xe0 => {
                    let old = c.position;
                    c.position = (wparam as i32).clamp(c.minimum, c.maximum.max(c.minimum));
                    old
                }
                0xe1 => c.position,
                0xe2 => {
                    c.minimum = wparam as i32;
                    c.maximum = lparam as i32;
                    0
                }
                _ => {
                    unsafe {
                        if wparam != 0 {
                            (wparam as *mut i32).write_unaligned(c.minimum);
                        }
                        if lparam != 0 {
                            (lparam as *mut i32).write_unaligned(c.maximum);
                        }
                    }
                    0
                }
            }
        });
    }
    if message == 0x87 {
        return if edit {
            0x89
        } else if button {
            0x2000
        } else {
            0
        };
    }
    unsafe {
        if wide {
            window::DefWindowProcW(hwnd, message, wparam, lparam)
        } else {
            window::DefWindowProcA(hwnd, message, wparam, lparam)
        }
    }
}
unsafe extern "system" fn proc_a(h: u32, m: u32, w: u32, l: u32) -> i32 {
    unsafe { control(h, m, w, l, false) }
}
unsafe extern "system" fn proc_w(h: u32, m: u32, w: u32, l: u32) -> i32 {
    unsafe { control(h, m, w, l, true) }
}
