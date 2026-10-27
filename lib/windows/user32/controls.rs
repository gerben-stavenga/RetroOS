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
    edit_child: u32,
    pub(crate) scroll: [crate::scrollbar::Info; 3],
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
    fn GetSysColorBrush(index: u32) -> u32;
    fn SetBkMode(dc: u32, mode: u32) -> i32;
    fn SetTextColor(dc: u32, color: u32) -> u32;
    fn SetBkColor(dc: u32, color: u32) -> u32;
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
                crate::frame::client(s, w)[2] - crate::frame::client(s, w)[0],
                crate::frame::client(s, w)[3] - crate::frame::client(s, w)[1],
                w.title.clone(),
                w.control.image,
                w.control.check,
                w.control.items.clone(),
                w.control.selected,
            )
        })
    });
    if let Some((parent, width, height, title, image, check, items, selected)) = info {
        let list = kind == [76, 105, 115, 116, 66, 111, 120]
            || kind == [67, 111, 109, 98, 111, 76, 66, 111, 120];
        let static_control = kind == [83, 116, 97, 116, 105, 99];
        let button = kind == [66, 117, 116, 116, 111, 110];
        let edit = kind == [69, 100, 105, 116];
        let bitmap = static_control && matches!(style & 0x1f, 3 | 14);
        let etched = static_control && matches!(style & 0x1f, 16 | 17);
        if (!bitmap || image != 0) && (!etched || ps[1] != 0) {
            let brush = if parent != 0 {
                unsafe {
                    crate::SendMessageW(
                        parent,
                        if static_control {
                            0x138
                        } else if list {
                            0x134
                        } else if edit {
                            0x133
                        } else {
                            0x135
                        },
                        dc,
                        hwnd,
                    ) as u32
                }
            } else {
                0
            };
            let brush = if brush == 0 {
                unsafe { GetStockObject(if edit { 0 } else { 1 }) }
            } else {
                brush
            };
            if kind == [83, 99, 114, 111, 108, 108, 66, 97, 114] {
                crate::scrollbar::draw(dc, hwnd, width, height, style);
                unsafe {
                    crate::paint::EndPaint(hwnd, ps.as_ptr() as u32);
                }
                return 0;
            }
            let group = button && style & 15 == 7;
            let rect = [0, 0, width, height];
            unsafe {
                if group {
                    // A group box is a frame, not an opaque panel. Its interior
                    // can contain sibling controls painted before it.
                    for edge in [
                        [0, 8, width, 9],
                        [0, 8, 1, height],
                        [0, height - 1, width, height],
                        [width - 1, 8, width, height],
                    ] {
                        FillRect(dc, &edge, GetStockObject(3));
                    }
                    FillRect(
                        dc,
                        &[
                            6,
                            0,
                            (title.len() as i32 * 8 + 10).min(width),
                            16.min(height),
                        ],
                        brush,
                    );
                } else {
                    FillRect(dc, &rect, brush);
                }
                SetBkMode(dc, 1);
            }
            if static_control && style & 0x1f == 3 && image != 0 {
                unsafe {
                    crate::resource::DrawIcon(dc, 0, 0, image);
                }
            }
            if button && style & 15 <= 1 {
                crate::frame::bevel(dc, [0, 0, width, height]);
            }
            let choice = button && matches!(style & 15, 2..=6 | 9);
            if choice {
                let top = ((height - 13) / 2).max(0);
                let radio = matches!(style & 15, 4 | 9);
                // Scanline drawing uses the shared fill primitive, so clipping
                // and both Win16/Win32 device contexts remain identical.
                for y in 0i32..13 {
                    let inset = if radio {
                        match y {
                            0 | 12 => 4,
                            1 | 11 => 2,
                            2 | 10 => 1,
                            _ => 0,
                        }
                    } else {
                        0
                    };
                    unsafe {
                        FillRect(
                            dc,
                            &[inset, top + y, 13 - inset, top + y + 1],
                            GetStockObject(4),
                        );
                        if y > 0 && y < 12 {
                            FillRect(
                                dc,
                                &[inset + 1, top + y, 12 - inset, top + y + 1],
                                GetStockObject(0),
                            );
                        }
                    }
                }
                if check != 0 {
                    if radio {
                        for y in 4i32..9 {
                            let inset = if y == 4 || y == 8 { 5 } else { 4 };
                            unsafe {
                                FillRect(
                                    dc,
                                    &[inset, top + y, 13 - inset, top + y + 1],
                                    GetStockObject(4),
                                );
                            }
                        }
                    } else {
                        for y in 3i32..10 {
                            unsafe {
                                FillRect(dc, &[y, top + y, y + 1, top + y + 1], GetStockObject(4));
                                FillRect(
                                    dc,
                                    &[12 - y, top + y, 13 - y, top + y + 1],
                                    GetStockObject(4),
                                );
                            }
                        }
                    }
                }
            }
            if list {
                for (i, item) in items
                    .iter()
                    .enumerate()
                    .take(((height + 15) / 16).max(0) as usize)
                {
                    let y = i as i32 * 16;
                    let active = selected == Some(i);
                    unsafe {
                        FillRect(
                            dc,
                            &[0, y, width, (y + 16).min(height)],
                            if active {
                                GetSysColorBrush(13)
                            } else {
                                GetStockObject(0)
                            },
                        );
                        let old_text = SetTextColor(dc, if active { 0xffffff } else { 0 });
                        let old_back = SetBkColor(dc, if active { 0x800000 } else { 0xffffff });
                        TextOutW(dc, 2, y, item.as_ptr(), item.len() as i32);
                        SetTextColor(dc, old_text);
                        SetBkColor(dc, old_back);
                    }
                }
            }
            if !list && !bitmap && !etched && !title.is_empty() {
                let mut label = Vec::new();
                let mut i = 0;
                while i < title.len() {
                    if (button || static_control && style & 0x80 == 0) && title[i] == 38 {
                        i += 1;
                        if i == title.len() {
                            break;
                        }
                    }
                    label.push(title[i]);
                    i += 1;
                }
                let (x, y) = if group {
                    (8, 0)
                } else if choice {
                    (17, (height - 16).max(0) / 2)
                } else if button && style & 15 <= 1 {
                    (
                        (width - label.len() as i32 * 8).max(0) / 2,
                        (height - 16).max(0) / 2,
                    )
                } else {
                    (0, 0)
                };
                unsafe {
                    if static_control && matches!(style & 0x1f,0..=2|12) {
                        let alignment=match style & 0x1f {1=>1,2=>2,_=>0};
                        let flags=0x800|alignment|if style & 0x1f==12 {0}else{0x10};
                        crate::drawing::DrawTextW(dc,label.as_ptr() as u32,label.len() as i32,&mut [0,0,width,height],flags);
                    } else {
                        TextOutW(dc, x, y, label.as_ptr(), label.len() as i32);
                    }
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
    if combo {
        if message == 1 && matches!(style & 3, 1 | 2) {
            let cs = unsafe { &*(lparam as *const crate::CreateStruct) };
            let child = unsafe {
                crate::CreateWindowExW(
                    0, [69u16,100,105,116,0].as_ptr() as u32, 0,
                    0x50000080, 2, 2, (cs.width-22).max(1), 18,
                    hwnd, 1001, cs.instance, 0,
                )
            };
            if child == 0 { return -1; }
            state::with(|s| {
                if let Some(w)=s.windows.iter_mut().find(|w|w.hwnd==hwnd) {
                    w.control.edit_child=child;
                }
            });
        }
        let child=state::with(|s|s.windows.iter().find(|w|w.hwnd==hwnd).map_or(0,|w|w.control.edit_child));
        if child != 0 {
            if matches!(message,0xc|0xd|0xe|0x30|0x31) {
                return unsafe { if wide {crate::SendMessageW(child,message,wparam,lparam)} else {crate::SendMessageA(child,message,wparam,lparam)} };
            }
            if message==7 { unsafe {crate::input::SetFocus(child);} return 0; }
            if message==0x111 && lparam==child {
                let code=match wparam>>16 {0x300=>5,0x400=>6,0x100=>3,0x200=>4,_=>0};
                if code!=0 {unsafe {notify(hwnd,code);}}
                return 0;
            }
        }
    }
    let scroll = kind == [83, 99, 114, 111, 108, 108, 66, 97, 114];
    let icon_control = kind == [83, 116, 97, 116, 105, 99] && style & 0x1f == 3;
    if icon_control && (message == 0x81 || message == 0xc) {
        let (instance, name) = if message == 0x81 {
            let cs = unsafe { &*(lparam as *const crate::CreateStruct) };
            (cs.instance, cs.title)
        } else {
            (unsafe { window::GetWindowLongA(hwnd, -6) }, lparam)
        };
        let image = if name == 0 {
            0
        } else {
            unsafe {
                if wide {
                    crate::resource::LoadIconW(instance, name)
                } else {
                    crate::resource::LoadIconA(instance, name)
                }
            }
        };
        state::with(|s| {
            if let Some(w) = s.windows.iter_mut().find(|w| w.hwnd == hwnd) {
                w.control.image = image;
            }
        });
        if message == 0xc {
            unsafe {
                crate::paint::InvalidateRect(hwnd, 0, 1);
            }
        }
        return 1;
    }
    if kind == [35, 51, 50, 55, 55, 48] {
        return unsafe {
            if wide {
                crate::dialog::DefDlgProcW(hwnd, message, wparam, lparam)
            } else {
                crate::dialog::DefDlgProcA(hwnd, message, wparam, lparam)
            }
        };
    }
    if list && matches!(message, 0x201 | 0x100) {
        let changed = state::with(|s| {
            let w = s.windows.iter_mut().find(|w| w.hwnd == hwnd).unwrap();
            let c = &mut w.control;
            let index = if message == 0x201 {
                ((lparam >> 16) as u16 as i16 as i32 / 16).max(0) as usize
            } else {
                match wparam {
                    0x26 => c.selected.unwrap_or(0).saturating_sub(1),
                    0x28 => c
                        .selected
                        .map_or(0, |v| v + 1)
                        .min(c.items.len().saturating_sub(1)),
                    _ => return false,
                }
            };
            if index >= c.items.len() || c.selected == Some(index) {
                return false;
            }
            c.selected = Some(index);
            true
        });
        unsafe {
            crate::input::SetFocus(hwnd);
            if changed {
                crate::paint::InvalidateRect(hwnd, 0, 0);
                if style & 1 != 0 {
                    notify(hwnd, 1);
                }
            }
        }
        return 0;
    }
    if (edit || button) && message == 0x201 {
        unsafe {
            crate::input::SetFocus(hwnd);
        }
    }
    if edit && message == 0x201 {
        let x = (lparam as u16 as i16) as i32;
        state::with(|s| {
            if let Some(w) = s.windows.iter_mut().find(|w| w.hwnd == hwnd) {
                let at = (x.max(0) as usize / 8).min(w.title.len());
                w.control.start = at;
                w.control.end = at;
            }
        });
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
        if style & 15 == 9 {
            let changed = state::with(|s| {
                let Some(parent) = s.windows.iter().find(|w| w.hwnd == hwnd).map(|w| w.parent)
                else {
                    return Vec::new();
                };
                let siblings: Vec<_> = s
                    .windows
                    .iter()
                    .enumerate()
                    .filter(|(_, w)| w.parent == parent)
                    .map(|(i, w)| (i, w.hwnd, w.style))
                    .collect();
                let Some(at) = siblings.iter().position(|v| v.1 == hwnd) else {
                    return Vec::new();
                };
                let first = (0..=at)
                    .rev()
                    .find(|&i| siblings[i].2 & 0x20000 != 0)
                    .unwrap_or(0);
                let end = (at + 1..siblings.len())
                    .find(|&i| siblings[i].2 & 0x20000 != 0)
                    .unwrap_or(siblings.len());
                let mut changed = Vec::new();
                for &(i, h, style) in &siblings[first..end] {
                    if matches!(style & 15, 4 | 9) {
                        s.windows[i].control.check = u32::from(h == hwnd);
                        changed.push(h);
                    }
                }
                changed
            });
            for h in changed {
                unsafe {
                    crate::paint::InvalidateRect(h, 0, 0);
                }
            }
        }
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
        let old = state::with(|s| {
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
        if matches!(message, 0x170 | 0x172) {
            unsafe {
                crate::paint::InvalidateRect(hwnd, 0, 1);
            }
        }
        return old;
    }
    if button && (0xf0..=0xf4).contains(&message) {
        let result = state::with(|s| {
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
        if matches!(message, 0xf1 | 0xf3 | 0xf4) {
            unsafe {
                crate::paint::InvalidateRect(hwnd, 0, 0);
            }
        }
        return result;
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
                0x146 => 0x18b,
                0x147 => 0x188,
                0x14e => 0x186,
                0x148 => 0x189,
                0x149 => 0x18a,
                0x14c => 0x18f,
                0x14d => 0x18c,
                0x158 => 0x1a2,
                _ => 0,
            }
        } else {
            message
        };
        if matches!(
            normalized,
            0x180 | 0x181 | 0x182 | 0x184 | 0x186 | 0x187 | 0x188 | 0x18b | 0x189 | 0x18a | 0x18c | 0x18f | 0x1a2
        ) {
            let string = if matches!(normalized,0x180|0x181|0x18c|0x18f|0x1a2) {
                unsafe { text::read(lparam, wide) }
            } else {
                Vec::new()
            };
            let result = state::with(|s| {
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
                    0x18c | 0x18f | 0x1a2 => {
                        let count=c.items.len();
                        if count==0 {return -1;}
                        let start=if wparam==u32::MAX {0}else{(wparam as usize+1)%count};
                        let found=(0..count).map(|step|(start+step)%count).find(|&i| {
                            let item=&c.items[i];
                            if normalized==0x1a2 {text::same(item,&string)}
                            else {item.len()>=string.len() && text::same(&item[..string.len()],&string)}
                        });
                        if normalized==0x18c && found.is_some() {c.selected=found;}
                        found.map_or(-1,|i|i as i32)
                    }
                    0x187 => i32::from(c.selected == Some(wparam as usize)),
                    0x188 => c.selected.map_or(-1, |i| i as i32),
                    0x18b => c.items.len() as i32,
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
            if combo && (matches!(normalized,0x184|0x186) || normalized==0x18c && result>=0) {
                let (child,mut value)=state::with(|s| {
                    let w=s.windows.iter_mut().find(|w|w.hwnd==hwnd).unwrap();
                    let value=w.control.selected.and_then(|i|w.control.items.get(i)).cloned().unwrap_or_default();
                    w.title=value.clone();
                    (w.control.edit_child,value)
                });
                if child!=0 {
                    value.push(0);
                    unsafe {crate::SendMessageW(child,0xc,0,value.as_ptr() as u32);}
                }
            }
            if matches!(normalized, 0x180 | 0x181 | 0x182 | 0x184 | 0x186 | 0x18c) {
                unsafe {
                    crate::paint::InvalidateRect(hwnd, 0, 0);
                }
            }
            return result;
        }
    }
    if scroll {
        if let Some(result) = unsafe { crate::scrollbar::message(hwnd, message, wparam, lparam) } {
            return result;
        }
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
