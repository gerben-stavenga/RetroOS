//! Dialog templates and modal loops execute in the guest, including callbacks.
use crate::window::GetDlgItem;
use crate::{CreateStruct, Message, state, window};
use alloc::vec::Vec;
pub struct Dialog {
    pub hwnd: u32,
    proc: u32,
    wide: bool,
    ended: Option<i32>,
    default: u32,
}
struct Reader {
    at: usize,
    end: usize,
}
impl Reader {
    unsafe fn word(&mut self) -> Option<u16> {
        if self.at.checked_add(2)? > self.end {
            return None;
        }
        let v = unsafe { (self.at as *const u16).read_unaligned() };
        self.at += 2;
        Some(v)
    }
    unsafe fn dword(&mut self) -> Option<u32> {
        Some(u32::from(unsafe { self.word()? }) | (u32::from(unsafe { self.word()? }) << 16))
    }
    fn align(&mut self) {
        self.at = (self.at + 3) & !3;
    }
    unsafe fn name(&mut self) -> Option<Vec<u16>> {
        let first = unsafe { self.word()? };
        let mut v = Vec::new();
        if first == 0xffff {
            v.push(first);
            v.push(unsafe { self.word()? });
        } else if first != 0 {
            v.push(first);
            loop {
                let c = unsafe { self.word()? };
                if c == 0 {
                    break;
                }
                v.push(c);
            }
        }
        v.push(0);
        Some(v)
    }
}
fn pointer(name: &[u16]) -> u32 {
    if name[0] == 0xffff {
        u32::from(name[1])
    } else {
        name.as_ptr() as u32
    }
}
unsafe fn template(
    instance: u32,
    data: u32,
    size: usize,
    parent: u32,
    proc: u32,
    parameter: u32,
    wide: bool,
) -> Option<u32> {
    if parent != 0 && window::IsWindow(parent) == 0 {
        state::error(1400);
        return None;
    }
    if data == 0 {
        return None;
    }
    let mut r = Reader {
        at: data as usize,
        end: (data as usize).checked_add(size)?,
    };
    let first = unsafe { r.dword()? };
    let extended = first == 0xffff0001;
    let (style, ex) = if extended {
        unsafe {
            r.dword()?;
            let ex = r.dword()?;
            (r.dword()?, ex)
        }
    } else {
        (first, unsafe { r.dword()? })
    };
    let count = unsafe { r.word()? };
    let x = unsafe { r.word()? } as i16 as i32;
    let y = unsafe { r.word()? } as i16 as i32;
    let width = unsafe { r.word()? } as i16 as i32;
    let height = unsafe { r.word()? } as i16 as i32;
    let _menu = unsafe { r.name()? };
    let mut class = unsafe { r.name()? };
    if class[0] == 0 {
        class = "#32770\0".encode_utf16().collect();
    }
    let title = unsafe { r.name()? };
    if style & 0x40 != 0 {
        unsafe {
            r.word()?;
            if extended {
                r.word()?;
                r.word()?;
            }
            r.name()?;
        }
    }
    // Default dialog units: the stock 8 by 16 system font.
    let hwnd = unsafe {
        window::create(
            CreateStruct {
                instance,
                parameter: 0,
                parent,
                menu: 0,
                x: x * 2,
                y: y * 2,
                width: width * 2,
                height: height * 2,
                style: style & !0x10000000,
                ex_style: ex,
                class: pointer(&class),
                title: pointer(&title),
            },
            true,
        )
    };
    if hwnd == 0 {
        return None;
    }
    state::with(|s| {
        s.dialogs.push(Dialog {
            hwnd,
            proc,
            wide,
            ended: None,
            default: 1,
        })
    });
    let children = (|| -> Option<()> {
        for _ in 0..count {
            r.align();
            let (style, ex) = if extended {
                unsafe {
                    r.dword()?;
                    let ex = r.dword()?;
                    (r.dword()?, ex)
                }
            } else {
                unsafe { (r.dword()?, r.dword()?) }
            };
            let x = unsafe { r.word()? } as i16 as i32;
            let y = unsafe { r.word()? } as i16 as i32;
            let width = unsafe { r.word()? } as i16 as i32;
            let height = unsafe { r.word()? } as i16 as i32;
            let id = if extended {
                unsafe { r.dword()? }
            } else {
                u32::from(unsafe { r.word()? })
            };
            let mut class = unsafe { r.name()? };
            let title = unsafe { r.name()? };
            if class[0] == 0xffff {
                let name = match class[1] {
                    0x80 => "Button",
                    0x81 => "Edit",
                    0x82 => "Static",
                    0x83 => "ListBox",
                    0x84 => "ScrollBar",
                    0x85 => "ComboBox",
                    _ => return None,
                };
                class = name.encode_utf16().chain(core::iter::once(0)).collect();
            }
            let extra = unsafe { r.word()? } as usize;
            let parameter = if extra == 0 { 0 } else { r.at as u32 };
            r.at = r.at.checked_add(extra)?;
            if r.at > r.end {
                return None;
            }
            let child = unsafe {
                window::create(
                    CreateStruct {
                        instance,
                        parameter,
                        parent: hwnd,
                        menu: id,
                        x: x * 2,
                        y: y * 2,
                        width: width * 2,
                        height: height * 2,
                        style: style | 0x40000000,
                        ex_style: ex,
                        class: pointer(&class),
                        title: if title[0] == 0xffff {
                            0
                        } else {
                            pointer(&title)
                        },
                    },
                    true,
                )
            };
            if child == 0 {
                return None;
            }
            if style & 0xf == 1 {
                state::with(|s| {
                    if let Some(d) = s.dialogs.iter_mut().find(|d| d.hwnd == hwnd) {
                        d.default = id;
                    }
                });
            }
        }
        Some(())
    })();
    if children.is_none() {
        window::DestroyWindow(hwnd);
        return None;
    }
    if proc != 0 {
        let callback: crate::WndProc = unsafe { core::mem::transmute(proc) };
        unsafe {
            let focus = crate::input::GetNextDlgTabItem(hwnd, 0, 0);
            if callback(hwnd, 0x110, focus, parameter) != 0
                && window::IsWindow(hwnd) != 0
                && style & 0x400 == 0
            {
                crate::input::SetFocus(crate::input::GetNextDlgTabItem(hwnd, 0, 0));
            }
        }
    }
    if style & 0x10000000 != 0 {
        window::ShowWindow(hwnd, 5);
    }
    Some(hwnd)
}
unsafe fn create(
    instance: u32,
    name: u32,
    parent: u32,
    proc: u32,
    parameter: u32,
    wide: bool,
) -> u32 {
    let Some(data) = (unsafe { crate::resource::bytes(instance, name, 5, wide) }) else {
        return 0;
    };
    unsafe {
        template(
            instance,
            data.as_ptr() as u32,
            data.len(),
            parent,
            proc,
            parameter,
            wide,
        )
        .unwrap_or(0)
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn CreateDialogParamA(i: u32, n: u32, p: u32, f: u32, l: u32) -> u32 {
    unsafe { create(i, n, p, f, l, false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn CreateDialogParamW(i: u32, n: u32, p: u32, f: u32, l: u32) -> u32 {
    unsafe { create(i, n, p, f, l, true) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn CreateDialogIndirectParamA(
    i: u32,
    n: u32,
    p: u32,
    f: u32,
    l: u32,
) -> u32 {
    unsafe { template(i, n, 0x100000, p, f, l, false).unwrap_or(0) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn CreateDialogIndirectParamW(
    i: u32,
    n: u32,
    p: u32,
    f: u32,
    l: u32,
) -> u32 {
    unsafe { template(i, n, 0x100000, p, f, l, true).unwrap_or(0) }
}
#[unsafe(no_mangle)]
pub extern "system" fn EndDialog(hwnd: u32, result: i32) -> i32 {
    state::with(|s| {
        let Some(d) = s.dialogs.iter_mut().find(|d| d.hwnd == hwnd) else {
            return 0;
        };
        d.ended = Some(result);
        1
    })
}
unsafe fn modal(hwnd: u32) -> i32 {
    if hwnd == 0 || window::IsWindow(hwnd) == 0 {
        return -1;
    }
    window::ShowWindow(hwnd, 0);
    let mut shown = false;
    let result = loop {
        let result = state::with(|s| {
            s.dialogs
                .iter()
                .find(|d| d.hwnd == hwnd)
                .and_then(|d| d.ended)
        });
        if let Some(result) = result {
            break result;
        }
        if window::IsWindow(hwnd) == 0 {
            break 0;
        }
        let mut msg = Message::default();
        if unsafe { crate::message::PeekMessageW(&mut msg, 0, 0, 0, 1) } == 0 {
            if !shown {
                window::ShowWindow(hwnd, 5);
                shown = true;
            }
            if unsafe { crate::message::GetMessageW(&mut msg, 0, 0, 0) } <= 0 {
                break -1;
            }
        }
        if msg.message == 0x12 {
            break -1;
        }
        unsafe {
            if crate::input::IsDialogMessageW(hwnd, &msg) == 0 {
                crate::DispatchMessageW(&msg);
            }
            if !shown && msg.message == 0x113 {
                window::ShowWindow(hwnd, 5);
                shown = true;
            }
        }
    };
    window::DestroyWindow(hwnd);
    state::with(|s| s.dialogs.retain(|d| d.hwnd != hwnd));
    result
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DialogBoxParamA(i: u32, n: u32, p: u32, f: u32, l: u32) -> i32 {
    unsafe { modal(create(i, n, p, f, l, false)) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DialogBoxParamW(i: u32, n: u32, p: u32, f: u32, l: u32) -> i32 {
    unsafe { modal(create(i, n, p, f, l, true)) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DialogBoxIndirectParamA(
    i: u32,
    n: u32,
    p: u32,
    f: u32,
    l: u32,
) -> i32 {
    unsafe { modal(CreateDialogIndirectParamA(i, n, p, f, l)) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DialogBoxIndirectParamW(
    i: u32,
    n: u32,
    p: u32,
    f: u32,
    l: u32,
) -> i32 {
    unsafe { modal(CreateDialogIndirectParamW(i, n, p, f, l)) }
}
unsafe fn default(hwnd: u32, m: u32, w: u32, l: u32, wide: bool) -> i32 {
    if m == 0x401 {
        state::with(|s| {
            if !s.dialogs.iter().any(|d| d.hwnd == hwnd) {
                s.dialogs.push(Dialog {
                    hwnd,
                    proc: 0,
                    wide,
                    ended: None,
                    default: 1,
                });
            }
        });
    }
    let callback = state::with(|s| {
        s.dialogs
            .iter()
            .find(|d| d.hwnd == hwnd)
            .map(|d| (d.proc, d.wide))
    });
    if let Some((proc, _)) = callback.filter(|p| p.0 != 0) {
        let callback: crate::WndProc = unsafe { core::mem::transmute(proc) };
        let result = unsafe { callback(hwnd, m, w, l) };
        if result != 0 {
            return result;
        }
    }
    match m {
        7 => {
            unsafe {
                crate::input::SetFocus(crate::input::GetNextDlgTabItem(hwnd, 0, 0));
            }
            0
        }
        0x28 => {
            unsafe {
                crate::input::SetFocus(if l != 0 {
                    w
                } else {
                    crate::input::GetNextDlgTabItem(hwnd, crate::input::GetFocus(), w)
                });
            }
            let focus = crate::input::GetFocus();
            let buttons = state::with(|s| {
                s.windows
                    .iter()
                    .filter(|v| {
                        v.parent == hwnd
                            && matches!(v.style & 15, 0 | 1)
                            && s.classes.iter().any(|c| {
                                c.atom == v.class && c.name == [66, 117, 116, 116, 111, 110]
                            })
                    })
                    .map(|v| v.hwnd)
                    .collect::<Vec<_>>()
            });
            for button in buttons {
                unsafe {
                    crate::SendMessageW(button, 0xf4, u32::from(button == focus), 1);
                }
            }
            0
        }
        0x400 => state::with(|s| {
            s.dialogs.iter().find(|d| d.hwnd == hwnd).map_or(0, |d| {
                if d.default == 0 {
                    0
                } else {
                    (0x534b0000 | d.default) as i32
                }
            })
        }),
        0x401 => {
            state::with(|s| {
                if let Some(d) = s.dialogs.iter_mut().find(|d| d.hwnd == hwnd) {
                    d.default = w;
                }
            });
            1
        }
        _ => unsafe {
            if wide {
                window::DefWindowProcW(hwnd, m, w, l)
            } else {
                window::DefWindowProcA(hwnd, m, w, l)
            }
        },
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DefDlgProcA(h: u32, m: u32, w: u32, l: u32) -> i32 {
    unsafe { default(h, m, w, l, false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DefDlgProcW(h: u32, m: u32, w: u32, l: u32) -> i32 {
    unsafe { default(h, m, w, l, true) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SendDlgItemMessageA(h: u32, id: u32, m: u32, w: u32, l: u32) -> i32 {
    unsafe { crate::SendMessageA(GetDlgItem(h, id as i32), m, w, l) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SendDlgItemMessageW(h: u32, id: u32, m: u32, w: u32, l: u32) -> i32 {
    unsafe { crate::SendMessageW(GetDlgItem(h, id as i32), m, w, l) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SetDlgItemTextA(h: u32, id: u32, t: u32) -> i32 {
    unsafe { SendDlgItemMessageA(h, id, 0xc, 0, t) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SetDlgItemTextW(h: u32, id: u32, t: u32) -> i32 {
    unsafe { SendDlgItemMessageW(h, id, 0xc, 0, t) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetDlgItemTextA(h: u32, id: u32, t: u32, n: u32) -> i32 {
    if t != 0 && n != 0 {
        unsafe {
            (t as *mut u8).write(0);
        }
    }
    unsafe { SendDlgItemMessageA(h, id, 0xd, n, t) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetDlgItemTextW(h: u32, id: u32, t: u32, n: u32) -> i32 {
    if t != 0 && n != 0 {
        unsafe {
            (t as *mut u16).write_unaligned(0);
        }
    }
    unsafe { SendDlgItemMessageW(h, id, 0xd, n, t) }
}
#[unsafe(no_mangle)]
pub extern "system" fn GetDialogBaseUnits() -> u32 {
    0x00100008
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn MapDialogRect(h: u32, r: *mut [i32; 4]) -> i32 {
    if r.is_null() || window::IsWindow(h) == 0 {
        return 0;
    }
    let mut rect = unsafe { r.read_unaligned() };
    for v in &mut rect {
        *v = v.saturating_mul(2);
    }
    unsafe {
        r.write_unaligned(rect);
    }
    1
}
