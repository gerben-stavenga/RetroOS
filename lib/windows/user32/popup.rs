//! Shortcut menus run an ordinary guest modal loop. The display state stays
//! on that guest stack, including when a submenu opens another modal loop.
use super::{Popup, display_label, draw_popup, rows};
use crate::{class, input, message, paint, state, window};
use core::cell::UnsafeCell;

#[derive(Clone, Copy)]
struct Display {
    popup: Popup,
    cancelled: bool,
}

struct Notifications {
    owner: u32,
    menu: u32,
    root: bool,
    enabled: bool,
}
impl Drop for Notifications {
    fn drop(&mut self) {
        if self.enabled && window::IsWindow(self.owner) != 0 {
            unsafe {
                crate::SendMessageW(self.owner, 0x125, self.menu, 0);
                if self.root {
                    crate::SendMessageW(self.owner, 0x212, 1, 0);
                }
            }
        }
    }
}

unsafe extern "system" fn procedure(hwnd: u32, msg: u32, wp: u32, lp: u32) -> i32 {
    let address = unsafe { window::GetWindowLongW(hwnd, -21) } as *mut Display;
    if !address.is_null() {
        match msg {
            0x10 | 0x1f => {
                unsafe {
                    (*address).cancelled = true;
                }
                return 0;
            }
            0xf => {
                let popup = unsafe { (*address).popup };
                let items = state::with(|s| rows(s, &popup));
                let mut ps = [0u32; 16];
                let dc = unsafe { paint::BeginPaint(hwnd, ps.as_mut_ptr() as u32) };
                if dc != 0 {
                    draw_popup(dc, &popup, &items);
                    unsafe {
                        paint::EndPaint(hwnd, ps.as_mut_ptr() as u32);
                    }
                }
                return 0;
            }
            0x14 => return 1,
            _ => {}
        }
    }
    unsafe { window::DefWindowProcW(hwnd, msg, wp, lp) }
}

fn popup_class() -> u32 {
    let proc = procedure as *const () as u32;
    if let Some(atom) = state::with(|s| s.classes.iter().find(|c| c.proc == proc).map(|c| c.atom)) {
        return atom;
    }
    let name: alloc::vec::Vec<u16> = "RetroPopupMenu\0".encode_utf16().collect();
    let descriptor = [0, proc, 0, 0, 0, 0, 0, 0, 0, name.as_ptr() as u32];
    unsafe { class::RegisterClassW(descriptor.as_ptr() as u32) }
}

fn enabled(item: &super::Item) -> bool {
    item.flags & (3 | 0x800) == 0
}

// The caller decides whether to post WM_COMMAND or return the selected ID.
unsafe fn track(
    menu: u32,
    flags: u32,
    mut x: i32,
    mut y: i32,
    owner: u32,
    depth: usize,
) -> Result<Option<u32>, ()> {
    if depth >= 32 || super::IsMenu(menu) == 0 || window::IsWindow(owner) == 0 {
        return Err(());
    }
    let _notifications = Notifications {
        owner,
        menu,
        root: depth == 0,
        enabled: flags & 0x80 == 0,
    };
    if flags & 0x80 == 0 {
        unsafe {
            if depth == 0 {
                crate::SendMessageW(owner, 0x211, 1, 0);
                crate::SendMessageW(owner, 0x116, menu, 0);
            }
            crate::SendMessageW(owner, 0x117, menu, 0);
        }
    }
    let size = state::with(|s| {
        s.menus.iter().find(|m| m.handle == menu).map(|m| {
            let width = m
                .items
                .iter()
                .map(|i| display_label(&i.label).len() as i32 * 8 + 36)
                .max()
                .unwrap_or(80);
            let height = 4 + m
                .items
                .iter()
                .map(|i| if i.flags & 0x800 != 0 { 7 } else { 20 })
                .sum::<i32>();
            (width.clamp(40, 1024), height.clamp(4, 768))
        })
    })
    .ok_or(())?;
    if flags & 8 != 0 {
        x -= size.0;
    } else if flags & 4 != 0 {
        x -= size.0 / 2;
    }
    if flags & 0x20 != 0 {
        y -= size.1;
    } else if flags & 0x10 != 0 {
        y -= size.1 / 2;
    }
    x = x.clamp(0, 1024 - size.0);
    y = y.clamp(0, 768 - size.1);
    let atom = popup_class();
    if atom == 0 || window::IsWindow(owner) == 0 {
        return Err(());
    }
    let display = UnsafeCell::new(Display {
        popup: Popup {
            hwnd: 0,
            menu,
            rect: [0, 0, size.0, size.1],
            hot: None,
            opening: false,
        },
        cancelled: false,
    });
    let hwnd = unsafe {
        window::create(
            crate::CreateStruct {
                parameter: 0,
                instance: 0,
                menu: 0,
                parent: owner,
                width: size.0,
                height: size.1,
                x,
                y,
                style: 0x80000000,
                title: 0,
                class: atom,
                ex_style: 0x80,
            },
            true,
        )
    };
    if hwnd == 0 {
        return Err(());
    }
    unsafe {
        window::SetWindowLongW(hwnd, -21, display.get() as u32);
    }
    window::ShowWindow(hwnd, 8);
    unsafe {
        paint::UpdateWindow(hwnd);
    }
    let previous_capture = unsafe { input::SetCapture(hwnd) };
    let result = loop {
        if window::IsWindow(owner) == 0
            || window::IsWindow(hwnd) == 0
            || input::GetCapture() != hwnd
            || unsafe { (*display.get()).cancelled }
            || super::IsMenu(menu) == 0
        {
            break Ok(None);
        }
        let mut msg = crate::Message::default();
        let received = unsafe { message::GetMessageW(&mut msg, 0, 0, 0) };
        if received == 0 {
            message::PostQuitMessage(msg.wparam);
            break Ok(None);
        }
        if received < 0 {
            break Err(());
        }
        let mut popup = unsafe { (*display.get()).popup };
        let items = state::with(|s| rows(s, &popup));
        let old_hot = popup.hot;
        let mut select = false;
        if matches!(msg.message, 0x200..=0x205) && msg.hwnd == hwnd {
            let px = msg.lparam as u16 as i16 as i32;
            let py = (msg.lparam >> 16) as u16 as i16 as i32;
            popup.hot = items.iter().position(|(_, r)| super::inside(*r, px, py));
            let button = matches!(msg.message, 0x201 | 0x202)
                || flags & 2 != 0 && matches!(msg.message, 0x204 | 0x205);
            if button && !super::inside(popup.rect, px, py) {
                break Ok(None);
            }
            select = msg.message == 0x202 || flags & 2 != 0 && msg.message == 0x205;
        } else if msg.message == 0x100 {
            match msg.wparam {
                0x1b | 0x25 => break Ok(None),
                0x0d | 0x27 => select = true,
                0x26 | 0x28 | 0x24 | 0x23 => {
                    let candidates: alloc::vec::Vec<usize> = items
                        .iter()
                        .enumerate()
                        .filter_map(|(i, (item, _))| enabled(item).then_some(i))
                        .collect();
                    if !candidates.is_empty() {
                        let old = candidates.iter().position(|i| Some(*i) == popup.hot);
                        let at = match msg.wparam {
                            0x24 => 0,
                            0x23 => candidates.len() - 1,
                            0x26 => old.map_or(candidates.len() - 1, |i| {
                                (i + candidates.len() - 1) % candidates.len()
                            }),
                            _ => old.map_or(0, |i| (i + 1) % candidates.len()),
                        };
                        popup.hot = Some(candidates[at]);
                    }
                }
                _ => {}
            }
        } else {
            unsafe {
                crate::keyboard::TranslateMessage(&msg);
                crate::DispatchMessageW(&msg);
            }
        }
        unsafe {
            (*display.get()).popup = popup;
        }
        if old_hot != popup.hot && window::IsWindow(hwnd) != 0 {
            unsafe {
                paint::InvalidateRect(hwnd, 0, 0);
                paint::UpdateWindow(hwnd);
            }
        }
        if select {
            if let Some((item, row)) = popup
                .hot
                .and_then(|i| items.get(i))
                .filter(|(i, _)| enabled(i))
            {
                if item.flags & 0x10 == 0 {
                    break Ok(Some(item.id));
                }
                let child_flags = flags & !(4 | 8 | 0x10 | 0x20);
                match unsafe {
                    track(
                        item.id,
                        child_flags,
                        x + size.0,
                        y + row[1],
                        owner,
                        depth + 1,
                    )
                } {
                    Ok(Some(id)) => break Ok(Some(id)),
                    Err(()) => break Err(()),
                    Ok(None) => {}
                }
            }
        }
    };
    if input::GetCapture() == hwnd {
        unsafe {
            input::ReleaseCapture();
        }
    }
    if previous_capture != 0 && window::IsWindow(previous_capture) != 0 {
        unsafe {
            input::SetCapture(previous_capture);
        }
    }
    if window::IsWindow(hwnd) != 0 {
        unsafe {
            window::SetWindowLongW(hwnd, -21, 0);
        }
        window::DestroyWindow(hwnd);
    }
    result
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn TrackPopupMenu(
    menu: u32,
    flags: u32,
    x: i32,
    y: i32,
    _reserved: i32,
    owner: u32,
    _rect: *const crate::rect::Rect,
) -> i32 {
    match unsafe { track(menu, flags, x, y, owner, 0) } {
        Err(()) => 0,
        Ok(selected) => {
            if flags & 0x100 != 0 {
                return selected.unwrap_or(0) as i32;
            }
            if flags & 0x80 == 0 {
                if let Some(id) = selected {
                    message::PostMessageW(owner, 0x111, id, 0);
                }
            }
            1
        }
    }
}
