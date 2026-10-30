//! Menu handles, item trees and resource decoding live in the guest.
use crate::{state, text, window};
use alloc::vec::Vec;
#[path = "popup.rs"]
mod popup;
pub use popup::TrackPopupMenu;
#[derive(Clone)]
pub struct Item {
    flags: u32,
    id: u32,
    label: Vec<u16>,
}
pub struct Menu {
    handle: u32,
    items: Vec<Item>,
}
pub struct Attached {
    pub hwnd: u32,
    pub menu: u32,
    system: u32,
}
fn create() -> u32 {
    state::with(|s| {
        let handle = s.next_resource;
        s.next_resource += 1;
        s.menus.push(Menu {
            handle,
            items: Vec::new(),
        });
        handle
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn CreateMenu() -> u32 {
    create()
}
#[unsafe(no_mangle)]
pub extern "system" fn CreatePopupMenu() -> u32 {
    create()
}
#[unsafe(no_mangle)]
pub extern "system" fn IsMenu(h: u32) -> i32 {
    state::with(|s| i32::from(s.menus.iter().any(|m| m.handle == h)))
}
#[unsafe(no_mangle)]
pub extern "system" fn DestroyMenu(h: u32) -> i32 {
    let children = state::with(|s| {
        let i = s.menus.iter().position(|m| m.handle == h)?;
        Some(
            s.menus
                .remove(i)
                .items
                .into_iter()
                .filter(|i| i.flags & 0x10 != 0)
                .map(|i| i.id)
                .collect::<Vec<_>>(),
        )
    });
    let Some(children) = children else {
        return 0;
    };
    for c in children {
        DestroyMenu(c);
    }
    1
}
fn locate(s: &state::State, h: u32, id: u32, flags: u32, depth: usize) -> Option<(usize, usize)> {
    if depth > s.menus.len() {
        return None;
    }
    let m = s.menus.iter().position(|m| m.handle == h)?;
    if flags & 0x400 != 0 {
        return ((id as usize) < s.menus[m].items.len()).then_some((m, id as usize));
    }
    for (i, item) in s.menus[m].items.iter().enumerate() {
        if item.id == id {
            return Some((m, i));
        }
        if item.flags & 0x10 != 0 {
            if let Some(v) = locate(s, item.id, id, flags, depth + 1) {
                return Some(v);
            }
        }
    }
    None
}
fn contains(s: &state::State, root: u32, target: u32, depth: usize) -> bool {
    root == target
        || depth <= s.menus.len()
            && s.menus.iter().find(|m| m.handle == root).is_some_and(|m| {
                m.items
                    .iter()
                    .any(|i| i.flags & 0x10 != 0 && contains(s, i.id, target, depth + 1))
            })
}
pub fn destroy_window(hwnd: u32) {
    let menus = state::with(|s| {
        let i = s.attached_menus.iter().position(|m| m.hwnd == hwnd)?;
        let m = s.attached_menus.remove(i);
        Some((m.menu, m.system))
    });
    if let Some((menu, system)) = menus {
        if menu != 0 {
            DestroyMenu(menu);
        }
        if system != 0 && system != menu {
            DestroyMenu(system);
        }
    }
}
unsafe fn insert(h: u32, at: u32, flags: u32, id: u32, p: u32, wide: bool, replace: bool) -> i32 {
    if flags & 0x10 != 0 && (id == h || IsMenu(id) == 0) {
        return 0;
    }
    if flags & 0x10 != 0 && state::with(|s| contains(s, id, h, 0)) {
        return state::error(87) as i32;
    }
    let label = if flags & 0x804 != 0 {
        Vec::new()
    } else {
        unsafe { text::read(p, wide) }
    };
    state::with(|s| {
        let Some(m) = s.menus.iter().position(|m| m.handle == h) else {
            return state::error(1401) as i32;
        };
        let target = locate(s, h, at, flags, 0);
        let (m, i) = target.unwrap_or((m, s.menus[m].items.len()));
        let flags = if flags & 0x14 == 0 && id == 0 && label.is_empty() {
            flags | 0x800
        } else {
            flags
        };
        let item = Item { flags, id, label };
        if replace {
            if i >= s.menus[m].items.len() {
                return 0;
            }
            s.menus[m].items[i] = item;
        } else {
            s.menus[m].items.insert(i, item);
        }
        1
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn AppendMenuA(h: u32, f: u32, id: u32, p: u32) -> i32 {
    unsafe { insert(h, u32::MAX, f | 0x400, id, p, false, false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn AppendMenuW(h: u32, f: u32, id: u32, p: u32) -> i32 {
    unsafe { insert(h, u32::MAX, f | 0x400, id, p, true, false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn InsertMenuA(h: u32, at: u32, f: u32, id: u32, p: u32) -> i32 {
    unsafe { insert(h, at, f, id, p, false, false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn InsertMenuW(h: u32, at: u32, f: u32, id: u32, p: u32) -> i32 {
    unsafe { insert(h, at, f, id, p, true, false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn ModifyMenuA(h: u32, at: u32, f: u32, id: u32, p: u32) -> i32 {
    unsafe { insert(h, at, f, id, p, false, true) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn ModifyMenuW(h: u32, at: u32, f: u32, id: u32, p: u32) -> i32 {
    unsafe { insert(h, at, f, id, p, true, true) }
}
#[unsafe(no_mangle)]
pub extern "system" fn GetMenuItemCount(h: u32) -> i32 {
    state::with(|s| {
        s.menus
            .iter()
            .find(|m| m.handle == h)
            .map_or(-1, |m| m.items.len() as i32)
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn GetMenuItemID(h: u32, i: i32) -> u32 {
    state::with(|s| {
        s.menus
            .iter()
            .find(|m| m.handle == h)
            .and_then(|m| m.items.get(i as usize))
            .map_or(
                u32::MAX,
                |i| if i.flags & 0x10 != 0 { u32::MAX } else { i.id },
            )
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn GetSubMenu(h: u32, i: i32) -> u32 {
    state::with(|s| {
        s.menus
            .iter()
            .find(|m| m.handle == h)
            .and_then(|m| m.items.get(i as usize))
            .map_or(0, |i| if i.flags & 0x10 != 0 { i.id } else { 0 })
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn GetMenuState(h: u32, id: u32, f: u32) -> u32 {
    state::with(|s| {
        let Some((m, i)) = locate(s, h, id, f, 0) else {
            return u32::MAX;
        };
        let i = &s.menus[m].items[i];
        (i.flags & 0xff)
            | if i.flags & 0x10 != 0 {
                s.menus
                    .iter()
                    .find(|m| m.handle == i.id)
                    .map_or(0, |m| (m.items.len() as u32) << 8)
            } else {
                0
            }
    })
}
fn change(h: u32, id: u32, f: u32, mask: u32) -> u32 {
    state::with(|s| {
        let Some((m, i)) = locate(s, h, id, f, 0) else {
            return u32::MAX;
        };
        let item = &mut s.menus[m].items[i];
        let old = item.flags & mask;
        item.flags = (item.flags & !mask) | (f & mask);
        old
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn EnableMenuItem(h: u32, id: u32, f: u32) -> u32 {
    change(h, id, f, 3)
}
#[unsafe(no_mangle)]
pub extern "system" fn CheckMenuItem(h: u32, id: u32, f: u32) -> u32 {
    change(h, id, f, 8)
}
#[unsafe(no_mangle)]
pub extern "system" fn RemoveMenu(h: u32, id: u32, f: u32) -> i32 {
    state::with(|s| {
        let Some((m, i)) = locate(s, h, id, f, 0) else {
            return 0;
        };
        s.menus[m].items.remove(i);
        1
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn DeleteMenu(h: u32, id: u32, f: u32) -> i32 {
    let sub = state::with(|s| {
        locate(s, h, id, f, 0).and_then(|(m, i)| {
            let i = &s.menus[m].items[i];
            (i.flags & 0x10 != 0).then_some(i.id)
        })
    });
    let r = RemoveMenu(h, id, f);
    if let Some(sub) = sub {
        DestroyMenu(sub);
    }
    r
}
#[unsafe(no_mangle)]
pub extern "system" fn GetMenu(h: u32) -> u32 {
    state::with(|s| {
        s.attached_menus
            .iter()
            .find(|m| m.hwnd == h)
            .map_or(0, |m| m.menu)
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn SetMenu(h: u32, menu: u32) -> i32 {
    if window::IsWindow(h) == 0 || menu != 0 && IsMenu(menu) == 0 {
        return 0;
    }
    state::with(|s| {
        if let Some(m) = s.attached_menus.iter_mut().find(|m| m.hwnd == h) {
            m.menu = menu;
        } else {
            s.attached_menus.push(Attached {
                hwnd: h,
                menu,
                system: 0,
            });
        }
    });
    unsafe {
        crate::paint::InvalidateRect(h, 0, 1);
    }
    1
}
#[unsafe(no_mangle)]
pub extern "system" fn GetSystemMenu(h: u32, reset: u32) -> u32 {
    if window::IsWindow(h) == 0 {
        return 0;
    }
    let old = state::with(|s| {
        s.attached_menus
            .iter()
            .find(|m| m.hwnd == h)
            .map_or(0, |m| m.system)
    });
    if reset != 0 {
        if old != 0 {
            DestroyMenu(old);
            state::with(|s| {
                if let Some(m) = s.attached_menus.iter_mut().find(|m| m.hwnd == h) {
                    m.system = 0;
                }
            });
        }
        return 0;
    }
    if old != 0 {
        return old;
    }
    let menu = create();
    for (id, label) in [
        (0xf120, "Restore"),
        (0xf010, "Move"),
        (0xf000, "Size"),
        (0xf020, "Minimize"),
        (0xf030, "Maximize"),
        (0xf060, "Close"),
    ] {
        let title: Vec<u16> = label.encode_utf16().chain(core::iter::once(0)).collect();
        unsafe {
            AppendMenuW(menu, 0, id, title.as_ptr() as u32);
        }
    }
    state::with(|s| {
        if let Some(m) = s.attached_menus.iter_mut().find(|m| m.hwnd == h) {
            m.system = menu;
        } else {
            s.attached_menus.push(Attached {
                hwnd: h,
                menu: 0,
                system: menu,
            });
        }
    });
    menu
}
unsafe fn load(instance: u32, name: u32, wide: bool) -> u32 {
    if crate::win16_resource::instance(instance) {
        return unsafe { crate::win16_resource::bytes(4, name, wide) }
            .and_then(crate::win16_resource::menu)
            .map_or(0, |data| template(&data));
    }
    let Some(data) = (unsafe { crate::resource::bytes(instance, name, 4, wide) }) else {
        return 0;
    };
    template(data)
}
fn template(data: &[u8]) -> u32 {
    fn word(data: &[u8], p: &mut usize) -> Option<u16> {
        let b = data.get(*p..*p + 2)?;
        *p += 2;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }
    fn items(data: &[u8], p: &mut usize, depth: usize) -> Option<u32> {
        if depth > 64 {
            return None;
        }
        let h = create();
        let parsed = (|| -> Option<()> {
            loop {
                let flags = u32::from(word(data, p)?);
                let id = if flags & 0x10 == 0 {
                    u32::from(word(data, p)?)
                } else {
                    0
                };
                let mut title = Vec::new();
                loop {
                    let c = word(data, p)?;
                    title.push(c);
                    if c == 0 {
                        break;
                    }
                }
                let id = if flags & 0x10 != 0 {
                    items(data, p, depth + 1)?
                } else {
                    id
                };
                unsafe {
                    AppendMenuW(h, flags & !0x80, id, title.as_ptr() as u32);
                }
                if flags & 0x80 != 0 {
                    break;
                }
            }
            Some(())
        })();
        if parsed.is_none() {
            DestroyMenu(h);
            return None;
        }
        Some(h)
    }
    let mut p = 0;
    let Some(version) = word(data, &mut p) else {
        return 0;
    };
    let Some(offset) = word(data, &mut p) else {
        return 0;
    };
    if version != 0 {
        return state::error(120);
    }
    p += offset as usize;
    items(data, &mut p, 0).unwrap_or(0)
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn LoadMenuA(i: u32, n: u32) -> u32 {
    unsafe { load(i, n, false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn LoadMenuW(i: u32, n: u32) -> u32 {
    unsafe { load(i, n, true) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DrawMenuBar(h: u32) -> i32 {
    if window::IsWindow(h) == 0 {
        return 0;
    }
    crate::frame::paint(h);
    1
}
#[derive(Clone, Copy)]
pub struct Popup {
    pub hwnd: u32,
    menu: u32,
    rect: [i32; 4],
    hot: Option<usize>,
    opening: bool,
}
fn display_label(text: &[u16]) -> Vec<u16> {
    text.iter().copied().filter(|&c| c != 38).collect()
}
fn bar_rects(s: &state::State, h: u32) -> Vec<(Item, [i32; 4])> {
    let Some(w) = s.windows.iter().find(|w| w.hwnd == h) else {
        return Vec::new();
    };
    let Some(a) = s.attached_menus.iter().find(|a| a.hwnd == h) else {
        return Vec::new();
    };
    let Some(menu) = s.menus.iter().find(|m| m.handle == a.menu) else {
        return Vec::new();
    };
    let r = crate::frame::client(s, w);
    let mut x = r[0];
    menu.items
        .iter()
        .map(|i| {
            let width = display_label(&i.label).len() as i32 * 8 + 16;
            let rect = [x, r[1] - crate::frame::MENU_HEIGHT, x + width, r[1]];
            x += width;
            (i.clone(), rect)
        })
        .collect()
}
fn rows(s: &state::State, p: &Popup) -> Vec<(Item, [i32; 4])> {
    let Some(menu) = s.menus.iter().find(|m| m.handle == p.menu) else {
        return Vec::new();
    };
    let mut y = p.rect[1] + 2;
    menu.items
        .iter()
        .map(|i| {
            let height = if i.flags & 0x800 != 0 { 7 } else { 20 };
            let r = [p.rect[0] + 2, y, p.rect[2] - 2, y + height];
            y += height;
            (i.clone(), r)
        })
        .collect()
}
fn inside(r: [i32; 4], x: i32, y: i32) -> bool {
    x >= r[0] && y >= r[1] && x < r[2] && y < r[3]
}
pub fn draw(h: u32, dc: u32) {
    let (bar, popup) = state::with(|s| {
        (
            bar_rects(s, h),
            s.menu_popup
                .as_ref()
                .filter(|p| p.hwnd == h)
                .map(|p| (*p, rows(s, p))),
        )
    });
    for (item, r) in bar {
        crate::frame::fill(dc, r, 0xc0c0c0);
        crate::frame::label(dc, r[0] + 8, r[1] + 1, &display_label(&item.label), 0);
    }
    if let Some((p, items)) = popup {
        draw_popup(dc, &p, &items);
    }
}
fn draw_popup(dc: u32, p: &Popup, items: &[(Item, [i32; 4])]) {
    crate::frame::bevel(dc, p.rect);
    for (index, (i, r)) in items.iter().enumerate() {
        if i.flags & 0x800 != 0 {
            crate::frame::fill(dc, [r[0] + 2, r[1] + 3, r[2] - 2, r[1] + 4], 0x808080);
            continue;
        }
        let hot = p.hot == Some(index) && i.flags & 3 == 0;
        crate::frame::fill(dc, *r, if hot { 0x800000 } else { 0xc0c0c0 });
        let color = if i.flags & 3 != 0 {
            0x808080
        } else if hot {
            0xffffff
        } else {
            0
        };
        let label = display_label(&i.label);
        let mut parts = label.split(|&c| c == 9);
        crate::frame::label(dc, r[0] + 18, r[1] + 2, parts.next().unwrap_or(&[]), color);
        if let Some(accel) = parts.next() {
            crate::frame::label(
                dc,
                r[2] - 4 - accel.len() as i32 * 8,
                r[1] + 2,
                accel,
                color,
            );
        }
        if i.flags & 8 != 0 {
            crate::frame::label(dc, r[0] + 3, r[1] + 2, &[42], color);
        }
    }
}

pub fn pointer(h: u32, message: u32, x: i32, y: i32) {
    let opening = state::with(|s| {
        if let Some(p) = s.menu_popup.as_mut().filter(|p| p.hwnd == h) {
            if p.opening && message == 0xa2 {
                p.opening = false;
                return true;
            }
        }
        false
    });
    if opening {
        return;
    }
    let open = state::with(|s| {
        if s.menu_popup
            .as_ref()
            .is_some_and(|p| p.hwnd == h && inside(p.rect, x, y))
        {
            return None;
        }
        bar_rects(s, h).into_iter().find(|(_, r)| inside(*r, x, y))
    });
    if let Some((item, rect)) = open {
        if message == 0xa1 && item.flags & 0x10 != 0 && item.flags & 3 == 0 {
            unsafe {
                crate::SendMessageW(h, 0x116, GetMenu(h), 0);
                crate::SendMessageW(h, 0x117, item.id, 0);
            }
            state::with(|s| {
                let Some(menu) = s.menus.iter().find(|m| m.handle == item.id) else {
                    return;
                };
                let width = menu
                    .items
                    .iter()
                    .map(|i| display_label(&i.label).len() as i32 * 8 + 32)
                    .max()
                    .unwrap_or(80);
                let height = 4 + menu
                    .items
                    .iter()
                    .map(|i| if i.flags & 0x800 != 0 { 7 } else { 20 })
                    .sum::<i32>();
                let Some(w) = s.windows.iter().find(|w| w.hwnd == h) else {
                    return;
                };
                let left = rect[0].min((w.width - width).max(0));
                let top = rect[3].min((w.height - height).max(0));
                s.menu_popup = Some(Popup {
                    hwnd: h,
                    menu: item.id,
                    rect: [left, top, (left + width).min(w.width), top + height],
                    hot: None,
                    opening: true,
                });
            });
            crate::frame::paint(h);
        }
        return;
    }
    let mut command = None;
    let mut close = false;
    let mut changed = false;
    state::with(|s| {
        let Some(p) = s.menu_popup.as_ref().filter(|p| p.hwnd == h).copied() else {
            return;
        };
        let hit = rows(s, &p)
            .into_iter()
            .enumerate()
            .find(|(_, (_, r))| inside(*r, x, y));
        if let Some(p) = s.menu_popup.as_mut() {
            let hot = hit.as_ref().map(|(i, _)| *i);
            changed = p.hot != hot;
            p.hot = hot;
        }
        if message == 0xa2 {
            close = true;
            if let Some((_, (i, _))) = hit {
                if i.flags & (3 | 0x800 | 0x10) == 0 {
                    command = Some(i.id);
                }
            }
        } else if message == 0xa1 && hit.is_none() {
            close = true;
        }
        if close {
            s.menu_popup = None;
        }
    });
    if close {
        unsafe {
            crate::paint::InvalidateRect(h, 0, 1);
            crate::paint::UpdateWindow(h);
        }
    } else if changed {
        crate::frame::paint(h);
    }
    if let Some(id) = command {
        unsafe {
            crate::SendMessageW(h, 0x111, id, 0);
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetMenuItemRect(
    h: u32,
    menu: u32,
    index: u32,
    out: *mut [i32; 4],
) -> i32 {
    if out.is_null() {
        return 0;
    }
    let rect = state::with(|s| {
        let h = if h == 0 {
            s.attached_menus.iter().find(|a| a.menu == menu)?.hwnd
        } else {
            h
        };
        let rect = if s
            .attached_menus
            .iter()
            .any(|a| a.hwnd == h && a.menu == menu)
        {
            bar_rects(s, h).get(index as usize)?.1
        } else {
            let p = s
                .menu_popup
                .as_ref()
                .filter(|p| p.hwnd == h && p.menu == menu)?;
            rows(s, p).get(index as usize)?.1
        };
        let (x, y) = crate::frame::origin(s, h, false)?;
        Some([rect[0] + x, rect[1] + y, rect[2] + x, rect[3] + y])
    });
    let Some(r) = rect else {
        return 0;
    };
    unsafe {
        out.write_unaligned(r);
    }
    1
}

pub fn popup_rect(h: u32) -> Option<[i32; 4]> {
    state::with(|s| {
        s.menu_popup
            .as_ref()
            .filter(|p| p.hwnd == h)
            .map(|p| p.rect)
    })
}
