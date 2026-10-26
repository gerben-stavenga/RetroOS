//! Menu handles, item trees and resource decoding live in the guest.
use crate::{state, text, window};
use alloc::vec::Vec;
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
    menu: u32,
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
    let Some(data) = (unsafe { crate::resource::bytes(instance, name, 4, wide) }) else {
        return 0;
    };
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
    let items = state::with(|s| {
        let menu = s.attached_menus.iter().find(|m| m.hwnd == h)?.menu;
        s.menus
            .iter()
            .find(|m| m.handle == menu)
            .map(|m| m.items.clone())
    });
    let Some(items) = items else {
        return 1;
    };
    unsafe extern "system" {
        fn TextOutW(dc: u32, x: i32, y: i32, text: *const u16, count: i32) -> i32;
        fn FillRect(dc: u32, r: *const [i32; 4], brush: u32) -> i32;
        fn GetStockObject(i: u32) -> u32;
    }
    let dc = unsafe { crate::paint::GetWindowDC(h) };
    if dc == 0 {
        return 0;
    }
    let mut x = 8;
    for item in items {
        let width = item.label.len() as i32 * 8 + 16;
        unsafe {
            FillRect(dc, &[x - 8, 0, x + width, 20], GetStockObject(1));
            TextOutW(dc, x, 2, item.label.as_ptr(), item.label.len() as i32);
        }
        x += width;
    }
    crate::paint::ReleaseDC(h, dc);
    1
}
