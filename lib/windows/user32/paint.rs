//! USER owns window DC lifetimes and update regions. GDI owns region algebra;
//! the kernel binds each DC to a surface and consumes its selected clip.
use crate::{state, window};
use alloc::vec::Vec;
unsafe extern "system" {
    fn RetroSurfaceDC(hwnd: u32, old: u32) -> u32;
    fn RetroInvalidateWindow(hwnd: u32, rect: u32, erase: u32) -> i32;
    fn RetroValidateWindow(hwnd: u32) -> i32;
    fn RetroEndPaint(hwnd: u32, paint: u32) -> i32;
    fn CreateRectRgn(l: i32, t: i32, r: i32, b: i32) -> u32;
    fn GetClipBox(dc: u32, rect: *mut [i32; 4]) -> i32;
    fn GetRgnBox(region: u32, rect: *mut [i32; 4]) -> i32;
    fn SelectClipRgn(dc: u32, region: u32) -> i32;
    fn CombineRgn(dst: u32, a: u32, b: u32, mode: u32) -> i32;
    fn OffsetRgn(region: u32, x: i32, y: i32) -> i32;
    fn DeleteObject(object: u32) -> i32;
    fn DeleteDC(dc: u32) -> i32;
    fn SetROP2(dc: u32, mode: i32) -> i32;
}
pub struct WindowDc {
    hwnd: u32,
    class: u32,
    handle: u32,
    persistent: bool,
    active: bool,
    owned_regions: Vec<(u32, u32)>,
    painting: bool,
}
pub struct Update {
    hwnd: u32,
    region: u32,
    erase: bool,
}
fn empty_region() -> u32 {
    unsafe { CreateRectRgn(0, 0, 0, 0) }
}
fn full(s: &state::State, hwnd: u32) -> u32 {
    let (w, h) = s
        .windows
        .iter()
        .find(|w| w.hwnd == hwnd)
        .map_or((1024, 768), |w| (w.width, w.height));
    unsafe { CreateRectRgn(0, 0, w, h) }
}
pub fn record_native(s: &mut state::State, hwnd: u32) {
    if !s.updates.iter().any(|u| u.hwnd == hwnd) {
        let region = full(s, hwnd);
        s.updates.push(Update {
            hwnd,
            region,
            erase: true,
        });
    }
}
fn origin(s: &state::State, mut hwnd: u32) -> (i32, i32) {
    let (mut x, mut y) = (0i32, 0i32);
    while let Some(w) = s.windows.iter().find(|w| w.hwnd == hwnd) {
        x = x.wrapping_add(w.x);
        y = y.wrapping_add(w.y);
        hwnd = w.parent;
    }
    (x, y)
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetDCEx(hwnd: u32, region: u32, flags: u32) -> u32 {
    state::with(|s| {
        if hwnd != 0 && !s.windows.iter().any(|w| w.hwnd == hwnd) {
            return state::error(1400);
        }
        if region != 0 && flags & 0xc0 != 0 {
            let mut bounds = [0; 4];
            if unsafe { GetRgnBox(region, &mut bounds) } == 0 {
                return state::error(6);
            }
        }
        let (class, style) = s
            .windows
            .iter()
            .find(|w| w.hwnd == hwnd)
            .and_then(|w| s.classes.iter().find(|c| c.atom == w.class))
            .map_or((0, 0), |c| (c.atom, c.style));
        let persistent = flags & 2 == 0 && style & 0x60 != 0;
        let key_class = if persistent && style & 0x40 != 0 {
            class
        } else {
            0
        };
        let existing = s.dcs.iter().position(|d| {
            if persistent {
                d.persistent
                    && if key_class != 0 {
                        d.class == key_class
                    } else {
                        d.class == 0 && d.hwnd == hwnd
                    }
            } else {
                !d.persistent && !d.active
            }
        });
        let i = if let Some(i) = existing {
            i
        } else {
            let handle = unsafe { RetroSurfaceDC(hwnd, 0) };
            if handle == 0 {
                return 0;
            }
            s.dcs.push(WindowDc {
                hwnd,
                class: key_class,
                handle,
                persistent,
                active: false,
                owned_regions: Vec::new(),
                painting: false,
            });
            s.dcs.len() - 1
        };
        let changed = s.dcs[i].hwnd != hwnd;
        let dc = s.dcs[i].handle;
        unsafe {
            RetroSurfaceDC(hwnd, dc);
        }
        if !persistent {
            unsafe {
                SetROP2(dc, 13);
            }
        }
        if !persistent || changed || flags & 0xc0 != 0 {
            unsafe {
                SelectClipRgn(dc, 0);
            }
        }
        if flags & 0xc0 != 0 {
            let temp = full(s, hwnd);
            let copy = empty_region();
            let result = if region == 0 {
                if flags & 0x80 != 0 {
                    unsafe { CombineRgn(temp, temp, temp, 4) }
                } else {
                    2
                }
            } else {
                unsafe {
                    CombineRgn(copy, region, 0, 5);
                }
                let (x, y) = origin(s, hwnd);
                unsafe {
                    OffsetRgn(copy, -x, -y);
                    CombineRgn(temp, temp, copy, if flags & 0x80 != 0 { 1 } else { 4 })
                }
            };
            unsafe {
                DeleteObject(copy);
            }
            if result == 0 {
                unsafe {
                    DeleteObject(temp);
                }
                return 0;
            }
            unsafe {
                SelectClipRgn(dc, temp);
                DeleteObject(temp);
            }
            if let Some(at) = s.dcs[i]
                .owned_regions
                .iter()
                .position(|(owner, _)| *owner == hwnd)
            {
                let (_, old) = s.dcs[i].owned_regions.remove(at);
                if old != region {
                    unsafe {
                        DeleteObject(old);
                    }
                }
            }
            if flags & 0x40000 == 0 && region != 0 {
                s.dcs[i].owned_regions.push((hwnd, region));
            }
        }
        s.dcs[i].hwnd = hwnd;
        s.dcs[i].active = true;
        dc
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetDC(hwnd: u32) -> u32 {
    unsafe { GetDCEx(hwnd, 0, 0x10000) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetWindowDC(hwnd: u32) -> u32 {
    unsafe { GetDCEx(hwnd, 0, 1 | 0x10000) }
}
#[unsafe(no_mangle)]
pub extern "system" fn ReleaseDC(_hwnd: u32, dc: u32) -> i32 {
    state::with(|s| {
        let Some(d) = s.dcs.iter_mut().find(|d| d.handle == dc) else {
            return 0;
        };
        if d.persistent {
            return 1;
        }
        if !d.active {
            return 0;
        }
        d.active = false;
        for (_, region) in d.owned_regions.drain(..) {
            unsafe {
                DeleteObject(region);
            }
        }

        1
    })
}
unsafe fn update(hwnd: u32, rect: u32, region: u32, invalidate: bool, erase: bool) -> i32 {
    state::with(|s| {
        if !s.windows.iter().any(|w| w.hwnd == hwnd) {
            return state::error(1400) as i32;
        }
        let target = if region != 0 {
            let r = empty_region();
            if unsafe { CombineRgn(r, region, 0, 5) } == 0 {
                unsafe {
                    DeleteObject(r);
                }
                return 0;
            }
            r
        } else if rect != 0 {
            let b = unsafe { (rect as *const [i32; 4]).read_unaligned() };
            unsafe { CreateRectRgn(b[0], b[1], b[2], b[3]) }
        } else {
            full(s, hwnd)
        };
        let i = if let Some(i) = s.updates.iter().position(|u| u.hwnd == hwnd) {
            i
        } else {
            if !invalidate {
                unsafe {
                    DeleteObject(target);
                    RetroValidateWindow(hwnd);
                }
                return 1;
            }
            let region = empty_region();
            s.updates.push(Update {
                hwnd,
                region,
                erase: false,
            });
            s.updates.len() - 1
        };
        let result = unsafe {
            CombineRgn(
                s.updates[i].region,
                s.updates[i].region,
                target,
                if invalidate { 2 } else { 4 },
            )
        };
        unsafe {
            DeleteObject(target);
        }
        if invalidate {
            s.updates[i].erase |= erase;
            unsafe {
                RetroInvalidateWindow(hwnd, 0, u32::from(erase));
            }
        }
        if result == 1 {
            let u = s.updates.remove(i);
            unsafe {
                DeleteObject(u.region);
                RetroValidateWindow(hwnd);
            }
            for q in &mut s.queues {
                q.input.retain(|m| m.hwnd != hwnd || m.message != 0xf);
            }
        }
        i32::from(result != 0)
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn InvalidateRect(hwnd: u32, rect: u32, erase: u32) -> i32 {
    let result = unsafe { update(hwnd, rect, 0, true, erase != 0) };
    if result == 0 {
        return 0;
    }
    let children = state::with(|s| {
        s.windows
            .iter()
            .filter(|w| w.parent == hwnd && w.style & 0x10000000 != 0)
            .map(|w| (w.hwnd, w.x, w.y, w.width, w.height))
            .collect::<Vec<_>>()
    });
    for (child, x, y, width, height) in children {
        let r = if rect == 0 {
            [0, 0, width, height]
        } else {
            let r = unsafe { (rect as *const [i32; 4]).read_unaligned() };
            [
                (r[0] - x).max(0),
                (r[1] - y).max(0),
                (r[2] - x).min(width),
                (r[3] - y).min(height),
            ]
        };
        if r[0] < r[2] && r[1] < r[3] {
            unsafe {
                InvalidateRect(child, r.as_ptr() as u32, erase);
            }
        }
    }
    result
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn ValidateRect(hwnd: u32, rect: u32) -> i32 {
    unsafe { update(hwnd, rect, 0, false, false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn InvalidateRgn(hwnd: u32, region: u32, erase: u32) -> i32 {
    unsafe { update(hwnd, 0, region, true, erase != 0) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn ValidateRgn(hwnd: u32, region: u32) -> i32 {
    unsafe { update(hwnd, 0, region, false, false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetUpdateRgn(hwnd: u32, region: u32, _erase: u32) -> i32 {
    state::with(|s| {
        if let Some(u) = s.updates.iter().find(|u| u.hwnd == hwnd) {
            unsafe { CombineRgn(region, u.region, 0, 5) }
        } else {
            unsafe { CombineRgn(region, region, region, 4) }
        }
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetUpdateRect(hwnd: u32, out: u32, _erase: u32) -> i32 {
    state::with(|s| {
        let Some(u) = s.updates.iter().find(|u| u.hwnd == hwnd) else {
            if out != 0 {
                unsafe {
                    (out as *mut [i32; 4]).write_unaligned([0; 4]);
                }
            }
            return 0;
        };
        if out == 0 {
            return 1;
        }
        i32::from(unsafe { GetRgnBox(u.region, out as *mut [i32; 4]) } > 1)
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn BeginPaint(hwnd: u32, out: u32) -> u32 {
    if out == 0 {
        return 0;
    }
    let dc = unsafe { GetDC(hwnd) };
    if dc == 0 {
        return 0;
    }
    let erase = state::with(|s| {
        let (region, erase) = if let Some(i) = s.updates.iter().position(|u| u.hwnd == hwnd) {
            let u = s.updates.remove(i);
            (u.region, u.erase)
        } else {
            (empty_region(), false)
        };
        unsafe {
            SelectClipRgn(dc, region);
            DeleteObject(region);
            RetroValidateWindow(hwnd);
        }
        for q in &mut s.queues {
            q.input.retain(|m| m.hwnd != hwnd || m.message != 0xf);
        }
        if let Some(d) = s.dcs.iter_mut().find(|d| d.handle == dc) {
            d.painting = true;
        }
        erase
    });
    let mut words = [0u32; 16];
    words[0] = dc;
    unsafe {
        GetClipBox(dc, words.as_mut_ptr().add(2).cast());
    }
    words[1] = u32::from(erase);
    if erase && unsafe { crate::SendMessageW(hwnd, 0x14, dc, 0) } != 0 {
        words[1] = 0;
    }
    unsafe {
        (out as *mut [u32; 16]).write_unaligned(words);
    }
    dc
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn EndPaint(hwnd: u32, out: u32) -> i32 {
    if out == 0 {
        return 0;
    }
    let dc = unsafe { (out as *const u32).read_unaligned() };
    unsafe {
        SelectClipRgn(dc, 0);
        RetroEndPaint(hwnd, out);
    }
    state::with(|s| {
        if let Some(d) = s.dcs.iter_mut().find(|d| d.handle == dc) {
            d.painting = false;
        }
    });
    ReleaseDC(hwnd, dc)
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn UpdateWindow(hwnd: u32) -> i32 {
    if window::IsWindow(hwnd) == 0 {
        return 0;
    }
    let dirty = state::with(|s| s.updates.iter().any(|u| u.hwnd == hwnd));
    if dirty {
        unsafe {
            crate::SendMessageW(hwnd, 0xf, 0, 0);
        }
    }
    let children = state::with(|s| {
        s.windows
            .iter()
            .filter(|w| w.parent == hwnd && w.style & 0x10000000 != 0)
            .map(|w| w.hwnd)
            .collect::<Vec<_>>()
    });
    for child in children {
        unsafe {
            UpdateWindow(child);
        }
    }
    1
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RedrawWindow(hwnd: u32, rect: u32, region: u32, flags: u32) -> i32 {
    if hwnd != 0 && window::IsWindow(hwnd) == 0 {
        return state::error(1400) as i32;
    }
    let mut windows = if hwnd == 0 {
        state::with(|s| {
            s.windows
                .iter()
                .filter(|w| w.parent == 0)
                .map(|w| w.hwnd)
                .collect::<Vec<_>>()
        })
    } else {
        alloc::vec![hwnd]
    };
    if flags & 0x80 != 0 {
        let children = state::with(|s| s.windows.iter().map(|w| w.hwnd).collect::<Vec<_>>());
        for child in children {
            if window::IsChild(hwnd, child) != 0 {
                windows.push(child);
            }
        }
    }
    for window in windows {
        if flags & 1 != 0 {
            unsafe {
                update(window, rect, region, true, flags & 4 != 0);
            }
        }
        if flags & 8 != 0 {
            unsafe {
                update(window, rect, region, false, false);
            }
        }
        if flags & 0x100 != 0 {
            unsafe {
                UpdateWindow(window);
            }
        }
        if flags & 0x200 != 0 {
            let dc = unsafe { GetDC(window) };
            unsafe {
                crate::SendMessageW(window, 0x14, dc, 0);
            }
            ReleaseDC(window, dc);
        }
    }
    1
}
pub fn destroy(hwnd: u32) {
    let (handles, regions) = state::with(|s| {
        let class = s
            .windows
            .iter()
            .find(|w| w.hwnd == hwnd)
            .map_or(0, |w| w.class);
        let last = s.windows.iter().filter(|w| w.class == class).count() == 1;
        let handles = s
            .dcs
            .iter()
            .filter(|d| {
                d.persistent && (d.class == 0 && d.hwnd == hwnd || d.class == class && last)
            })
            .map(|d| d.handle)
            .collect::<Vec<_>>();
        let mut regions = Vec::new();
        for d in &mut s.dcs {
            d.owned_regions.retain(|&(owner, region)| {
                if owner == hwnd || handles.contains(&d.handle) {
                    regions.push(region);
                    false
                } else {
                    true
                }
            });
        }
        s.dcs.retain(|d| !handles.contains(&d.handle));
        if let Some(i) = s.updates.iter().position(|u| u.hwnd == hwnd) {
            regions.push(s.updates.remove(i).region);
        }
        (handles, regions)
    });
    for h in handles {
        unsafe {
            DeleteDC(h);
        }
    }
    for r in regions {
        unsafe {
            DeleteObject(r);
        }
    }
}
