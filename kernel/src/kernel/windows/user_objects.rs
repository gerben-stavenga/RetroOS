//! Named USER objects shared across Windows processes, with process-local handles.
use super::*;
mod paint;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU32, Ordering};

struct Object {
    name: Vec<u16>,
    kind: u32,
    parent: Option<Arc<Object>>,
    flags: AtomicU32,
    id: u64,
    offset: u64,
    windows: spin::Mutex<Vec<WindowRecord>>,
    cursor: spin::Mutex<Cursor>,
    monitors: spin::Mutex<(u64, Vec<u8>)>,
    foreground: Arc<spin::Mutex<user_queue::Foreground>>,
}
impl Drop for Object {
    fn drop(&mut self) {
        if self.offset != 0 {
            session::release_object(self.offset);
        }
    }
}
struct WindowRecord {
    handle: u32,
    offset: u64,
    _class: Arc<classes::Class>,
    properties: Vec<Property>,
    parent: u32,
    owner: u32,
    last_active: u32,
    tid: u32,
    pid: u32,
    style: u32,
    ex_style: u32,
    rect: [i32; 4],
    client_rect: [i32; 4],
    linked: bool,
    instance: u64,
    identifier: u64,
    userdata: u64,
    unicode: u32,
    extra: Vec<u8>,
    shape: Option<Vec<[i32; 4]>>,
    text: Vec<u16>,
    damage: paint::Damage,
}
impl WindowRecord {
    fn new<A: crate::Arch>(
        machine: &mut A,
        class: Arc<classes::Class>,
        owner: [u32; 2],
    ) -> Option<Self> {
        let id = next_id();
        let offset = session::allocate_object(machine, id);
        let mut data = [0u8; 24];
        data[..8].copy_from_slice(&class.id.to_le_bytes());
        data[8..16].copy_from_slice(&class.offset.to_le_bytes());
        // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE (Wine internal value).
        data[16..20].copy_from_slice(&0x12u32.to_le_bytes());
        session::write_object(offset, &data);
        let Some(handle) = session::allocate_user(machine, id, offset, 1, owner) else {
            session::release_object(offset);
            return None;
        };
        let desktop = class.is_desktop();
        Some(Self {
            parent: 0,
            owner: 0,
            last_active: handle,
            tid: owner[0],
            pid: owner[1],
            style: if desktop { 0x96000000 } else { 0x86000000 },
            ex_style: 0,
            rect: if desktop { [0, 0, 640, 480] } else { [0; 4] },
            client_rect: if desktop { [0, 0, 640, 480] } else { [0; 4] },
            linked: true,
            instance: 0,
            identifier: 0,
            userdata: 0,
            unicode: 1,
            extra: vec![0; class.win_extra as usize],
            shape: None,
            text: Vec::new(),
            damage: paint::Damage::default(),
            handle,
            offset,
            _class: class,
            properties: Vec::new(),
        })
    }
}
impl Drop for WindowRecord {
    fn drop(&mut self) {
        session::release_user(self.handle);
        session::release_object(self.offset);
    }
}
static NAMES: spin::Mutex<Vec<Weak<Object>>> = spin::Mutex::new(Vec::new());
static NEXT_ID: spin::Mutex<u64> = spin::Mutex::new(1);
pub(super) fn next_id() -> u64 {
    let mut next = NEXT_ID.lock();
    let id = *next;
    *next = next.checked_add(1).expect("user object ID exhausted");
    id
}
#[derive(Default)]
pub(super) struct State {
    handles: Vec<Option<Arc<Object>>>,
    station: u32,
    desktops: Vec<(u32, u32)>,
    client_handles: Vec<(u32, u16)>,
    cursors: Vec<(u32, u32, i32)>,
}
impl Drop for State {
    fn drop(&mut self) {
        for (handle, _) in self.client_handles.drain(..) {
            session::release_user(handle);
        }
    }
}
const BASE: u32 = 0x74000000;
impl State {
    fn get(&self, h: u32) -> Option<Arc<Object>> {
        h.checked_sub(BASE)
            .filter(|n| n % 4 == 0)
            .and_then(|n| self.handles.get(n as usize / 4))
            .and_then(Clone::clone)
    }
    fn insert(&mut self, object: Arc<Object>) -> u32 {
        let i = self
            .handles
            .iter()
            .position(Option::is_none)
            .unwrap_or(self.handles.len());
        if i == self.handles.len() {
            self.handles.push(Some(object));
        } else {
            self.handles[i] = Some(object);
        }
        BASE + i as u32 * 4
    }
}
pub(super) fn call<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    args: [u32; 6],
) -> u32 {
    let [op, handle, name, length, flags, out] = args;
    if op == 13 {
        if length > 40960 || length % 40 != 0 {
            return 0xc000000d;
        }
        let Some(station) = state.user_objects.get(state.user_objects.station) else {
            return 0xc0000022;
        };
        let mut data = vec![0u8; length as usize];
        machine.copy_from(name as usize, &mut data);
        let names = NAMES.lock();
        let mut monitors = station.monitors.lock();
        if flags != 0 || monitors.1 != data {
            monitors.0 += 1;
        }
        monitors.1 = data;
        for desktop in names
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|o| o.kind == 2 && o.parent.as_ref().is_some_and(|p| p.id == station.id))
        {
            session::write_object_part(desktop.offset, 288, &monitors.0.to_le_bytes());
        }
        machine.write::<u64>(out as usize, monitors.0);
        return 0;
    }
    if length > 510 || length & 1 != 0 {
        return 0xc000000d;
    }
    let tid = machine.read::<u32>((state.teb_base + 0x24) as usize);
    let mut object = None;
    let mut result = handle;
    let mut previous = 0;
    if op == 12 {
        let desktop = state
            .user_objects
            .desktops
            .iter()
            .find(|d| d.0 == tid)
            .and_then(|d| state.user_objects.get(d.1));
        let Some(desktop) = desktop else {
            return 0xc0000022;
        };
        let mut roots = desktop.windows.lock();
        if roots.is_empty() {
            let Some([top, message]) = state.classes.desktop_classes() else {
                return 0xc0010583;
            };
            let Some(top) = WindowRecord::new(machine, top, [0, 0]) else {
                return 0xc000009a;
            };
            let Some(message) = WindowRecord::new(machine, message, [0, 0]) else {
                return 0xc000009a;
            };
            roots.extend([top, message]);
        }
        machine.zero(out as usize, 544);
        machine.write::<u32>(out as usize, roots[0].handle);
        machine.write::<u32>(out as usize + 4, roots[1].handle);
        return 0;
    }
    if op == 0 {
        result = state.user_objects.station;
    } else if op == 7 {
        if handle != tid {
            return 0xc000000b;
        }
        result = state
            .user_objects
            .desktops
            .iter()
            .find(|d| d.0 == tid)
            .map_or(0, |d| d.1);
        object = state.user_objects.get(result);
    } else if matches!(op, 2 | 3 | 5 | 6 | 11) {
        let kind = if op == 11 {
            0
        } else if op <= 3 {
            1
        } else {
            2
        };
        let parent = if kind == 2 {
            let station = if handle != 0 {
                handle
            } else {
                state.user_objects.station
            };
            let Some(p) = state.user_objects.get(station).filter(|p| p.kind == 1) else {
                return 0xc0000008;
            };
            Some(p)
        } else {
            None
        };
        if kind == 1 && handle != 0 && state.user_objects.get(handle).is_none_or(|p| p.kind != 0) {
            return 0xc0000008;
        }
        let name: Vec<u16> = (0..length / 2)
            .map(|i| machine.read::<u16>((name + i * 2) as usize))
            .collect();
        if name.is_empty() {
            return 0xc0000033;
        }
        let canonical = alloc::string::String::from_utf16_lossy(&name).to_lowercase();
        let mut names = NAMES.lock();
        names.retain(|w| w.strong_count() != 0);
        let existing = names.iter().filter_map(Weak::upgrade).find(|o| {
            o.kind == kind
                && o.parent.as_ref().map(|p| p.id) == parent.as_ref().map(|p| p.id)
                && alloc::string::String::from_utf16_lossy(&o.name).to_lowercase() == canonical
        });
        let value = if let Some(o) = existing {
            if matches!(op, 2 | 5) && flags & 0x80 == 0 {
                return 0xc0000035;
            }
            o
        } else {
            if matches!(op, 3 | 6) {
                return 0xc0000034;
            }
            let id = next_id();
            let offset = if kind == 2 {
                let offset = session::allocate_object(machine, id);
                let mut shared = [0u8; 304];
                shared[24..28].copy_from_slice(&640i32.to_le_bytes());
                shared[28..32].copy_from_slice(&480i32.to_le_bytes());
                shared[288..296]
                    .copy_from_slice(&parent.as_ref().unwrap().monitors.lock().0.to_le_bytes());
                session::write_object(offset, &shared);
                offset
            } else {
                0
            };
            let o = Arc::new(Object {
                name,
                kind,
                parent,
                flags: AtomicU32::new(0),
                id,
                offset,
                windows: spin::Mutex::new(Vec::new()),
                cursor: spin::Mutex::new(Cursor::default()),
                monitors: spin::Mutex::new((1, Vec::new())),
                foreground: Arc::new(spin::Mutex::new(user_queue::Foreground::default())),
            });
            names.push(Arc::downgrade(&o));
            o
        };
        result = state.user_objects.insert(value.clone());
        object = Some(value);
    } else {
        let Some(o) = state.user_objects.get(handle) else {
            return 0xc0000008;
        };
        match op {
            1 if o.kind == 1 => {
                state.user_objects.station = handle;
            }
            8 if o.kind == 2 => {
                if o.parent.as_ref().map(|p| p.id)
                    != state
                        .user_objects
                        .get(state.user_objects.station)
                        .map(|p| p.id)
                {
                    return 0xc0000022;
                }
                if let Some(d) = state.user_objects.desktops.iter_mut().find(|d| d.0 == tid) {
                    d.1 = handle;
                } else {
                    state.user_objects.desktops.push((tid, handle));
                }
            }
            4 => {
                if handle == state.user_objects.station
                    || state.user_objects.desktops.iter().any(|d| d.1 == handle)
                {
                    return 0xc0000022;
                }
                state.user_objects.handles[((handle - BASE) / 4) as usize] = None;
                return 0;
            }
            9 => {
                previous = o.flags.load(Ordering::Relaxed);
            }
            10 => {
                previous = o.flags.swap(flags, Ordering::Relaxed);
            }
            _ => return 0xc0000024,
        }
        object = Some(o);
    }
    if out != 0 {
        machine.zero(out as usize, 32 + 512);
        machine.write::<u32>(out as usize, result);
        if let Some(o) = object {
            machine.write::<u32>(out as usize + 4, o.kind);
            machine.write::<u32>(out as usize + 8, previous);
            machine.write::<u32>(out as usize + 12, o.name.len() as u32 * 2);
            machine.write::<u64>(out as usize + 16, o.id);
            machine.write::<u64>(out as usize + 24, o.offset);
            for (i, c) in o.name.iter().enumerate() {
                machine.write::<u16>(out as usize + 32 + i * 2, *c);
            }
        }
    }
    0
}

struct Property {
    atom: u16,
    data: u64,
}
impl Drop for Property {
    fn drop(&mut self) {
        let _ = atoms::GLOBAL.lock().delete(self.atom);
    }
}

/// Window property storage; names and numeric global atoms address the same key.
pub(super) fn window_call<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    args: [u32; 6],
) -> u32 {
    let [op, handle, name, length, atom, data] = args;
    if op == 3 || op == 4 {
        // Window records have separate ownership; these are Wine client objects.
        if !matches!(atom, 2 | 3 | 4 | 8 | 15 | 17) {
            return 0xc000000d;
        }
        if op == 3 {
            let owner = [
                machine.read::<u32>((state.teb_base + 0x24) as usize),
                machine.read::<u32>((state.teb_base + 0x20) as usize),
            ];
            let Some(handle) = session::allocate_user(machine, 0, 0, atom as u16, owner) else {
                return 0xc000009a;
            };
            state
                .user_objects
                .client_handles
                .push((handle, atom as u16));
            machine.write::<u32>(data as usize, handle);
        } else {
            let Some(i) = state
                .user_objects
                .client_handles
                .iter()
                .position(|&(h, kind)| {
                    kind == atom as u16
                        && (h == handle
                            || ((handle >> 16 == 0 || handle >> 16 == 0xffff)
                                && h as u16 == handle as u16))
                })
            else {
                return 0xc0000008;
            };
            let (handle, _) = state.user_objects.client_handles.swap_remove(i);
            session::release_user(handle);
        }
        return 0;
    }
    if (op > 2 && op != 5) || length > 510 || length & 1 != 0 || atom > 0xffff {
        return 0xc000000d;
    }
    let tid = machine.read::<u32>((state.teb_base + 0x24) as usize);
    let desktop = state
        .user_objects
        .desktops
        .iter()
        .find(|d| d.0 == tid)
        .and_then(|d| state.user_objects.get(d.1));
    let Some(desktop) = desktop else {
        return 0xc0000022;
    };
    let mut roots = desktop.windows.lock();
    let Some(index) = roots.iter().position(|w| matches_handle(w.handle, handle)) else {
        return 0xc0010578;
    };
    if op == 5 {
        let w = &roots[index];
        let siblings: Vec<u32> = roots
            .iter()
            .filter(|x| x.linked && x.parent == w.parent)
            .map(|x| x.handle)
            .collect();
        let children: Vec<u32> = roots
            .iter()
            .filter(|x| x.linked && x.parent == w.handle)
            .map(|x| x.handle)
            .collect();
        let si = siblings.iter().position(|&h| h == w.handle);
        let tree = [
            w.parent,
            w.owner,
            si.and_then(|i| siblings.get(i + 1)).copied().unwrap_or(0),
            si.and_then(|i| i.checked_sub(1))
                .and_then(|i| siblings.get(i))
                .copied()
                .unwrap_or(0),
            siblings.first().copied().unwrap_or(0),
            siblings.last().copied().unwrap_or(0),
            children.first().copied().unwrap_or(0),
            children.last().copied().unwrap_or(0),
        ];
        let header = [
            w.handle,
            w.style,
            w.ex_style,
            w.parent,
            w.owner,
            (w.rect[2] - w.rect[0]) as u32,
            (w.rect[3] - w.rect[1]) as u32,
            w.unicode,
        ];
        for (i, n) in header
            .into_iter()
            .chain(w.rect.map(|n| n as u32))
            .chain(w.client_rect.map(|n| n as u32))
            .chain(tree)
            .enumerate()
        {
            machine.write::<u32>(data as usize + i * 4, n);
        }
        let mut origin = [0i32; 2];
        let mut parent = w.parent;
        while let Some(p) = roots.iter().find(|p| p.handle == parent) {
            origin[0] = origin[0].saturating_add(p.client_rect[0]);
            origin[1] = origin[1].saturating_add(p.client_rect[1]);
            parent = p.parent;
        }
        for (i, n) in w.rect.into_iter().chain(w.client_rect).enumerate() {
            machine.write::<i32>(data as usize + 96 + i * 4, n.saturating_add(origin[i % 2]));
        }
        return 0;
    }
    let window = &mut roots[index];
    let mut table = atoms::GLOBAL.lock();
    let key = if length != 0 {
        let units: Vec<u16> = (0..length / 2)
            .map(|i| machine.read::<u16>((name + i * 2) as usize))
            .collect();
        let Ok(name) = alloc::string::String::from_utf16(&units) else {
            return 0xc000000d;
        };
        table.lookup(&name, op == 1)
    } else if op == 1 {
        table
            .name(atom as u16)
            .and_then(|name| table.lookup(&name, true))
    } else {
        Ok(atom as u16)
    };
    let key = match key {
        Ok(key) => key,
        Err(_) if op != 1 => {
            machine.write::<u64>(data as usize, 0);
            return 0;
        }
        Err(_) => return 0xc000000d,
    };
    let index = window.properties.iter().position(|p| p.atom == key);
    if op == 1 {
        let value = machine.read::<u64>(data as usize);
        if let Some(i) = index {
            window.properties[i].data = value;
            let _ = table.delete(key); // release temporary lookup reference
        } else {
            window.properties.push(Property {
                atom: key,
                data: value,
            });
        }
    } else {
        let value = index.map_or(0, |i| window.properties[i].data);
        drop(table); // removing a Property releases its atom reference
        if op == 2 {
            if let Some(i) = index {
                window.properties.swap_remove(i);
            }
        }
        machine.write::<u64>(data as usize, value);
    }
    0
}

fn matches_handle(full: u32, h: u32) -> bool {
    full == h || ((h >> 16 == 0 || h >> 16 == 0xffff) && full as u16 == h as u16)
}

pub(super) fn tree_call<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    args: [u32; 3],
) -> u32 {
    let [op, params, out] = args;
    let p: [u32; 16] = core::array::from_fn(|i| machine.read::<u32>(params as usize + i * 4));
    let tid = machine.read::<u32>((state.teb_base + 0x24) as usize);
    let pid = machine.read::<u32>((state.teb_base + 0x20) as usize);
    let desktop = if op == 2 && p[0] != 0 {
        state.user_objects.get(p[0]).filter(|o| o.kind == 2)
    } else {
        state
            .user_objects
            .desktops
            .iter()
            .find(|d| d.0 == tid)
            .and_then(|d| state.user_objects.get(d.1))
    };
    let Some(desktop) = desktop else {
        return 0xc0000008;
    };
    let mut windows = desktop.windows.lock();
    machine.zero(out as usize, 32);
    match op {
        13 | 14 => return paint::call(machine, &mut windows, op, p, out),
        // No layered attributes have been set: Wine expects this error for
        // ordinary windows (and falls back to their normal opaque surface).
        15 => return 0xc0010578,

        0 => {
            if windows.len() < 2 {
                return 0xc0000022;
            }
            if p[12] > 510 || p[12] & 1 != 0 {
                return 0xc000000d;
            }
            let name: Vec<u16> = (0..p[12] / 2)
                .map(|i| machine.read::<u16>((p[11] + i * 2) as usize))
                .collect();
            let Some(class) = state
                .classes
                .find(p[2], &name, p[3] as u64 | ((p[4] as u64) << 32))
            else {
                return 0xc0010583;
            };
            let parent = if p[0] == 0 {
                windows[0].handle
            } else if p[0] == 0xfffffffd {
                windows[1].handle
            } else if let Some(w) = windows.iter().find(|w| matches_handle(w.handle, p[0])) {
                w.handle
            } else {
                return 0xc0010578;
            };
            let owner = if p[1] == 0 {
                0
            } else if let Some(w) = windows.iter().find(|w| matches_handle(w.handle, p[1])) {
                w.handle
            } else {
                return 0xc0010578;
            };
            let Some(mut window) = WindowRecord::new(machine, class.clone(), [tid, pid]) else {
                return 0xc000009a;
            };
            window.instance = p[5] as u64 | ((p[6] as u64) << 32);
            window.parent = parent;
            window.owner = owner;
            window.style = p[8];
            window.ex_style = p[9];
            window.rect = [0; 4];
            window.client_rect = [0; 4];
            window.linked = false;
            let mut shared = [0u8; 24];
            shared[..8].copy_from_slice(&class.id.to_le_bytes());
            shared[8..16].copy_from_slice(&class.offset.to_le_bytes());
            shared[16..20].copy_from_slice(&p[7].to_le_bytes());
            session::write_object(window.offset, &shared);
            for (i, n) in [window.handle, parent, owner, class.win_extra]
                .into_iter()
                .enumerate()
            {
                machine.write::<u32>(out as usize + i * 4, n);
            }
            machine.write::<u64>(out as usize + 16, class.client);
            windows.push(window);
        }
        1 => {
            let Some(i) = windows.iter().position(|w| matches_handle(w.handle, p[0])) else {
                return 0xc0010578;
            };
            if i < 2 || windows[i].pid != pid {
                return 0xc0000022;
            }
            let mut removed = vec![windows[i].handle];
            let mut cursor = 0;
            while cursor < removed.len() {
                for w in windows.iter() {
                    if w.parent == removed[cursor] {
                        removed.push(w.handle);
                    }
                }
                cursor += 1;
            }
            user_queue::remove_windows(&mut state.user_queues, &removed);
            state.windows.retain(|w| !removed.contains(&w.hwnd));
            state.dirty = true;
            windows.retain(|w| !removed.contains(&w.handle));
            for w in windows.iter_mut() {
                if removed.contains(&w.last_active) {
                    w.last_active = w.handle;
                }
                if removed.contains(&w.owner) {
                    w.owner = 0;
                }
            }
        }
        2 => {
            if p[2] != 0 && p[2] != tid {
                return 0xc0000008;
            }
            let index = if p[1] == 0 {
                None
            } else {
                let Some(i) = windows.iter().position(|w| matches_handle(w.handle, p[1])) else {
                    return 0xc0000008;
                };
                Some(i)
            };
            let mut list = Vec::new();
            if !(p[0] != 0 && p[3] != 0) && !windows.is_empty() {
                if p[0] != 0 || index.is_none() {
                    let root = windows[0].handle;
                    list.extend(
                        windows
                            .iter()
                            .filter(|w| w.linked && w.parent == root)
                            .map(|w| w.handle),
                    );
                } else if p[3] != 0 {
                    let mut pending = vec![windows[index.unwrap()].handle];
                    while let Some(parent) = pending.pop() {
                        let children: Vec<u32> = windows
                            .iter()
                            .filter(|w| w.linked && w.parent == parent)
                            .map(|w| w.handle)
                            .collect();
                        if parent != windows[index.unwrap()].handle {
                            list.push(parent);
                        }
                        pending.extend(children.into_iter().rev());
                    }
                } else {
                    let i = index.unwrap();
                    let parent = windows[i].parent;
                    list.extend(
                        windows[i..]
                            .iter()
                            .filter(|w| w.linked && w.parent == parent)
                            .map(|w| w.handle),
                    );
                }
                if p[2] != 0 {
                    list.retain(|h| windows.iter().any(|w| w.handle == *h && w.tid == p[2]));
                }
            }
            machine.write::<u32>(out as usize, list.len() as u32);
            if list.len() > p[4] as usize {
                return 0xc0000023;
            }
            for (i, h) in list.into_iter().enumerate() {
                machine.write::<u32>(p[5] as usize + i * 4, h);
            }
        }
        3 => {
            let Some(i) = windows.iter().position(|w| matches_handle(w.handle, p[0])) else {
                return 0xc0010578;
            };
            if windows[i].pid != pid {
                return 0xc0000022;
            }
            if p[2] & 4 == 0
                && !matches!(p[1], 0 | 1 | 0xffffffff | 0xfffffffe)
                && !windows
                    .iter()
                    .any(|w| matches_handle(w.handle, p[1]) && w.parent == windows[i].parent)
            {
                return 0xc0010578;
            }
            let w = &mut windows[i];
            if p[2] & 4 == 0 {
                if p[1] == 0xffffffff {
                    w.ex_style |= 8;
                } else if p[1] == 0xfffffffe {
                    w.ex_style &= !8;
                }
            }
            let old_rect = w.rect;
            w.rect = core::array::from_fn(|i| p[4 + i] as i32);
            w.client_rect = core::array::from_fn(|i| p[8 + i] as i32);
            if p[2] & 0x40 != 0 {
                w.style |= 0x10000000;
            }
            if p[2] & 0x80 != 0 {
                w.style &= !0x10000000;
            }
            w.linked = true;
            paint::positioned(w, old_rect, p[2]);
            machine.write::<u32>(out as usize, w.style);
            machine.write::<u32>(out as usize + 4, w.ex_style);
            machine.write::<u32>(out as usize + 8, w.handle);
            if p[2] & 4 == 0 && !matches_handle(w.handle, p[1]) {
                let w = windows.remove(i);
                let insert = match p[1] {
                    1 => windows
                        .iter()
                        .rposition(|x| x.parent == w.parent)
                        .map_or(windows.len(), |i| i + 1),
                    0 | 0xffffffff | 0xfffffffe => windows
                        .iter()
                        .position(|x| x.parent == w.parent)
                        .unwrap_or(windows.len()),
                    h => windows
                        .iter()
                        .position(|x| matches_handle(x.handle, h))
                        .map_or(windows.len(), |i| i + 1),
                };
                windows.insert(insert.max(2), w);
            }
        }
        4 | 5 | 6 => {
            let Some(i) = windows.iter().position(|w| matches_handle(w.handle, p[0])) else {
                return 0xc0010578;
            };
            if op != 5 && (i < 2 || windows[i].pid != pid) {
                return 0xc0000022;
            }
            let w = &mut windows[i];
            if op == 4 {
                w.style = p[1];
                w.ex_style = p[2];
                w.unicode = p[3];
                return 0;
            }
            let value = p[3] as u64 | ((p[4] as u64) << 32);
            let offset = p[1] as i32;
            let old = match offset {
                -16 => w.style as u64,
                -20 => w.ex_style as u64,
                -12 => w.identifier,
                -6 => w.instance,
                -4 => w.unicode as u64,
                -21 => w.userdata,
                n if n >= 0
                    && p[2] <= 8
                    && (n as usize)
                        .checked_add(p[2] as usize)
                        .is_some_and(|end| end <= w.extra.len()) =>
                {
                    let mut bytes = [0u8; 8];
                    bytes[..p[2] as usize]
                        .copy_from_slice(&w.extra[n as usize..n as usize + p[2] as usize]);
                    u64::from_le_bytes(bytes)
                }
                _ => return 0xc0010585,
            };
            machine.write::<u64>(out as usize, old);
            machine.write::<u32>(out as usize + 8, w.unicode);
            machine.write::<u32>(out as usize + 12, w.last_active);
            if op == 6 {
                match offset {
                    -16 => w.style = value as u32,
                    -20 => w.ex_style = value as u32,
                    -12 => w.identifier = value,
                    -6 => w.instance = value,
                    -4 => w.unicode = value as u32,
                    -21 => w.userdata = value,
                    n => w.extra[n as usize..n as usize + p[2] as usize]
                        .copy_from_slice(&value.to_le_bytes()[..p[2] as usize]),
                }
            }
        }
        7 | 8 => {
            let Some(i) = windows.iter().position(|w| matches_handle(w.handle, p[0])) else {
                return 0xc0010578;
            };
            let w = &mut windows[i];
            if op == 8 {
                if w.pid != pid {
                    return 0xc0000022;
                }
                if p[3] % 16 != 0 || p[3] > 16 * 1024 * 1024 {
                    return 0xc000000d;
                }
                if w.ex_style & 0x400000 != 0 {
                    return 0xc00000bb;
                }
                if p[3] == 0 {
                    w.shape = None;
                    return 0;
                }
                let mut region = Vec::new();
                for i in 0..p[3] / 16 {
                    let r: [i32; 4] = core::array::from_fn(|j| {
                        machine.read::<i32>(p[2] as usize + i as usize * 16 + j * 4)
                    });
                    if r[0] > r[2] || r[1] > r[3] {
                        return 0xc000000d;
                    }
                    if r[0] < r[2] && r[1] < r[3] {
                        region.push(r);
                    }
                }
                w.shape = Some(region);
                return 0;
            }
            for (i, n) in w.rect.into_iter().enumerate() {
                machine.write::<i32>(out as usize + i * 4, n);
            }
            if p[1] != 0 && w.style & 0x10000000 == 0 {
                return 0;
            }
            let mut region = if p[1] == 0 {
                let Some(shape) = w.shape.as_ref() else {
                    return 0;
                };
                shape.clone()
            } else if let Some(shape) = w.shape.as_ref() {
                shape
                    .iter()
                    .filter_map(|r| {
                        let r = [
                            r[0].saturating_add(w.rect[0]).max(w.rect[0]),
                            r[1].saturating_add(w.rect[1]).max(w.rect[1]),
                            r[2].saturating_add(w.rect[0]).min(w.rect[2]),
                            r[3].saturating_add(w.rect[1]).min(w.rect[3]),
                        ];
                        (r[0] < r[2] && r[1] < r[3]).then_some(r)
                    })
                    .collect()
            } else {
                vec![w.rect]
            };
            if region.is_empty() {
                region.push([0; 4]);
            }
            let bytes = region.len() * 16;
            machine.write::<u32>(out as usize + 16, bytes as u32);
            if bytes > p[3] as usize {
                return 0x80000005;
            }
            for (i, r) in region.iter().enumerate() {
                for (j, n) in r.iter().enumerate() {
                    machine.write::<i32>(p[2] as usize + i * 16 + j * 4, *n);
                }
            }
        }
        12 => {
            let Some(i) = windows.iter().position(|w| matches_handle(w.handle, p[0])) else {
                return 0xc0010578;
            };
            if i < 2 || windows[i].pid != pid {
                return 0xc0000022;
            }
            let parent = if p[1] == 0 {
                None
            } else {
                let Some(j) = windows.iter().position(|w| matches_handle(w.handle, p[1])) else {
                    return 0xc0010578;
                };
                if windows[j].tid != 0 && windows[j].tid != windows[i].tid {
                    return 0xc00000bb; // Cross-thread input attachment is not implemented.
                }
                let mut ancestor = windows[j].handle;
                while let Some(w) = windows.iter().find(|w| w.handle == ancestor) {
                    if w.handle == windows[i].handle {
                        return 0xc000000d;
                    }
                    ancestor = w.parent;
                }
                Some(windows[j].handle)
            };
            machine.write::<u32>(out as usize, windows[i].parent);
            machine.write::<u32>(out as usize + 4, parent.unwrap_or(0));
            if let Some(parent) = parent {
                let mut w = windows.remove(i);
                w.parent = parent;
                w.linked = true;
                windows.insert(2, w);
            } else {
                // Wine keeps the parent reference while moving to its unlinked list.
                windows[i].linked = false;
            }
        }
        10 | 11 => {
            let Some(w) = windows.iter_mut().find(|w| matches_handle(w.handle, p[0])) else {
                return 0xc0010578;
            };
            if op == 11 {
                if p[2] > 16 * 1024 * 1024 {
                    return 0xc000000d;
                }
                w.text = (0..p[2] / 2)
                    .map(|i| machine.read::<u16>(p[1] as usize + i as usize * 2))
                    .collect();
            } else {
                let bytes = (w.text.len() * 2).min(p[2] as usize);
                machine.write::<u32>(out as usize, w.text.len() as u32);
                machine.write::<u32>(out as usize + 4, bytes as u32);
                for i in 0..bytes {
                    machine.write::<u8>(p[1] as usize + i, w.text[i / 2].to_le_bytes()[i % 2]);
                }
            }
        }
        9 => {
            let Some(index) = windows.iter().position(|w| matches_handle(w.handle, p[0])) else {
                return 0xc0010578;
            };
            let scale = |v: u32| -> i32 {
                if p[3] == 0 {
                    v as i32
                } else {
                    ((v as i32 as i64) * 96 / p[3] as i64).clamp(i32::MIN as i64, i32::MAX as i64)
                        as i32
                }
            };
            let mut x = scale(p[1]);
            let mut y = scale(p[2]);
            let mut parent = windows[index].parent;
            while let Some(w) = windows.iter().find(|w| w.handle == parent) {
                x = x.saturating_sub(w.client_rect[0]);
                y = y.saturating_sub(w.client_rect[1]);
                parent = w.parent;
            }
            let inside =
                |r: [i32; 4], x: i32, y: i32| r[0] <= x && x < r[2] && r[1] <= y && y < r[3];
            let mut pending = vec![(index, x, y, false)];
            let mut hits = Vec::new();
            while let Some((i, x, y, visited)) = pending.pop() {
                let w = &windows[i];
                if visited {
                    hits.push(w.handle);
                    continue;
                }
                if !w.linked
                    || w.style & 0x10000000 == 0
                    || w.style & 0xc8000000 == 0x48000000
                    || w.ex_style & 0x80020 == 0x80020
                    || !inside(w.rect, x, y)
                {
                    continue;
                }
                if let Some(shape) = &w.shape {
                    if !shape.iter().any(|r| {
                        inside(*r, x.saturating_sub(w.rect[0]), y.saturating_sub(w.rect[1]))
                    }) {
                        continue;
                    }
                }
                pending.push((i, x, y, true));
                if w.style & 0x28000000 == 0 && inside(w.client_rect, x, y) {
                    for (j, c) in windows.iter().enumerate().rev() {
                        if c.parent == w.handle {
                            pending.push((
                                j,
                                x.saturating_sub(w.client_rect[0]),
                                y.saturating_sub(w.client_rect[1]),
                                false,
                            ));
                        }
                    }
                }
            }
            machine.write::<u32>(out as usize, hits.len() as u32);
            for (i, h) in hits.iter().take(p[5] as usize).enumerate() {
                machine.write::<u32>(p[4] as usize + i * 4, *h);
            }
        }
        _ => return 0xc000000d,
    }
    0
}

struct Cursor {
    x: i32,
    y: i32,
    clip: [i32; 4],
    changed: u32,
}
pub(super) fn input_cursor(state: &WindowsState, tid: u32) -> (u32, i32) {
    state
        .user_objects
        .cursors
        .iter()
        .find(|c| c.0 == tid)
        .map_or((0, 0), |c| (c.1, c.2))
}
impl Default for Cursor {
    fn default() -> Self {
        Self {
            x: 0,
            y: 0,
            clip: [0, 0, 640, 480],
            changed: 0,
        }
    }
}
pub(super) fn cursor_call<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    args: [u32; 2],
) -> u32 {
    let [params, out] = args;
    let p: [u32; 9] = core::array::from_fn(|i| machine.read::<u32>(params as usize + i * 4));
    if p[0] & !0x3f != 0 {
        return 0xc000000d;
    }
    let tid = machine.read::<u32>((state.teb_base + 0x24) as usize);
    let Some(desktop) = state
        .user_objects
        .desktops
        .iter()
        .find(|d| d.0 == tid)
        .and_then(|d| state.user_objects.get(d.1))
    else {
        return 0xc0000022;
    };
    if p[0] & 1 != 0
        && p[1] != 0
        && !state
            .user_objects
            .client_handles
            .iter()
            .any(|&(h, k)| k == 3 && matches_handle(h, p[1]))
    {
        return 0xc001057a;
    }
    let requested_clip = [
        (p[5] as i32).max(0),
        (p[6] as i32).max(0),
        (p[7] as i32).min(640),
        (p[8] as i32).min(480),
    ];
    if p[0] & 8 != 0
        && (requested_clip[0] >= requested_clip[2] || requested_clip[1] >= requested_clip[3])
    {
        return 0xc000000d;
    }
    let index = if let Some(i) = state.user_objects.cursors.iter().position(|c| c.0 == tid) {
        i
    } else {
        state.user_objects.cursors.push((tid, 0, 0));
        state.user_objects.cursors.len() - 1
    };
    let input = &mut state.user_objects.cursors[index];
    let mut cursor = desktop.cursor.lock();
    let old = [input.1, input.2 as u32, cursor.x as u32, cursor.y as u32];
    if p[0] & 1 != 0 {
        input.1 = p[1];
    }
    if p[0] & 2 != 0 {
        input.2 = input.2.saturating_add(p[2] as i32);
    }
    user_queue::set_cursor(&mut state.user_queues, tid, input.1, input.2);
    if p[0] & 8 != 0 {
        cursor.clip = requested_clip;
    }
    if p[0] & 16 != 0 {
        cursor.clip = [0, 0, 640, 480];
    }
    if p[0] & 4 != 0 {
        cursor.x = p[3] as i32;
        cursor.y = p[4] as i32;
    }
    cursor.x = cursor.x.clamp(cursor.clip[0], cursor.clip[2] - 1);
    cursor.y = cursor.y.clamp(cursor.clip[1], cursor.clip[3] - 1);
    if cursor.x as u32 != old[2] || cursor.y as u32 != old[3] {
        cursor.changed = (machine.now() / 1_000_000) as u32;
    }
    let mut shared = [0u8; 32];
    for (i, n) in [cursor.x as u32, cursor.y as u32, cursor.changed]
        .into_iter()
        .chain(cursor.clip.map(|n| n as u32))
        .enumerate()
    {
        shared[4 + i * 4..8 + i * 4].copy_from_slice(&n.to_le_bytes());
    }
    session::write_object(desktop.offset, &shared);
    for (i, n) in old
        .into_iter()
        .chain([cursor.x as u32, cursor.y as u32])
        .chain(cursor.clip.map(|n| n as u32))
        .chain([cursor.changed])
        .enumerate()
    {
        machine.write::<u32>(out as usize + i * 4, n);
    }
    state.mouse_x = cursor.x;
    state.mouse_y = cursor.y;
    0
}

pub(super) fn window_owner(state: &WindowsState, tid: u32, handle: u32) -> Option<(u32, u32, u32)> {
    let desktop = state
        .user_objects
        .desktops
        .iter()
        .find(|d| d.0 == tid)
        .and_then(|d| state.user_objects.get(d.1))?;
    let windows = desktop.windows.lock();
    windows
        .iter()
        .find(|w| matches_handle(w.handle, handle))
        .map(|w| (w.handle, w.tid, w.pid))
}
pub(super) fn window_filter(state: &WindowsState, tid: u32, handle: u32) -> Option<Vec<u32>> {
    let desktop = state
        .user_objects
        .desktops
        .iter()
        .find(|d| d.0 == tid)
        .and_then(|d| state.user_objects.get(d.1))?;
    let windows = desktop.windows.lock();
    let root = windows
        .iter()
        .find(|w| matches_handle(w.handle, handle))?
        .handle;
    let mut result = vec![root];
    let mut index = 0;
    while index < result.len() {
        for w in windows.iter() {
            if w.parent == result[index] {
                result.push(w.handle);
            }
        }
        index += 1;
    }
    Some(result)
}

pub(super) fn pending_paints(state: &WindowsState) -> Vec<(u32, u32)> {
    let mut result = Vec::new();
    for &(tid, handle) in &state.user_objects.desktops {
        let Some(desktop) = state.user_objects.get(handle) else {
            continue;
        };
        let windows = desktop.windows.lock();
        for (i, w) in windows.iter().enumerate() {
            if w.tid == tid
                && paint::visible(&windows, i)
                && (!w.damage.region.is_empty() || w.damage.flags & 8 != 0)
            {
                result.push((tid, w.handle));
            }
        }
    }
    result
}
pub(super) fn consume_internal_paint(state: &WindowsState, tid: u32, hwnd: u32) {
    let Some(desktop) = state
        .user_objects
        .desktops
        .iter()
        .find(|d| d.0 == tid)
        .and_then(|d| state.user_objects.get(d.1))
    else {
        return;
    };
    if let Some(w) = desktop.windows.lock().iter_mut().find(|w| w.handle == hwnd) {
        w.damage.flags &= !8;
    }
}

pub(super) fn foreground(
    state: &WindowsState,
    tid: u32,
) -> Option<Arc<spin::Mutex<user_queue::Foreground>>> {
    let desktop = state
        .user_objects
        .desktops
        .iter()
        .find(|d| d.0 == tid)
        .and_then(|d| state.user_objects.get(d.1))?;
    Some(desktop.foreground.clone())
}
pub(super) fn foreground_window(
    state: &WindowsState,
    tid: u32,
    handle: u32,
) -> Option<(u32, u32, u32, bool)> {
    let desktop = state
        .user_objects
        .desktops
        .iter()
        .find(|d| d.0 == tid)
        .and_then(|d| state.user_objects.get(d.1))?;
    let windows = desktop.windows.lock();
    let w = windows.iter().find(|w| matches_handle(w.handle, handle))?;
    if w.style & 0xc0000000 == 0x40000000 {
        return None;
    }
    Some((w.handle, w.tid, w.pid, w.parent == 0))
}

pub(super) fn mark_active(state: &WindowsState, tid: u32, handle: u32) {
    let Some(desktop) = state
        .user_objects
        .desktops
        .iter()
        .find(|d| d.0 == tid)
        .and_then(|d| state.user_objects.get(d.1))
    else {
        return;
    };
    let mut windows = desktop.windows.lock();
    let mut owner = handle;
    for _ in 0..windows.len() {
        let Some(w) = windows.iter_mut().find(|w| w.handle == owner) else {
            break;
        };
        w.last_active = handle;
        owner = w.owner;
    }
}

/// Publish asynchronous physical state; the queue keeps its own consumed state.
pub(super) fn keyboard_state(state:&WindowsState, tid:u32, keys:&[u8;256]) {
    if let Some(desktop)=state.user_objects.desktops.iter().find(|d| d.0==tid).and_then(|d| state.user_objects.get(d.1)) {
        session::write_object_part(desktop.offset,32,keys);
    }
}
