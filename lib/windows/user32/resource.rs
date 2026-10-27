//! Resource decoding and USER handles stay in the DLL. Pixel storage is a GDI
//! service; PE directory traversal is provided by guest KERNEL32.
use crate::{Message, state, text};
use alloc::{vec, vec::Vec};
unsafe extern "system" {
    fn FindResourceA(module: u32, name: u32, kind: u32) -> u32;
    fn FindResourceW(module: u32, name: u32, kind: u32) -> u32;
    fn LoadResource(module: u32, info: u32) -> u32;
    fn SizeofResource(module: u32, info: u32) -> u32;
    fn CreateBitmap(width: i32, height: i32, planes: u32, depth: u32, bits: *const u8) -> u32;
    fn GetKeyState(key: u32) -> i32;
    fn CreateCompatibleDC(dc: u32) -> u32;
    fn SelectObject(dc: u32, object: u32) -> u32;
    fn DeleteObject(object: u32) -> i32;
    fn DeleteDC(dc: u32) -> i32;
    fn BitBlt(
        dst: u32,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        src: u32,
        sx: i32,
        sy: i32,
        rop: u32,
    ) -> i32;
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Accel {
    flags: u8,
    pad: u8,
    key: u16,
    command: u16,
}
pub enum Resource {
    Accelerators(Vec<Accel>),
    Image {
        module: u32,
        name: Vec<u16>,
        kind: u32,
        shared: bool,
        _bytes: Vec<u8>,
        icon: Option<(i32, i32, Vec<u8>, Vec<u8>)>,
    },
}
pub(crate) unsafe fn bytes(module: u32, name: u32, kind: u32, wide: bool) -> Option<&'static [u8]> {
    if crate::win16_resource::instance(module) {
        return unsafe { crate::win16_resource::bytes(kind as u16, name, wide) };
    }
    let info = unsafe {
        if wide {
            FindResourceW(module, name, kind)
        } else {
            FindResourceA(module, name, kind)
        }
    };
    if info == 0 {
        return None;
    }
    let data = unsafe { LoadResource(module, info) };
    let size = unsafe { SizeofResource(module, info) };
    if data == 0 {
        return None;
    }
    Some(unsafe { core::slice::from_raw_parts(data as *const u8, size as usize) })
}
fn add(resource: Resource) -> u32 {
    state::with(|s| {
        let handle = s.next_resource;
        s.next_resource += 1;
        s.resources.push((handle, resource));
        handle
    })
}
unsafe fn create_accel(input: *const Accel, count: i32, wide: bool) -> u32 {
    if count <= 0 || count > 0x7fff || input.is_null() {
        return state::error(87);
    }
    let mut entries = Vec::new();
    for i in 0..count as usize {
        let mut entry = unsafe { input.add(i).read_unaligned() };
        entry.flags &= 0x7f;
        entry.pad = 0;
        if !wide && entry.flags & 1 == 0 {
            let input = [entry.key as u8, 0];
            entry.key = unsafe { text::read(input.as_ptr() as u32, false) }
                .first()
                .copied()
                .unwrap_or(0);
        }
        entries.push(entry);
    }
    add(Resource::Accelerators(entries))
}
unsafe fn copy_accel(handle: u32, out: *mut Accel, count: i32, wide: bool) -> i32 {
    state::with(|s| {
        let Some((_, Resource::Accelerators(entries))) =
            s.resources.iter().find(|(h, _)| *h == handle)
        else {
            return state::error(1403) as i32;
        };
        if out.is_null() {
            return entries.len() as i32;
        }
        let count = entries.len().min(count.max(0) as usize);
        for (i, entry) in entries[..count].iter().enumerate() {
            let mut entry = *entry;
            if !wide && entry.flags & 1 == 0 {
                entry.key = text::ansi(&[entry.key]).first().copied().unwrap_or(0) as u16;
            }
            unsafe {
                out.add(i).write_unaligned(entry);
            }
        }
        count as i32
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn DestroyAcceleratorTable(handle: u32) -> i32 {
    state::with(|s| {
        let Some(i) = s
            .resources
            .iter()
            .position(|(h, r)| *h == handle && matches!(r, Resource::Accelerators(_)))
        else {
            return 0;
        };
        s.resources.remove(i);
        1
    })
}
unsafe fn load_accel(module: u32, name: u32, wide: bool) -> u32 {
    let Some(data) = (unsafe { bytes(module, name, 9, wide) }) else {
        return 0;
    };
    let mut entries = Vec::new();
    for record in data.chunks_exact(8) {
        entries.push(Accel {
            flags: record[0] & 0x7f,
            pad: 0,
            key: u16::from_le_bytes([record[2], record[3]]),
            command: u16::from_le_bytes([record[4], record[5]]),
        });
        if record[0] & 0x80 != 0 {
            break;
        }
    }
    if entries.is_empty() {
        return 0;
    }
    add(Resource::Accelerators(entries))
}
unsafe fn translate(hwnd: u32, handle: u32, msg: *const Message) -> i32 {
    if msg.is_null() || crate::window::IsWindowEnabled(hwnd) == 0 {
        return 0;
    }
    let m = unsafe { msg.read_unaligned() };
    let modifiers = unsafe {
        (u8::from(GetKeyState(0x10) & 0x8000 != 0) << 2)
            | (u8::from(GetKeyState(0x11) & 0x8000 != 0) << 3)
            | (u8::from(GetKeyState(0x12) & 0x8000 != 0) << 4)
    };
    let command = state::with(|s| {
        let (_, Resource::Accelerators(entries)) =
            s.resources.iter().find(|(h, _)| *h == handle)?
        else {
            return None;
        };
        entries
            .iter()
            .find(|a| {
                a.key as u32 == m.wparam
                    && a.flags & 0x1c == modifiers
                    && if a.flags & 1 != 0 {
                        matches!(m.message, 0x100 | 0x104)
                    } else {
                        matches!(m.message, 0x102 | 0x106)
                    }
            })
            .map(|a| a.command)
    });
    if let Some(command) = command {
        unsafe {
            crate::SendMessageW(hwnd, 0x111, 0x10000 | command as u32, 0);
        }
        1
    } else {
        0
    }
}
unsafe fn load_string(module: u32, id: u32, out: u32, capacity: i32, wide: bool) -> i32 {
    let id = id & 0xffff;
    let Some(data) = (unsafe { bytes(module, (id >> 4) + 1, 6, true) }) else {
        if capacity > 0 && out != 0 {
            unsafe {
                if wide {
                    (out as *mut u16).write_unaligned(0);
                } else {
                    (out as *mut u8).write(0);
                }
            }
        }
        return 0;
    };
    let mut at = 0;
    for slot in 0..16 {
        let Some(length) = data.get(at..at + 2) else {
            return 0;
        };
        let length = u16::from_le_bytes([length[0], length[1]]) as usize;
        at += 2;
        let Some(raw) = data.get(at..at + length * 2) else {
            return 0;
        };
        if slot == id & 15 {
            if wide && capacity == 0 && out != 0 {
                unsafe {
                    (out as *mut u32).write_unaligned(raw.as_ptr() as u32);
                }
                return length as i32;
            }
            let chars: Vec<u16> = raw
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            return unsafe { text::write(out, capacity, &chars, wide) as i32 };
        }
        at += length * 2;
    }
    0
}
fn word(data: &[u8], at: usize) -> Option<u16> {
    let b = data.get(at..at + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}
unsafe fn bitmap(data: &[u8], width: i32, height: i32) -> Option<u32> {
    let (width, height, bits) = crate::bitmap::decode(data, width, height)?;
    Some(unsafe { CreateBitmap(width, height, 1, 32, bits.as_ptr()) })
}

unsafe fn load_image(
    module: u32,
    name: u32,
    kind: u32,
    width: i32,
    height: i32,
    flags: u32,
    wide: bool,
) -> u32 {
    let name = if name > 0xffff {
        let text = unsafe { text::read(name, wide) };
        if text.first() == Some(&(b'#' as u16)) && text.len() > 1 {
            text[1..]
                .iter()
                .try_fold(0u32, |id, &c| {
                    if !(48..=57).contains(&c) {
                        return None;
                    }
                    id.checked_mul(10)?
                        .checked_add(u32::from(c - 48))
                        .filter(|&id| id <= 0xffff)
                })
                .unwrap_or(name)
        } else {
            name
        }
    } else {
        name
    };
    if kind > 2 || width < 0 || height < 0 || flags & 0x10 != 0 {
        return state::error(87);
    }
    if kind == 0 {
        let Some(data) = (unsafe { bytes(module, name, 2, wide) }) else {
            return 0;
        };
        return unsafe { bitmap(data, width, height) }.unwrap_or_else(|| state::error(13));
    }
    let key = if name <= 0xffff {
        vec![0, name as u16]
    } else {
        unsafe { text::read(name, wide) }
    };
    let shared = flags & 0x8000 != 0;
    if shared {
        let cached = state::with(|s| {
            s.resources.iter().find_map(|(h, r)| match r {
                Resource::Image {
                    module: m,
                    name: n,
                    kind: k,
                    shared: true,
                    ..
                } if *m == module && *k == kind && *n == key => Some(*h),
                _ => None,
            })
        });
        if let Some(handle) = cached {
            return handle;
        }
    }
    let data = if module == 0 && name <= 0xffff && (32512..=32672).contains(&name) {
        Vec::new()
    } else {
        let Some(group) = (unsafe { bytes(module, name, if kind == 1 { 14 } else { 12 }, wide) })
        else {
            return 0;
        };
        if word(group, 4).unwrap_or(0) == 0 {
            return state::error(13);
        }
        let count = word(group, 4).unwrap_or(0) as usize;
        if group.get(6..6 + count * 14).is_none() {
            return state::error(13);
        }
        // Prefer the requested/default dimensions, then the richest palette.
        let best = (0..if kind == 1 { count } else { 1 })
            .min_by_key(|&i| {
                let at = 6 + i * 14;
                let w = if group[at] == 0 {
                    256
                } else {
                    group[at] as i32
                };
                let h = if group[at + 1] == 0 {
                    256
                } else {
                    group[at + 1] as i32
                };
                (
                    (w - if width == 0 { 32 } else { width }).abs()
                        + (h - if height == 0 { 32 } else { height }).abs(),
                    u16::MAX - word(group, at + 6).unwrap_or(0),
                )
            })
            .unwrap();
        let id = word(group, 6 + best * 14 + 12).unwrap();
        let Some(data) = (unsafe { bytes(module, id as u32, if kind == 1 { 3 } else { 1 }, true) })
        else {
            return 0;
        };
        data.to_vec()
    };
    let icon = if kind == 1 && !data.is_empty() {
        let Some(decoded) = crate::bitmap::decode_icon(&data) else {
            return state::error(13);
        };
        Some(decoded)
    } else {
        None
    };
    add(Resource::Image {
        module,
        name: key,
        kind,
        shared,
        _bytes: data,
        icon,
    })
}
/// Classic masked icon drawing is shared by NE and PE callers.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DrawIcon(dc: u32, x: i32, y: i32, handle: u32) -> i32 {
    let icon = state::with(|s| {
        s.resources.iter().find_map(|(h, r)| match r {
            Resource::Image {
                icon: Some(icon), ..
            } if *h == handle => Some(icon.clone()),
            _ => None,
        })
    });
    let Some((width, height, color, mask)) = icon else {
        return state::error(6) as i32;
    };
    unsafe {
        let source = CreateCompatibleDC(dc);
        if source == 0 {
            return 0;
        }
        let mut result = 1;
        for (pixels, rop) in [(&mask, 0x008800c6), (&color, 0x00660046)] {
            let bitmap = CreateBitmap(width, height, 1, 32, pixels.as_ptr());
            if bitmap == 0 {
                result = 0;
                break;
            }
            let old = SelectObject(source, bitmap);
            result = BitBlt(dc, x, y, width, height, source, 0, 0, rop);
            SelectObject(source, old);
            DeleteObject(bitmap);
            if result == 0 {
                break;
            }
        }
        DeleteDC(source);
        result
    }
}
#[unsafe(no_mangle)]
pub extern "system" fn DestroyIcon(handle: u32) -> i32 {
    state::with(|s| {
        let Some(i) = s
            .resources
            .iter()
            .position(|(h, r)| *h == handle && matches!(r, Resource::Image { .. }))
        else {
            return 0;
        };
        if !matches!(&s.resources[i].1, Resource::Image { shared: true, .. }) {
            s.resources.remove(i);
        }
        1
    })
}
macro_rules! api {
    ($create:ident,$copy:ident,$load:ident,$translate:ident,$string:ident,$image:ident,$icon:ident,$cursor:ident,$bitmap:ident,$wide:expr) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $create(p: *const Accel, n: i32) -> u32 {
            unsafe { create_accel(p, n, $wide) }
        }
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $copy(h: u32, p: *mut Accel, n: i32) -> i32 {
            unsafe { copy_accel(h, p, n, $wide) }
        }
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $load(m: u32, n: u32) -> u32 {
            unsafe { load_accel(m, n, $wide) }
        }
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $translate(h: u32, a: u32, m: *const Message) -> i32 {
            unsafe { translate(h, a, m) }
        }
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $string(m: u32, id: u32, p: u32, n: i32) -> i32 {
            unsafe { load_string(m, id, p, n, $wide) }
        }
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $image(
            m: u32,
            n: u32,
            k: u32,
            w: i32,
            h: i32,
            f: u32,
        ) -> u32 {
            unsafe { load_image(m, n, k, w, h, f, $wide) }
        }
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $icon(m: u32, n: u32) -> u32 {
            unsafe { load_image(m, n, 1, 0, 0, 0x8040, $wide) }
        }
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $cursor(m: u32, n: u32) -> u32 {
            unsafe { load_image(m, n, 2, 0, 0, 0x8040, $wide) }
        }
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $bitmap(m: u32, n: u32) -> u32 {
            unsafe { load_image(m, n, 0, 0, 0, 0, $wide) }
        }
    };
}
api!(
    CreateAcceleratorTableA,
    CopyAcceleratorTableA,
    LoadAcceleratorsA,
    TranslateAcceleratorA,
    LoadStringA,
    LoadImageA,
    LoadIconA,
    LoadCursorA,
    LoadBitmapA,
    false
);
api!(
    CreateAcceleratorTableW,
    CopyAcceleratorTableW,
    LoadAcceleratorsW,
    TranslateAcceleratorW,
    LoadStringW,
    LoadImageW,
    LoadIconW,
    LoadCursorW,
    LoadBitmapW,
    true
);
