//! Class registration and metadata are USER32 policy, not kernel operations.
use crate::{
    state::{self, Class},
    text,
};
use alloc::{vec, vec::Vec};

pub unsafe fn find(classes: &[Class], name: u32, instance: u32, wide: bool) -> Option<usize> {
    let value = if name > 0xffff {
        unsafe { text::read(name, wide) }
    } else {
        Vec::new()
    };
    let matches = |c: &&Class| {
        name <= 0xffff && c.atom == name || name > 0xffff && text::same(&c.name, &value)
    };
    classes
        .iter()
        .enumerate()
        .rev()
        .filter(|(_, c)| matches(c))
        .find(|(_, c)| !c.global && c.instance == instance && instance != 0)
        .or_else(|| {
            classes
                .iter()
                .enumerate()
                .rev()
                .filter(|(_, c)| matches(c))
                .find(|(_, c)| c.global)
        })
        .map(|(i, _)| i)
}
unsafe fn register(address: u32, wide: bool, extended: bool) -> u32 {
    crate::controls::ensure();
    if address == 0 {
        return state::error(87);
    }
    let base = address as *const u32;
    if extended && unsafe { base.read_unaligned() } != 48 {
        return state::error(87);
    }
    let p = unsafe { base.add(usize::from(extended)) };
    let field = |n| unsafe { p.add(n).read_unaligned() };
    let (proc, ce, we, name) = (field(1), field(2), field(3), field(9));
    if proc == 0 || name <= 0xffff || ce > 4096 || we > 4096 {
        return state::error(87);
    }
    let value = unsafe { text::read(name, wide) };
    if value.is_empty() {
        return state::error(87);
    }
    let instance = if field(4) == 0 {
        unsafe { crate::runtime::GetModuleHandleA(0) }
    } else {
        field(4)
    };
    if instance == unsafe { crate::runtime::GetModuleHandleA(c"USER32".as_ptr() as u32) } {
        return state::error(87);
    }
    let global = field(0) & 0x4000 != 0;
    state::with(|s| {
        if s.classes.iter().any(|c| {
            text::same(&c.name, &value)
                && if global {
                    c.global
                } else {
                    !c.global && c.instance == instance
                }
        }) {
            return state::error(1410);
        }
        if s.next_atom > 0xffff {
            return state::error(8);
        }
        let atom = s.next_atom;
        s.next_atom += 1;
        s.classes.push(Class {
            global,
            atom,
            name: value,
            style: field(0),
            proc,
            extra: vec![0; ce as usize],
            window_extra: we as usize,
            instance,
            icon: field(5),
            cursor: field(6),
            background: field(7),
            menu: field(8),
            small_icon: if extended { field(10) } else { 0 },
            wide,
            live: 0,
        });
        atom
    })
}
unsafe fn unregister(name: u32, instance: u32, wide: bool) -> i32 {
    let instance = if instance == 0 {
        unsafe { crate::runtime::GetModuleHandleA(0) }
    } else {
        instance
    };
    state::with(|s| {
        let Some(index) = (unsafe { find(&s.classes, name, instance, wide) }) else {
            return state::error(1411) as i32;
        };
        let atom = s.classes[index].atom;
        if s.classes[index].live != 0 || s.windows.iter().any(|w| w.class == atom) {
            return state::error(1412) as i32;
        }
        s.classes.remove(index);
        1
    })
}
unsafe fn info(instance: u32, name: u32, output: u32, wide: bool, extended: bool) -> i32 {
    crate::controls::ensure();
    if output == 0 {
        return state::error(87) as i32;
    }
    state::with(|s| {
        let Some(index) = (unsafe { find(&s.classes, name, instance, wide) }) else {
            return state::error(1411) as i32;
        };
        let c = &s.classes[index];
        let values = [
            c.style,
            crate::controls::variant(c.proc, wide),
            c.extra.len() as u32,
            c.window_extra as u32,
            if c.global { instance } else { c.instance },
            c.icon,
            c.cursor,
            c.background,
            c.menu,
            name,
            c.small_icon,
        ];
        let mut p = output as *mut u32;
        if extended {
            unsafe {
                p.write_unaligned(48);
                p = p.add(1);
            }
        }
        for (i, &value) in values[..if extended { 11 } else { 10 }].iter().enumerate() {
            unsafe {
                p.add(i).write_unaligned(value);
            }
        }
        c.atom as i32
    })
}
macro_rules! class_api {
    ($reg:ident,$reg_ex:ident,$unreg:ident,$info:ident,$info_ex:ident,$wide:expr) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $reg(p: u32) -> u32 {
            unsafe { register(p, $wide, false) }
        }
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $reg_ex(p: u32) -> u32 {
            unsafe { register(p, $wide, true) }
        }
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $unreg(n: u32, i: u32) -> i32 {
            unsafe { unregister(n, i, $wide) }
        }
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $info(i: u32, n: u32, o: u32) -> i32 {
            unsafe { info(i, n, o, $wide, false) }
        }
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $info_ex(i: u32, n: u32, o: u32) -> i32 {
            unsafe { info(i, n, o, $wide, true) }
        }
    };
}
class_api!(
    RegisterClassA,
    RegisterClassExA,
    UnregisterClassA,
    GetClassInfoA,
    GetClassInfoExA,
    false
);
class_api!(
    RegisterClassW,
    RegisterClassExW,
    UnregisterClassW,
    GetClassInfoW,
    GetClassInfoExW,
    true
);

unsafe fn long(hwnd: u32, index: i32, value: Option<u32>, wide: bool) -> u32 {
    state::with(|s| {
        let Some(w) = s.windows.iter().find(|w| w.hwnd == hwnd) else {
            return state::error(1400);
        };
        let Some(c) = s.classes.iter_mut().find(|c| c.atom == w.class) else {
            return state::error(1411);
        };
        if index >= 0 {
            let i = index as usize;
            if i.checked_add(4).is_none_or(|end| end > c.extra.len()) {
                return state::error(1413);
            }
            let old = u32::from_le_bytes(c.extra[i..i + 4].try_into().unwrap());
            if let Some(v) = value {
                c.extra[i..i + 4].copy_from_slice(&v.to_le_bytes());
            }
            return old;
        }
        let slot = match index {
            -8 => &mut c.menu,
            -10 => &mut c.background,
            -12 => &mut c.cursor,
            -14 => &mut c.icon,
            -16 => &mut c.instance,
            -24 => &mut c.proc,
            -26 => &mut c.style,
            -34 => &mut c.small_icon,
            -18 if value.is_none() => return c.window_extra as u32,
            -20 if value.is_none() => return c.extra.len() as u32,
            -32 if value.is_none() => return c.atom,
            _ => return state::error(1413),
        };
        let old = if index == -24 {
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
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetClassLongA(h: u32, i: i32) -> u32 {
    unsafe { long(h, i, None, false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetClassLongW(h: u32, i: i32) -> u32 {
    unsafe { long(h, i, None, true) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SetClassLongA(h: u32, i: i32, v: u32) -> u32 {
    unsafe { long(h, i, Some(v), false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SetClassLongW(h: u32, i: i32, v: u32) -> u32 {
    unsafe { long(h, i, Some(v), true) }
}
