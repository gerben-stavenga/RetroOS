//! Resource handles point at PE data entries in the already mapped module.
//! Traversal checks all directory offsets before reading them.
use crate::{GetModuleHandleA, SetLastError};
unsafe extern "system" {
    fn GetModuleFileNameA(module: u32, out: *mut u8, size: u32) -> u32;
    fn MultiByteToWideChar(cp: u32, flags: u32, src: u32, len: i32, dst: *mut u16, cap: i32)
    -> i32;
}
unsafe fn word(at: u32) -> u16 {
    unsafe { (at as *const u16).read_unaligned() }
}
unsafe fn dword(at: u32) -> u32 {
    unsafe { (at as *const u32).read_unaligned() }
}
struct Tree {
    base: u32,
    image_size: u32,
    root: u32,
    size: u32,
}
impl Tree {
    unsafe fn open(module: u32) -> Option<Self> {
        let base = if module == 0 {
            unsafe { GetModuleHandleA(0) }
        } else {
            module
        };
        let mut path = [0u8; 2];
        if base == 0
            || unsafe { GetModuleFileNameA(base, path.as_mut_ptr(), 2) } == 0
            || unsafe { word(base) } != 0x5a4d
        {
            return None;
        }
        let pe = base.checked_add(unsafe { dword(base + 0x3c) })?;
        if unsafe { dword(pe) } != 0x4550 || unsafe { word(pe + 24) } != 0x10b {
            return None;
        }
        let image_size = unsafe { dword(pe + 24 + 56) };
        let rva = unsafe { dword(pe + 24 + 112) };
        let size = unsafe { dword(pe + 24 + 116) };
        if rva == 0 || rva.checked_add(size)? > image_size {
            return None;
        }
        Some(Self {
            base,
            image_size,
            root: base.checked_add(rva)?,
            size,
        })
    }
    fn at(&self, offset: u32, size: u32) -> Option<u32> {
        (offset.checked_add(size)? <= self.size).then(|| self.root + offset)
    }
    unsafe fn key(&self, raw: u32, name: u32, wide: bool) -> bool {
        if raw & 0x8000_0000 == 0 {
            return name <= 0xffff && raw == name;
        }
        if name <= 0xffff {
            return false;
        }
        let offset = raw & 0x7fff_ffff;
        let Some(at) = self.at(offset, 2) else {
            return false;
        };
        let len = unsafe { word(at) } as usize;
        if self.at(offset + 2, len as u32 * 2).is_none() {
            return false;
        }
        let mut buffer = [0u16; 256];
        let pointer = if wide {
            name as *const u16
        } else {
            let n = unsafe { MultiByteToWideChar(0, 0, name, -1, buffer.as_mut_ptr(), 256) };
            if n <= 0 {
                return false;
            }
            buffer.as_ptr()
        };
        for i in 0..len {
            let a = unsafe { word(at + 2 + i as u32 * 2) };
            let b = unsafe { pointer.add(i).read_unaligned() };
            if b == 0 {
                return false;
            }
            let fold = |c: u16| char::from_u32(c as u32).map(|c| c.to_uppercase().next().unwrap());
            if a != b && fold(a) != fold(b) {
                return false;
            }
        }
        unsafe { pointer.add(len).read_unaligned() == 0 }
    }
    unsafe fn descend(&self, offset: u32, key: u32, wide: bool) -> Option<u32> {
        let at = self.at(offset, 16)?;
        let count = u32::from(unsafe { word(at + 12) }) + u32::from(unsafe { word(at + 14) });
        self.at(offset + 16, count.checked_mul(8)?)?;
        for n in 0..count {
            let entry = at + 16 + n * 8;
            if unsafe { self.key(dword(entry), key, wide) } {
                return Some(unsafe { dword(entry + 4) });
            }
        }
        None
    }
    unsafe fn find(&self, name: u32, kind: u32, wide: bool, language: Option<u16>) -> Option<u32> {
        let kind = unsafe { self.descend(0, kind, wide) }?;
        if kind & 0x8000_0000 == 0 {
            return None;
        }
        let names = unsafe { self.descend(kind & 0x7fff_ffff, name, wide) }?;
        if names & 0x8000_0000 == 0 {
            return None;
        }
        let offset = names & 0x7fff_ffff;
        let header = self.at(offset, 16)?;
        let entry = if let Some(lang) = language.filter(|&l| l != 0) {
            unsafe { self.descend(offset, lang as u32, false) }?
        } else {
            if unsafe { word(header + 12) } + unsafe { word(header + 14) } == 0 {
                return None;
            }
            unsafe { dword(self.at(offset + 16, 8)? + 4) }
        };
        if entry & 0x8000_0000 != 0 {
            return None;
        }
        let record = self.at(entry, 16)?;
        let rva = unsafe { dword(record) };
        let size = unsafe { dword(record + 4) };
        if rva.checked_add(size)? > self.image_size {
            return None;
        }
        Some(record)
    }
    unsafe fn valid(&self, record: u32) -> Option<(u32, u32)> {
        self.at(record.checked_sub(self.root)?, 16)?;
        let rva = unsafe { dword(record) };
        let size = unsafe { dword(record + 4) };
        if rva.checked_add(size)? > self.image_size {
            return None;
        }
        Some((self.base.checked_add(rva)?, size))
    }
}
unsafe fn find(module: u32, name: u32, kind: u32, wide: bool, language: Option<u16>) -> u32 {
    // Windows accepts decimal resource IDs written as "#123" as well as
    // MAKEINTRESOURCE pointers, for both the name and type.
    let numeric = |value: u32| -> u32 {
        if value <= 0xffff {
            return value;
        }
        let unit = |n: usize| unsafe {
            if wide {
                (value as *const u16).add(n).read_unaligned() as u32
            } else {
                (value as *const u8).add(n).read() as u32
            }
        };
        if unit(0) != 35 {
            return value;
        }
        let mut number = 0u32;
        for n in 1..7 {
            let c = unit(n);
            if c == 0 {
                return if n > 1 { number } else { value };
            }
            if !(48..=57).contains(&c) {
                return value;
            }
            number = number * 10 + c - 48;
            if number > 0xffff {
                return value;
            }
        }
        value
    };
    let (name, kind) = (numeric(name), numeric(kind));
    let found = unsafe { Tree::open(module).and_then(|t| t.find(name, kind, wide, language)) };
    found.unwrap_or_else(|| {
        unsafe {
            SetLastError(1814);
        }
        0
    })
}
macro_rules! api {
    ($find:ident, $ex:ident, $wide:expr) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $find(module: u32, name: u32, kind: u32) -> u32 {
            unsafe { find(module, name, kind, $wide, None) }
        }
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $ex(module: u32, kind: u32, name: u32, language: u16) -> u32 {
            unsafe { find(module, name, kind, $wide, Some(language)) }
        }
    };
}
api!(FindResourceA, FindResourceExA, false);
api!(FindResourceW, FindResourceExW, true);
#[unsafe(no_mangle)]
pub unsafe extern "system" fn LoadResource(module: u32, record: u32) -> u32 {
    unsafe {
        Tree::open(module)
            .and_then(|t| t.valid(record))
            .map_or(0, |(at, _)| at)
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SizeofResource(module: u32, record: u32) -> u32 {
    unsafe {
        Tree::open(module)
            .and_then(|t| t.valid(record))
            .map_or(0, |(_, size)| size)
    }
}
#[unsafe(no_mangle)]
pub extern "system" fn LockResource(data: u32) -> u32 {
    data
}
#[unsafe(no_mangle)]
pub extern "system" fn FreeResource(_: u32) -> u32 {
    0
}
