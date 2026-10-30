//! Buffered multimedia files and RIFF traversal live entirely in the guest DLL.
//! Custom I/O procedures are rejected until their callback ABI is implemented.
use alloc::vec::Vec;
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};
const DOS: u32 = u32::from_le_bytes(*b"DOS ");
const MEM: u32 = u32::from_le_bytes(*b"MEM ");
const RIFF: u32 = u32::from_le_bytes(*b"RIFF");
const LIST: u32 = u32::from_le_bytes(*b"LIST");
const DIRTY: u32 = 0x10000000;
const ALLOC: u32 = 0x10000;
type Info = [u32; 18];
unsafe extern "system" {
    fn CreateFileA(
        name: u32,
        access: u32,
        share: u32,
        security: u32,
        creation: u32,
        flags: u32,
        template: u32,
    ) -> u32;
    fn CreateFileW(
        name: u32,
        access: u32,
        share: u32,
        security: u32,
        creation: u32,
        flags: u32,
        template: u32,
    ) -> u32;
    fn ReadFile(file: u32, out: u32, count: u32, done: *mut u32, overlapped: u32) -> u32;
    fn WriteFile(file: u32, data: u32, count: u32, done: *mut u32, overlapped: u32) -> u32;
    fn SetFilePointer(file: u32, offset: i32, high: u32, origin: u32) -> u32;
    fn GetLastError() -> u32;
    fn CloseHandle(file: u32) -> u32;
}
struct File {
    info: Info,
    fd: Option<u32>,
    owned: Vec<u8>,
    loaded: bool,
    written: u32,
}
impl Drop for File {
    fn drop(&mut self) {
        if let Some(fd) = self.fd.take() {
            unsafe {
                CloseHandle(fd);
            }
        }
    }
}
impl File {
    fn position(&self) -> u32 {
        if self.info[5] == 0 {
            self.info[11]
        } else {
            self.info[10] + (self.info[7] - self.info[6])
        }
    }
    fn size(&mut self) -> Option<u32> {
        if self.info[1] == MEM {
            return Some(self.info[5]);
        }
        if self.flush(false) != 0 {
            return None;
        }
        let fd = self.fd?;
        let n = unsafe { SetFilePointer(fd, 0, 0, 2) };
        if unsafe { SetFilePointer(fd, self.info[11] as i32, 0, 0) } == u32::MAX {
            return None;
        }
        (n <= i32::MAX as u32).then_some(n)
    }
    fn flush(&mut self, empty: bool) -> u32 {
        let pos = self.position();
        if self.info[1] != MEM && self.info[0] & DIRTY != 0 {
            let count = self.written.max(self.info[7] - self.info[6]);
            let fd = self.fd.unwrap();
            if unsafe { SetFilePointer(fd, self.info[10] as i32, 0, 0) } == u32::MAX {
                return 263;
            }
            let mut done = 0;
            if unsafe { WriteFile(fd, self.info[6], count, &mut done, 0) } == 0 || done != count {
                return 262;
            }
            self.info[11] = self.info[10] + done;
        }
        self.info[0] &= !DIRTY;
        self.written = 0;
        if empty && self.info[1] != MEM {
            if let Some(fd) = self.fd {
                if unsafe { SetFilePointer(fd, pos as i32, 0, 0) } == u32::MAX {
                    return 263;
                }
            }
            self.info[10] = pos;
            self.info[11] = pos;
            self.info[7] = self.info[6];
            self.info[8] = self.info[6];
            self.loaded = false;
        }
        0
    }
    fn fill(&mut self, read: bool) -> Result<u32, u32> {
        if self.info[5] == 0 {
            return Err(266);
        }
        if self.info[1] == MEM {
            return Err(if read { 261 } else { 264 });
        }
        let start = if self.loaded {
            self.info[10] + (self.info[if read { 8 } else { 7 }] - self.info[6])
        } else {
            self.info[11]
        };
        let result = self.flush(false);
        if result != 0 {
            return Err(result);
        }
        if unsafe { SetFilePointer(self.fd.unwrap(), start as i32, 0, 0) } == u32::MAX {
            return Err(263);
        }
        self.info[11] = start;
        self.info[10] = start;
        self.info[7] = self.info[6];
        self.info[8] = self.info[6];
        self.loaded = true;
        if !read {
            return Ok(self.info[5]);
        }
        let mut done = 0;
        if unsafe { ReadFile(self.fd.unwrap(), self.info[6], self.info[5], &mut done, 0) } == 0 {
            return Err(261);
        }
        self.info[11] = self.info[11]
            .checked_add(done)
            .filter(|n| *n <= i32::MAX as u32)
            .ok_or(263u32)?;
        self.info[8] += done;
        Ok(done)
    }
    unsafe fn read(&mut self, out: u32, n: u32) -> i32 {
        if self.info[0] & 3 == 1
            || (out == 0 && n != 0)
            || n > (i32::MAX as u32).saturating_sub(self.position())
        {
            return -1;
        }
        if self.info[5] == 0 {
            let mut done = 0;
            if unsafe { ReadFile(self.fd.unwrap(), out, n, &mut done, 0) } == 0 {
                return -1;
            }
            self.info[11] += done;
            self.info[10] = self.info[11];
            return done as i32;
        }
        let mut done = 0;
        while done < n {
            if !self.loaded || self.info[7] >= self.info[8] {
                if self.info[1] == MEM {
                    break;
                }
                match self.fill(true) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => return if done == 0 { -1 } else { done as i32 },
                }
            }
            let count = (n - done).min(self.info[8] - self.info[7]);
            unsafe {
                core::ptr::copy(
                    self.info[7] as *const u8,
                    (out + done) as *mut u8,
                    count as usize,
                );
            }
            done += count;
            self.info[7] += count;
        }
        done as i32
    }
    unsafe fn write(&mut self, data: u32, n: u32) -> i32 {
        if self.info[0] & 3 == 0
            || (data == 0 && n != 0)
            || n > (i32::MAX as u32).saturating_sub(self.position())
        {
            return -1;
        }
        if self.info[5] == 0 {
            let mut done = 0;
            if unsafe { WriteFile(self.fd.unwrap(), data, n, &mut done, 0) } == 0 {
                return -1;
            }
            self.info[11] += done;
            self.info[10] = self.info[11];
            return done as i32;
        }
        let mut done = 0;
        while done < n {
            if !self.loaded || self.info[7] >= self.info[9] {
                if self.info[1] == MEM {
                    break;
                }
                if self.fill(false).is_err() {
                    return if done == 0 { -1 } else { done as i32 };
                }
            }
            let count = (n - done).min(self.info[9] - self.info[7]);
            unsafe {
                core::ptr::copy(
                    (data + done) as *const u8,
                    self.info[7] as *mut u8,
                    count as usize,
                );
            }
            done += count;
            self.info[7] += count;
            self.info[8] = self.info[8].max(self.info[7]);
            self.written = self.written.max(self.info[7] - self.info[6]);
            self.info[0] |= DIRTY;
        }
        done as i32
    }
    fn seek(&mut self, offset: i32, origin: u32) -> i32 {
        let base = match origin {
            0 => 0,
            1 => self.position(),
            2 => match self.size() {
                Some(n) => n,
                None => return -1,
            },
            _ => return -1,
        };
        let target = i64::from(base) + i64::from(offset);
        if !(0..=i64::from(i32::MAX)).contains(&target) {
            return -1;
        }
        let target = target as u32;
        if self.info[1] == MEM {
            if target > self.info[5] {
                return -1;
            }
            self.info[7] = self.info[6] + target;
            return target as i32;
        }
        if self.loaded
            && target >= self.info[10]
            && target <= self.info[10] + (self.info[8] - self.info[6])
        {
            self.info[7] = self.info[6] + target - self.info[10];
            return target as i32;
        }
        if self.flush(false) != 0 {
            return -1;
        }
        if unsafe { SetFilePointer(self.fd.unwrap(), target as i32, 0, 0) } == u32::MAX {
            return -1;
        }
        self.info[10] = target;
        self.info[11] = target;
        self.info[7] = self.info[6];
        self.info[8] = self.info[6];
        self.loaded = false;
        target as i32
    }
    fn set_info(&mut self, info: Info) -> u32 {
        let low = self.info[6];
        let Some(high) = low.checked_add(self.info[5]) else {
            return 11;
        };
        if info[6] != low
            || info[5] != self.info[5]
            || ![info[7], info[8], info[9]]
                .iter()
                .all(|p| (low..=high).contains(p))
        {
            return 11;
        }
        if info[0] & DIRTY != 0 && self.info[0] & 3 == 0 {
            return 11;
        }
        self.info[7] = info[7];
        self.info[8] = info[8];
        self.info[0] |= info[0] & DIRTY;
        if self.info[0] & DIRTY != 0 {
            self.written = self.written.max(info[7] - low);
        }
        0
    }
}
struct State {
    files: Vec<File>,
    next: u32,
}
struct Global {
    lock: AtomicBool,
    state: UnsafeCell<State>,
}
unsafe impl Sync for Global {}
static GLOBAL: Global = Global {
    lock: AtomicBool::new(false),
    state: UnsafeCell::new(State {
        files: Vec::new(),
        next: 1,
    }),
};
fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    while GLOBAL.lock.swap(true, Ordering::Acquire) {
        unsafe {
            crate::runtime::Sleep(0);
        }
    }
    let r = f(unsafe { &mut *GLOBAL.state.get() });
    GLOBAL.lock.store(false, Ordering::Release);
    r
}
fn file<R>(handle: u32, missing: R, f: impl FnOnce(&mut File) -> R) -> R {
    with(
        |s| match s.files.iter_mut().find(|f| f.info[17] == handle) {
            Some(v) => f(v),
            None => missing,
        },
    )
}
unsafe fn open(name: u32, info: *mut Info, flags: u32, wide: bool) -> u32 {
    let mut values = if info.is_null() {
        [0; 18]
    } else {
        unsafe { info.read_unaligned() }
    };
    values[17] = 0;
    let result = (|| -> Result<File, u32> {
        if flags & !(3 | 0x70 | 0x1000 | ALLOC) != 0
            || flags & 3 == 3
            || values[2] != 0
            || (values[1] != 0 && values[1] != DOS && values[1] != MEM)
        {
            return Err(259);
        }
        if values[5] > i32::MAX as u32 {
            return Err(11);
        }
        let mut f = File {
            info: [0; 18],
            fd: None,
            owned: Vec::new(),
            loaded: false,
            written: 0,
        };
        f.info[0] = flags & !ALLOC;
        f.info[1] = if values[1] == MEM { MEM } else { DOS };
        let cch = if values[5] == 0 && flags & ALLOC != 0 {
            8192
        } else {
            values[5]
        };
        let mut buffer = values[6];
        if cch != 0 && buffer == 0 {
            f.owned
                .try_reserve_exact(cch as usize)
                .map_err(|_| 258u32)?;
            f.owned.resize(cch as usize, 0);
            buffer = f.owned.as_mut_ptr() as u32;
            f.info[0] |= ALLOC;
        }
        buffer.checked_add(cch).ok_or(11u32)?;
        f.info[5] = cch;
        f.info[6] = if cch == 0 { 0 } else { buffer };
        f.info[7] = f.info[6];
        f.info[8] = f.info[6];
        f.info[9] = f.info[6] + cch;
        if f.info[1] == MEM {
            if cch == 0 {
                return Err(11);
            }
            f.loaded = true;
            f.info[8] = f.info[9];
            return Ok(f);
        }
        let fd = if name == 0 {
            if values[12] == 0 {
                return Err(259);
            }
            values[12]
        } else {
            let access = match flags & 3 {
                0 => 0x80000000,
                1 => 0x40000000,
                _ => 0xc0000000,
            };
            let share = match flags & 0x70 {
                0x10 => 0,
                0x20 => 1,
                0x30 => 2,
                _ => 3,
            };
            let creation = if flags & 0x1000 != 0 { 2 } else { 3 };
            unsafe {
                if wide {
                    CreateFileW(name, access, share, 0, creation, 0, 0)
                } else {
                    CreateFileA(name, access, share, 0, creation, 0, 0)
                }
            }
        };
        if fd == u32::MAX {
            return Err(match unsafe { GetLastError() } {
                2 => 257,
                3 => 267,
                5 => 268,
                32 => 269,
                _ => 259,
            });
        }
        f.fd = Some(fd);
        f.info[12] = fd;
        let pos = unsafe { SetFilePointer(fd, 0, 0, 1) };
        if pos > i32::MAX as u32 {
            return Err(263);
        }
        f.info[10] = pos;
        f.info[11] = pos;
        Ok(f)
    })();
    let handle = match result {
        Ok(mut f) => with(|s| {
            for _ in 0..65535 {
                let id = s.next;
                s.next = s.next % 65535 + 1;
                if !s.files.iter().any(|v| v.info[17] == id) {
                    f.info[17] = id;
                    values = f.info;
                    s.files.push(f);
                    return id;
                }
            }
            values[3] = 258;
            0
        }),
        Err(e) => {
            values[3] = e;
            0
        }
    };
    if !info.is_null() {
        unsafe {
            info.write_unaligned(values);
        }
    }
    handle
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn mmioOpenA(name: u32, info: *mut Info, flags: u32) -> u32 {
    unsafe { open(name, info, flags, false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn mmioOpenW(name: u32, info: *mut Info, flags: u32) -> u32 {
    unsafe { open(name, info, flags, true) }
}
#[unsafe(no_mangle)]
pub extern "system" fn mmioClose(h: u32, flags: u32) -> u32 {
    if flags & !0x10 != 0 {
        return 11;
    }
    with(|s| {
        let Some(i) = s.files.iter().position(|f| f.info[17] == h) else {
            return 5;
        };
        let e = s.files[i].flush(false);
        if e != 0 {
            return e;
        }
        let mut f = s.files.remove(i);
        if flags & 0x10 != 0 {
            f.fd.take();
        }
        0
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn mmioRead(h: u32, out: u32, n: i32) -> i32 {
    if n < 0 {
        -1
    } else {
        file(h, -1, |f| unsafe { f.read(out, n as u32) })
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn mmioWrite(h: u32, data: u32, n: i32) -> i32 {
    if n < 0 {
        -1
    } else {
        file(h, -1, |f| unsafe { f.write(data, n as u32) })
    }
}
#[unsafe(no_mangle)]
pub extern "system" fn mmioSeek(h: u32, offset: i32, origin: u32) -> i32 {
    file(h, -1, |f| f.seek(offset, origin))
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn mmioGetInfo(h: u32, out: *mut Info, flags: u32) -> u32 {
    file(h, 5, |f| {
        if out.is_null() || flags != 0 {
            11
        } else {
            unsafe {
                out.write_unaligned(f.info);
            }
            0
        }
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn mmioSetInfo(h: u32, info: *const Info, flags: u32) -> u32 {
    file(h, 5, |f| {
        if info.is_null() || flags != 0 {
            11
        } else {
            f.set_info(unsafe { info.read_unaligned() })
        }
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn mmioAdvance(h: u32, info: *mut Info, flags: u32) -> u32 {
    file(h, 5, |f| {
        if flags > 1 {
            return 11;
        }
        if f.info[5] == 0 {
            return 266;
        }
        if !info.is_null() {
            let e = f.set_info(unsafe { info.read_unaligned() });
            if e != 0 {
                return e;
            }
        }
        match f.fill(flags == 0) {
            Ok(_) => {
                if !info.is_null() {
                    unsafe {
                        info.write_unaligned(f.info);
                    }
                }
                0
            }
            Err(e) => e,
        }
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn mmioFlush(h: u32, flags: u32) -> u32 {
    if flags & !0x10 != 0 {
        return 11;
    }
    file(h, 5, |f| f.flush(flags & 0x10 != 0))
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Chunk {
    id: u32,
    size: u32,
    kind: u32,
    offset: u32,
    flags: u32,
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn mmioDescend(
    h: u32,
    out: *mut Chunk,
    parent: *const Chunk,
    flags: u32,
) -> u32 {
    if out.is_null() || !matches!(flags, 0 | 0x10 | 0x20 | 0x40) {
        return 11;
    }
    let wanted = unsafe { out.read_unaligned() };
    let parent = if parent.is_null() {
        None
    } else {
        Some(unsafe { parent.read_unaligned() })
    };
    file(h, 5, |f| {
        let Some(length) = f.size() else {
            return 263;
        };
        let end = if let Some(p) = parent {
            let start = p
                .offset
                .checked_add(if p.id == RIFF || p.id == LIST { 4 } else { 0 });
            if start.is_none_or(|start| f.position() < start) {
                return 265;
            }
            match p.offset.checked_add(p.size) {
                Some(n) if n <= length => n,
                _ => return 265,
            }
        } else {
            length
        };
        loop {
            let start = f.position();
            if start.checked_add(8).is_none_or(|n| n > end) {
                return 265;
            }
            let mut header = [0u32; 2];
            if unsafe { f.read(header.as_mut_ptr() as u32, 8) } != 8 {
                return 265;
            }
            let offset = start + 8;
            let size = header[1];
            let Some(next) = offset.checked_add(size).filter(|n| *n <= end) else {
                return 265;
            };
            let mut chunk = Chunk {
                id: header[0],
                size,
                kind: 0,
                offset,
                flags: 0,
            };
            if chunk.id == RIFF || chunk.id == LIST {
                if size < 4 || unsafe { f.read(&mut chunk.kind as *mut u32 as u32, 4) } != 4 {
                    return 265;
                }
            }
            let found = match flags {
                0 => true,
                0x10 => chunk.id == wanted.id,
                0x20 => chunk.id == RIFF && chunk.kind == wanted.kind,
                _ => chunk.id == LIST && chunk.kind == wanted.kind,
            };
            if found {
                unsafe {
                    out.write_unaligned(chunk);
                }
                return 0;
            }
            let Some(next) = next.checked_add(size & 1).filter(|n| *n <= end) else {
                return 265;
            };
            if f.seek(next as i32, 0) < 0 {
                return 263;
            }
        }
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn mmioAscend(h: u32, chunk: *mut Chunk, flags: u32) -> u32 {
    if chunk.is_null() || flags != 0 {
        return 11;
    }
    file(h, 5, |f| {
        let mut c = unsafe { chunk.read_unaligned() };
        if c.offset < 8 {
            return 11;
        }
        if c.flags & DIRTY != 0 {
            let end = f.position();
            if end < c.offset {
                return 11;
            }
            c.size = end - c.offset;
            if f.seek((c.offset - 4) as i32, 0) < 0
                || unsafe { f.write(&c.size as *const u32 as u32, 4) } != 4
                || f.seek(end as i32, 0) < 0
            {
                return 262;
            }
            if c.size & 1 != 0 {
                let pad = 0u8;
                if unsafe { f.write(&pad as *const u8 as u32, 1) } != 1 {
                    return 262;
                }
            }
            c.flags &= !DIRTY;
            unsafe {
                chunk.write_unaligned(c);
            }
            0
        } else {
            let Some(end) = c
                .offset
                .checked_add(c.size)
                .and_then(|n| n.checked_add(c.size & 1))
                .filter(|n| *n <= i32::MAX as u32)
            else {
                return 263;
            };
            if f.seek(end as i32, 0) < 0 { 263 } else { 0 }
        }
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn mmioCreateChunk(h: u32, chunk: *mut Chunk, flags: u32) -> u32 {
    if chunk.is_null() || !matches!(flags, 0 | 0x20 | 0x40) {
        return 11;
    }
    file(h, 5, |f| {
        let mut c = unsafe { chunk.read_unaligned() };
        let Some(offset) = f
            .position()
            .checked_add(8)
            .filter(|n| *n <= i32::MAX as u32)
        else {
            return 263;
        };
        if flags != 0 {
            c.id = if flags == 0x20 { RIFF } else { LIST };
        }
        let words = [c.id, 0, c.kind];
        let n = if c.id == RIFF || c.id == LIST { 12 } else { 8 };
        if unsafe { f.write(words.as_ptr() as u32, n) } != n as i32 {
            return 262;
        }
        c.offset = offset;
        c.size = 0;
        c.flags = DIRTY;
        unsafe {
            chunk.write_unaligned(c);
        }
        0
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn mmioStringToFOURCCA(name: *const u8, flags: u32) -> u32 {
    if name.is_null() {
        return 0;
    }
    let mut bytes = [b' '; 4];
    for (i, b) in bytes.iter_mut().enumerate() {
        let c = unsafe { name.add(i).read() };
        if c == 0 {
            break;
        }
        *b = if flags & 0x10 != 0 {
            c.to_ascii_uppercase()
        } else {
            c
        };
    }
    u32::from_le_bytes(bytes)
}
