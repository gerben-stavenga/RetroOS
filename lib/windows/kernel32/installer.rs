//! Legacy installer helpers execute in the guest.
use alloc::vec::Vec;
unsafe extern "system" {
    fn CreateFileA(
        path: u32,
        access: u32,
        share: u32,
        security: u32,
        creation: u32,
        flags: u32,
        template: u32,
    ) -> u32;
    fn CloseHandle(h: u32) -> i32;
    fn ReadFile(h: u32, p: u32, n: u32, done: *mut u32, overlap: u32) -> i32;
    fn WriteFile(h: u32, p: u32, n: u32, done: *mut u32, overlap: u32) -> i32;
    fn GetLastError() -> u32;
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetTempFileNameA(
    path: u32,
    prefix: u32,
    unique: u32,
    out: u32,
) -> u32 {
    if path == 0 || out == 0 {
        return 0;
    }
    let mut name = Vec::new();
    let mut p = path as *const u8;
    while name.len() < 240 {
        let c = unsafe { p.read() };
        if c == 0 {
            break;
        }
        name.push(c);
        p = unsafe { p.add(1) };
    }
    if name.is_empty() || name.len() == 240 {
        return 0;
    }
    if !matches!(name.last(), Some(b'\\' | b'/')) {
        name.push(b'\\');
    }
    if prefix != 0 {
        for i in 0..3 {
            let c = unsafe { (prefix as *const u8).add(i).read() };
            if c == 0 {
                break;
            }
            name.push(c);
        }
    }
    let base = name.len();
    for attempt in 0..65535u32 {
        let id = if unique != 0 {
            unique as u16
        } else {
            (attempt + 1) as u16
        };
        name.truncate(base);
        for shift in [12, 8, 4, 0] {
            name.push(b"0123456789ABCDEF"[((id >> shift) & 15) as usize]);
        }
        name.extend_from_slice(b".TMP\0");
        if unique == 0 {
            let handle = unsafe { CreateFileA(name.as_ptr() as u32, 0xc0000000, 0, 0, 1, 0, 0) };
            if handle == u32::MAX {
                if matches!(unsafe { GetLastError() }, 80 | 183) {
                    continue;
                }
                return 0;
            }
            unsafe {
                CloseHandle(handle);
            }
        }
        unsafe {
            core::ptr::copy_nonoverlapping(name.as_ptr(), out as *mut u8, name.len());
        }
        return u32::from(id);
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn LZCopy(source: u32, dest: u32) -> i32 {
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let mut got = 0;
        if unsafe { ReadFile(source, buf.as_mut_ptr() as u32, 4096, &mut got, 0) } == 0 {
            return -3;
        }
        if got == 0 {
            break;
        }
        if got > 4096 || data.len() + got as usize > 64 * 1024 * 1024 {
            return -5;
        }
        data.extend_from_slice(&buf[..got as usize]);
    }
    let output = match crate::szdd::expand(&data) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut sent = 0;
    while sent < output.len() {
        let mut done = 0;
        let n = (output.len() - sent).min(4096);
        if unsafe {
            WriteFile(
                dest,
                output.as_ptr().add(sent) as u32,
                n as u32,
                &mut done,
                0,
            )
        } == 0
            || done == 0
            || done as usize > n
        {
            return -4;
        }
        sent += done as usize;
    }
    sent as i32
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetWindowsDirectoryA(out: u32, capacity: u32) -> u32 {
    let path = b"C:\\RETROOS\\WINDOWS\0";
    if capacity < path.len() as u32 {
        return path.len() as u32;
    }
    if out == 0 {
        return 0;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(path.as_ptr(), out as *mut u8, path.len());
    }
    path.len() as u32 - 1
}
