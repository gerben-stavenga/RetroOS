//! Small Win32 helpers execute in the guest; OS services remain kernel gates.
#![no_std]
#![allow(non_snake_case)]
#![deny(unsafe_op_in_unsafe_fn)]
extern crate alloc;
mod profile;
mod resource;
#[allow(dead_code)]
#[path = "../user32/runtime.rs"]
mod runtime;

unsafe extern "system" {
    fn CompareStringA(locale: u32, flags: u32, a: u32, an: i32, b: u32, bn: i32) -> i32;
    fn CompareStringW(locale: u32, flags: u32, a: u32, an: i32, b: u32, bn: i32) -> i32;
    pub fn GetModuleHandleA(name: u32) -> u32;
    pub fn SetLastError(code: u32);
}
macro_rules! strings {
    ($unit:ty, $len:ident, $copy:ident, $copyn:ident, $cmp:ident, $cmpi:ident, $compare:ident) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $len(s: *const $unit) -> i32 {
            if s.is_null() {
                return 0;
            }
            let mut n = 0;
            while unsafe { s.add(n).read_unaligned() } != 0 {
                n += 1;
            }
            n as i32
        }
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $copy(dst: *mut $unit, src: *const $unit) -> *mut $unit {
            if dst.is_null() || src.is_null() {
                return core::ptr::null_mut();
            }
            let mut n = 0;
            loop {
                let c = unsafe { src.add(n).read_unaligned() };
                unsafe {
                    dst.add(n).write_unaligned(c);
                }
                if c == 0 {
                    return dst;
                }
                n += 1;
            }
        }
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $copyn(
            dst: *mut $unit,
            src: *const $unit,
            count: i32,
        ) -> *mut $unit {
            if count <= 0 {
                return dst;
            }
            if dst.is_null() || src.is_null() {
                return core::ptr::null_mut();
            }
            for n in 0..(count - 1) as usize {
                let c = unsafe { src.add(n).read_unaligned() };
                unsafe {
                    dst.add(n).write_unaligned(c);
                }
                if c == 0 {
                    return dst;
                }
            }
            unsafe {
                dst.add((count - 1) as usize).write_unaligned(0);
            }
            dst
        }
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $cmp(a: u32, b: u32) -> i32 {
            unsafe { $compare(0x400, 0, a, -1, b, -1) - 2 }
        }
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $cmpi(a: u32, b: u32) -> i32 {
            unsafe { $compare(0x400, 1, a, -1, b, -1) - 2 }
        }
    };
}
strings!(
    u8,
    lstrlenA,
    lstrcpyA,
    lstrcpynA,
    lstrcmpA,
    lstrcmpiA,
    CompareStringA
);
strings!(
    u16,
    lstrlenW,
    lstrcpyW,
    lstrcpynW,
    lstrcmpW,
    lstrcmpiW,
    CompareStringW
);

#[unsafe(no_mangle)]
pub extern "system" fn MulDiv(number: i32, numerator: i32, denominator: i32) -> i32 {
    if denominator == 0 {
        return -1;
    }
    let product = i64::from(number) * i64::from(numerator);
    let negative = (product < 0) != (denominator < 0);
    let magnitude = (product.unsigned_abs() + i64::from(denominator).unsigned_abs() / 2)
        / i64::from(denominator).unsigned_abs();
    let result = if negative {
        -(magnitude as i64)
    } else {
        magnitude as i64
    };
    i32::try_from(result).unwrap_or(-1)
}

// LLVM may lower lstrlenA's scan to a C runtime call. Supply it in the DLL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    let mut n = 0;
    while unsafe { s.add(n).read_volatile() } != 0 {
        n += 1;
    }
    n
}
