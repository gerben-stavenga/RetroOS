//! Freestanding C-runtime shim for the vendored lwext4 (metal backend).
//!
//! lwext4's entire external symbol surface is 15 functions (per the feasibility
//! spike). `mem*` and `__udivdi3`/`__umoddi3` come from `compiler-builtins`;
//! this module provides the remaining 9 — the allocator (routed to the kernel's
//! global heap) plus five `str*` and `qsort`.
//!
//! It lives in `arch-metal` — the metal-only backend — precisely so it needs NO
//! `cfg` gate: `arch-metal` is never linked into the hosted build, so these
//! `#[no_mangle]` names can't collide with the host libc. Backend-specific
//! runtime support belongs below the arch boundary, not as kernel policy.

extern crate alloc;

use core::alloc::Layout;

// `malloc`/`free` stash the allocation size in a 16-byte header so `free` can
// rebuild the exact `Layout` that `GlobalAlloc` requires (C's `free` gets no
// size). 16 bytes keeps the returned pointer 16-aligned — enough for any
// lwext4 structure.
const HDR: usize = 16;
const ALIGN: usize = 16;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn malloc(size: usize) -> *mut u8 {
    if size == 0 {
        return core::ptr::null_mut();
    }
    let Some(total) = size.checked_add(HDR) else {
        return core::ptr::null_mut();
    };
    let Ok(layout) = Layout::from_size_align(total, ALIGN) else {
        return core::ptr::null_mut();
    };
    let base = unsafe { alloc::alloc::alloc(layout) };
    if base.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        *(base as *mut usize) = total;
        base.add(HDR)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn calloc(nmemb: usize, size: usize) -> *mut u8 {
    let Some(total) = nmemb.checked_mul(size) else {
        return core::ptr::null_mut();
    };
    let p = unsafe { malloc(total) };
    if !p.is_null() {
        unsafe { core::ptr::write_bytes(p, 0, total) };
    }
    p
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let base = ptr.sub(HDR);
        let total = *(base as *mut usize);
        let layout = Layout::from_size_align_unchecked(total, ALIGN);
        alloc::alloc::dealloc(base, layout);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    let mut n = 0;
    while unsafe { *s.add(n) } != 0 {
        n += 1;
    }
    n
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcmp(a: *const u8, b: *const u8) -> i32 {
    // C compares as `unsigned char`; u8 arithmetic gives the correct sign.
    let mut i = 0;
    loop {
        let (ca, cb) = unsafe { (*a.add(i), *b.add(i)) };
        if ca != cb {
            return ca as i32 - cb as i32;
        }
        if ca == 0 {
            return 0;
        }
        i += 1;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strncmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let (ca, cb) = unsafe { (*a.add(i), *b.add(i)) };
        if ca != cb {
            return ca as i32 - cb as i32;
        }
        if ca == 0 {
            return 0;
        }
        i += 1;
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcpy(dst: *mut u8, src: *const u8) -> *mut u8 {
    let mut i = 0;
    loop {
        let c = unsafe { *src.add(i) };
        unsafe { *dst.add(i) = c };
        if c == 0 {
            break;
        }
        i += 1;
    }
    dst
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strncpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // Copy up to a NUL, then zero-pad the remainder to `n` (C semantics).
    let mut i = 0;
    let mut hit_nul = false;
    while i < n {
        let c = if hit_nul { 0 } else { unsafe { *src.add(i) } };
        if c == 0 {
            hit_nul = true;
        }
        unsafe { *dst.add(i) = c };
        i += 1;
    }
    dst
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qsort(
    base: *mut u8,
    nmemb: usize,
    size: usize,
    cmp: unsafe extern "C" fn(*const u8, *const u8) -> i32,
) {
    // Insertion sort with byte-wise swaps. lwext4 only sorts small arrays
    // (extent records, directory entries), so O(n²) is fine and — unlike a
    // quicksort — it needs no size-parameterized scratch buffer.
    if size == 0 {
        return;
    }
    for i in 1..nmemb {
        let mut j = i;
        while j > 0 {
            let a = unsafe { base.add((j - 1) * size) };
            let b = unsafe { base.add(j * size) };
            if unsafe { cmp(a, b) } > 0 {
                for k in 0..size {
                    unsafe { core::ptr::swap(a.add(k), b.add(k)) };
                }
                j -= 1;
            } else {
                break;
            }
        }
    }
}
