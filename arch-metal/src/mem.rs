//! `memset`/`memcpy`/`memmove` for the metal kernel, via x86 fast strings.
//!
//! These override the weak symbols `compiler-builtins` supplies. That
//! implementation is a portable scalar loop, and on this hardware it is not
//! close: measured on a Ryzen 9 8945HS over 3 MB,
//!
//!     compiler-builtins fill   2.49 B/cycle
//!     hand-rolled u32 loop     4.94 B/cycle
//!     rep stosd               26.57 B/cycle
//!     rep stosb               33.39 B/cycle
//!
//! `rep stosb`/`rep movsb` are 13x the portable version because fast-string
//! microcode moves a cache line per step rather than a register. Working set
//! made no difference (3 MB and 256 KB measured the same), so this is purely
//! about how the stores are issued, not cache or bandwidth.
//!
//! Every bulk memory operation in the kernel goes through these — the VGA
//! blit's row copies, `vga_render`'s frame clear, the ext4 block cache, every
//! `Vec` growth — so the win is not confined to any one path.
//!
//! DF is cleared explicitly: the ABI says it is clear at function entry, but
//! these run from interrupt and trap context too, where that is a promise
//! nobody made.

/// Fill `n` bytes at `dest` with `c`.
///
/// # Safety
/// `dest` must be valid for `n` writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    unsafe {
        core::arch::asm!(
            "cld",
            "rep stosb",
            inout("edi") dest => _,
            inout("ecx") n => _,
            in("eax") c as u32,
            options(nostack, preserves_flags),
        );
    }
    dest
}

/// Copy `n` bytes from `src` to `dest`. The regions must not overlap.
///
/// # Safety
/// Both pointers must be valid for `n` bytes, and the regions disjoint.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // ESI is reserved by LLVM on x86-32, so it is saved and loaded inside the
    // block rather than named as an operand (hence no `nostack`: we push).
    unsafe {
        core::arch::asm!(
            "push esi",
            "mov esi, {src}",
            "cld",
            "rep movsb",
            "pop esi",
            src = in(reg) src,
            inout("edi") dest => _,
            inout("ecx") n => _,
            options(preserves_flags),
        );
    }
    dest
}

/// Copy `n` bytes from `src` to `dest`, correct when the regions overlap.
///
/// # Safety
/// Both pointers must be valid for `n` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if (dest as usize) < (src as usize) || (dest as usize) >= (src as usize) + n {
        return unsafe { memcpy(dest, src, n) };
    }
    // Overlapping with dest above src: copy downward so a byte is read before
    // it is overwritten. `std` (direction flag set) makes the string ops step
    // backwards; it must be cleared again before returning — the rest of the
    // kernel, and the ABI, assume DF=0.
    if n != 0 {
        unsafe {
            core::arch::asm!(
                "push esi",
                "mov esi, {src}",
                "std",
                "rep movsb",
                "cld",
                "pop esi",
                src = in(reg) src.add(n - 1),
                inout("edi") dest.add(n - 1) => _,
                inout("ecx") n => _,
                options(preserves_flags),
            );
        }
    }
    dest
}
