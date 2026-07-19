//! Vcpu — one execution context: register state plus the address space it
//! runs in.
//!
//! This is the unit `arch` hands the kernel: "a set of registers and a place
//! to run them." Bundling the two is what lets the kernel stop caring whether
//! it is driving real silicon or a software interpreter — both can present a
//! `Vcpu`.
//!
//! Single-core for now, so `space` is simply the thread's full per-thread
//! page-table root. When multiple cores share one address space (SMP), `space`
//! becomes a shared handle and the per-core register state stays here; the
//! kernel-facing shape of this type does not change.

use arch_abi::GuestBytes;

/// Register state + address-space handle for one execution context. The shape is
/// shared across backends, so it is `arch_abi::Vcpu<P>` over this backend's
/// page-table type. Derefs to `Regs` so every `regs.rax` / `regs.mode()` keeps
/// working and a `&mut Vcpu` coerces where a `&mut Regs` is expected. Guest
/// memory comes from the blanket `GuestBytes for Vcpu<P>` impl in `arch-abi`,
/// forwarding to the `GuestBytes for RootPageTable` impl below.
pub type Vcpu = arch_abi::Vcpu<crate::backend::Metal>;

/// Bulk guest-memory moves via x86 fast strings.
///
/// These keep the `GuestBytes` contract — no reference into guest memory is
/// ever formed, only raw pointers — while replacing per-byte `read_volatile`
/// loops that ran at ~0.5 bytes/cycle. `rep movsb` is a single instruction the
/// compiler cannot elide, reorder against other memory, or coalesce, so the
/// volatility the contract asks for is preserved; it is byte-granular, so
/// unaligned guest addresses are still fine. Measured ~30 bytes/cycle, ~60x the
/// loop it replaces, and every guest copy in the system goes through it: DOS
/// file reads and writes, the VGA aperture scanout, EMS/XMS block moves.
///
/// ESI is saved inside the block rather than named as an operand; LLVM reserves
/// it on x86-32.
#[inline]
unsafe fn rep_movsb(dst: *mut u8, src: *const u8, len: usize) {
    unsafe {
        core::arch::asm!(
            "push esi",
            "mov esi, {src}",
            "cld",
            "rep movsb",
            "pop esi",
            src = in(reg) src,
            inout("edi") dst => _,
            inout("ecx") len => _,
            options(preserves_flags),
        );
    }
}

/// Backwards `rep movsb` for an upward-overlapping move; pointers address the
/// LAST byte of each region. Clears DF before returning — the rest of the
/// kernel, and the ABI, assume DF=0.
#[inline]
unsafe fn rep_movsb_back(dst_last: *mut u8, src_last: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    unsafe {
        core::arch::asm!(
            "push esi",
            "mov esi, {src}",
            "std",
            "rep movsb",
            "cld",
            "pop esi",
            src = in(reg) src_last,
            inout("edi") dst_last => _,
            inout("ecx") len => _,
            options(preserves_flags),
        );
    }
}

#[inline]
unsafe fn rep_stosb(dst: *mut u8, val: u8, len: usize) {
    unsafe {
        core::arch::asm!(
            "cld",
            "rep stosb",
            inout("edi") dst => _,
            inout("ecx") len => _,
            in("eax") val as u32,
            options(nostack, preserves_flags),
        );
    }
}


/// The metal guest-memory primitive. On the ring-1 kernel a guest-linear address
/// *is* a host pointer (shared page tables), so these dereference it directly.
/// Every access is **volatile** (guest/BIOS/devices may observe and mutate the
/// bytes) and **bytewise** (so any address/alignment is fine — a DOS guest puts
/// live structures at address 0 and at unaligned paragraph addresses). No method
/// hands out a reference into guest memory: bytes are copied to/from a
/// caller-owned buffer, so kernel/dos code never asserts Rust's non-null /
/// alignment / aliasing invariants against guest RAM, and holds no `unsafe`.
/// `self` (the page-table root) is not consulted — the access reaches the active
/// mapping (single-core; one space is live at a time).
impl GuestBytes for crate::backend::Metal {
    fn read<T: Copy>(&self, addr: usize) -> T {
        let mut v = core::mem::MaybeUninit::<T>::uninit();
        let dst = v.as_mut_ptr() as *mut u8;
        let src = addr as *const u8;
        for i in 0..core::mem::size_of::<T>() {
            unsafe { dst.add(i).write(src.add(i).read_volatile()); }
        }
        unsafe { v.assume_init() }
    }
    fn write<T: Copy>(&mut self, addr: usize, val: T) {
        let src = &val as *const T as *const u8;
        let dst = addr as *mut u8;
        for i in 0..core::mem::size_of::<T>() {
            unsafe { dst.add(i).write_volatile(src.add(i).read()); }
        }
    }
    fn copy_from(&self, addr: usize, dst: &mut [u8]) {
        unsafe { rep_movsb(dst.as_mut_ptr(), addr as *const u8, dst.len()) };
    }
    fn copy_to(&mut self, addr: usize, src: &[u8]) {
        unsafe { rep_movsb(addr as *mut u8, src.as_ptr(), src.len()) };
    }
    fn copy_cstr(&self, addr: usize, dst: &mut [u8]) -> usize {
        let src = addr as *const u8;
        let mut n = 0;
        while n < dst.len() {
            let b = unsafe { src.add(n).read_volatile() };
            if b == 0 { break; }
            dst[n] = b;
            n += 1;
        }
        n
    }
    fn zero(&mut self, addr: usize, len: usize) {
        unsafe { rep_stosb(addr as *mut u8, 0, len) };
    }
    fn copy_within(&mut self, src: usize, dst: usize, len: usize) {
        // Overlap-safe: copy back-to-front when the destination is above the
        // source, front-to-back otherwise.
        if dst > src && dst < src + len {
            unsafe { rep_movsb_back((dst + len - 1) as *mut u8, (src + len - 1) as *const u8, len) };
        } else {
            unsafe { rep_movsb(dst as *mut u8, src as *const u8, len) };
        }
    }
}

