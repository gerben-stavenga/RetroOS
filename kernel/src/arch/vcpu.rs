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
use super::paging2::RootPageTable;

/// Register state + address-space handle for one execution context. The shape is
/// shared across backends, so it is `arch_abi::Vcpu<P>` over this backend's
/// page-table type. Derefs to `Regs` so every `regs.rax` / `regs.mode()` keeps
/// working and a `&mut Vcpu` coerces where a `&mut Regs` is expected. Guest
/// memory comes from the blanket `GuestBytes for Vcpu<P>` impl in `arch-abi`,
/// forwarding to the `GuestBytes for RootPageTable` impl below.
pub type Vcpu = arch_abi::Vcpu<RootPageTable>;

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
impl GuestBytes for RootPageTable {
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
        let src = addr as *const u8;
        for (i, b) in dst.iter_mut().enumerate() {
            unsafe { *b = src.add(i).read_volatile(); }
        }
    }
    fn copy_to(&mut self, addr: usize, src: &[u8]) {
        let dst = addr as *mut u8;
        for (i, &b) in src.iter().enumerate() {
            unsafe { dst.add(i).write_volatile(b); }
        }
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
        let dst = addr as *mut u8;
        for i in 0..len {
            unsafe { dst.add(i).write_volatile(0); }
        }
    }
    fn copy_within(&mut self, src: usize, dst: usize, len: usize) {
        // Overlap-safe: copy back-to-front when the destination is above the
        // source, front-to-back otherwise.
        let s = src as *const u8;
        let d = dst as *mut u8;
        if dst > src {
            for i in (0..len).rev() { unsafe { d.add(i).write_volatile(s.add(i).read_volatile()); } }
        } else {
            for i in 0..len { unsafe { d.add(i).write_volatile(s.add(i).read_volatile()); } }
        }
    }
}

/// Seed the live execution context with `v`. Used for the very first thread,
/// which is entered directly rather than through a context switch (the swap
/// path otherwise owns `REGS`). The `static mut` access is confined here.
pub fn set_current_vcpu(v: Vcpu) {
    unsafe { *(&raw mut crate::arch::REGS) = v; }
}
