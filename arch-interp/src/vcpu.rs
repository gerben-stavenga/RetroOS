//! Vcpu and guest-memory access for the interpreter backend.
//!
//! Mirrors `kernel/src/arch/vcpu.rs` exactly in shape so the kernel is blind to
//! the backend. The one difference is where the bytes live: on metal a
//! guest-linear address *is* a host pointer (shared page tables); here it
//! indexes a flat host-side guest-RAM buffer. The raw access stays confined to
//! `GuestMem`, so kernel/dos code holds no `unsafe` of its own.

use crate::mmu;
use crate::space::RootPageTable;
use arch_abi::{GuestBytes, Regs};

/// Register state + address-space handle for one execution context. The shape
/// is shared across backends, so it is `arch_abi::Vcpu<P>` parameterized over
/// this backend's page-table type. Guest-memory access comes from the blanket
/// `GuestBytes for Vcpu<P>` impl in `arch-abi`, which forwards to the
/// `GuestBytes for RootPageTable` impl below.
pub type Vcpu = arch_abi::Vcpu<RootPageTable>;

/// The kernel-facing guest-memory primitive on this backend. Each access
/// commits the spanned pages then indexes the active guest-RAM buffer. Every
/// access is **volatile** (the guest/devices may observe and mutate the bytes)
/// and **bytewise** (any address/alignment is fine). No method hands out a
/// reference into guest memory: bytes are copied to/from a caller-owned buffer,
/// so kernel/dos code never asserts Rust's non-null / alignment / aliasing
/// invariants against guest RAM. `self` (the space id) is not consulted —
/// `host_ptr` resolves the *active* space, matching the prior behaviour. (The
/// inherent `GuestMem` API below stays for arch-internal callers — BIOS/screen
/// setup — that legitimately want slice views below the boundary.)
impl GuestBytes for RootPageTable {
    fn read<T: Copy>(&self, addr: usize) -> T {
        let size = core::mem::size_of::<T>();
        let src = host_ptr(addr, size) as *const u8;
        let mut v = core::mem::MaybeUninit::<T>::uninit();
        let dst = v.as_mut_ptr() as *mut u8;
        for i in 0..size {
            unsafe { dst.add(i).write(src.add(i).read_volatile()); }
        }
        unsafe { v.assume_init() }
    }
    fn write<T: Copy>(&mut self, addr: usize, val: T) {
        let size = core::mem::size_of::<T>();
        let dst = host_ptr(addr, size);
        let src = &val as *const T as *const u8;
        for i in 0..size {
            unsafe { dst.add(i).write_volatile(src.add(i).read()); }
        }
    }
    fn copy_from(&self, addr: usize, dst: &mut [u8]) {
        let src = host_ptr(addr, dst.len()) as *const u8;
        for (i, b) in dst.iter_mut().enumerate() {
            unsafe { *b = src.add(i).read_volatile(); }
        }
    }
    fn copy_to(&mut self, addr: usize, src: &[u8]) {
        let dst = host_ptr(addr, src.len());
        for (i, &b) in src.iter().enumerate() {
            unsafe { dst.add(i).write_volatile(b); }
        }
    }
    fn copy_cstr(&self, addr: usize, dst: &mut [u8]) -> usize {
        let base = host_ptr(addr, dst.len()) as *const u8;
        let mut n = 0;
        while n < dst.len() {
            let b = unsafe { base.add(n).read_volatile() };
            if b == 0 { break; }
            dst[n] = b;
            n += 1;
        }
        n
    }
    fn zero(&mut self, addr: usize, len: usize) {
        let dst = host_ptr(addr, len);
        for i in 0..len {
            unsafe { dst.add(i).write_volatile(0); }
        }
    }
    fn copy_within(&mut self, src: usize, dst: usize, len: usize) {
        // Commit both ranges, then an overlap-safe directional copy through the
        // contiguous active base (host_ptr returns base+addr, so the pointers
        // alias the same region).
        let s = host_ptr(src, len) as *const u8;
        let d = host_ptr(dst, len);
        if dst > src {
            for i in (0..len).rev() { unsafe { d.add(i).write_volatile(s.add(i).read_volatile()); } }
        } else {
            for i in 0..len { unsafe { d.add(i).write_volatile(s.add(i).read_volatile()); } }
        }
    }
}

/// The live execution context while the kernel runs (the interpreter's analogue
/// of metal's `traps::REGS`). Single-core: one global Vcpu that `do_arch_execute`
/// syncs to/from the software CPU before/after each run slice.
pub static mut REGS: Vcpu = Vcpu::new(Regs::empty(), RootPageTable::empty());

/// Seed the live execution context. The `static mut` access is confined here.
pub fn set_current_vcpu(v: Vcpu) {
    unsafe { *(&raw mut REGS) = v; }
}

/// Initialize guest memory: create the initial address space. The `len`
/// argument is vestigial (the MMU reserves the full user VA range per space);
/// kept for surface compatibility with the bring-up call site.
pub fn init_guest_ram(_len: usize) {
    mmu::init();
}

/// Host pointer for a guest address in the active space, demand-committing the
/// spanned pages. A reserved-contiguous VA window means this is a plain
/// `base + addr` once committed — so multi-page slices are sound.
#[inline]
fn host_ptr(addr: usize, len: usize) -> *mut u8 {
    mmu::ensure_committed(addr, len);
    unsafe { mmu::active_base().add(addr) }
}

/// The active address space's memory interface — `arch::mem()`. THE place the
/// kernel touches guest memory; the backend detail (software MMU vs page
/// tables) stays behind this identical API.
#[derive(Clone, Copy)]
pub struct GuestMem(());

#[inline]
pub fn mem() -> GuestMem { GuestMem(()) }

impl GuestMem {
    pub fn slice(self, addr: usize, len: usize) -> &'static [u8] {
        unsafe { core::slice::from_raw_parts(host_ptr(addr, len), len) }
    }
    pub fn slice_mut(self, addr: usize, len: usize) -> &'static mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(host_ptr(addr, len), len) }
    }
    pub fn c_str(self, addr: usize, max: usize) -> &'static [u8] {
        unsafe {
            let p = host_ptr(addr, max);
            let mut len = 0;
            while len < max && *p.add(len) != 0 { len += 1; }
            core::slice::from_raw_parts(p, len)
        }
    }
    pub fn read<T: Copy>(self, addr: usize) -> T {
        unsafe { core::ptr::read_unaligned(host_ptr(addr, core::mem::size_of::<T>()) as *const T) }
    }
    pub fn write<T: Copy>(self, addr: usize, val: T) {
        unsafe { core::ptr::write_unaligned(host_ptr(addr, core::mem::size_of::<T>()) as *mut T, val); }
    }
    pub fn at<T>(self, addr: usize) -> &'static mut T {
        unsafe { &mut *(host_ptr(addr, core::mem::size_of::<T>()) as *mut T) }
    }
    pub fn zero(self, addr: usize, len: usize) {
        unsafe { core::ptr::write_bytes(host_ptr(addr, len), 0, len); }
    }
    pub fn write_bytes(self, addr: usize, src: &[u8]) {
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), host_ptr(addr, src.len()), src.len()); }
    }
    pub fn copy_within(self, src: usize, dst: usize, len: usize) {
        // Commit both ranges, then an overlap-safe copy through the contiguous
        // active base (host_ptr returns base+addr, so the two pointers alias the
        // same region and `copy` handles overlap).
        unsafe { core::ptr::copy(host_ptr(src, len), host_ptr(dst, len), len); }
    }
}
