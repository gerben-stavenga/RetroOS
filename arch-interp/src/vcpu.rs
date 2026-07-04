//! Vcpu and guest-memory access for the interpreter backend.
//!
//! Mirrors `kernel/src/arch/vcpu.rs` exactly in shape so the kernel is blind to
//! the backend. The one difference is where the bytes live: on metal a
//! guest-linear address *is* a host pointer (shared page tables); here it
//! indexes a flat host-side guest-RAM buffer. The raw access stays confined to
//! `GuestMem`, so kernel/dos code holds no `unsafe` of its own.

use crate::mmu;
use crate::paging;
use crate::space::RootPageTable;
use arch_abi::{GuestBytes, Regs};

/// Walk `[addr, addr+len)` one page-bounded chunk at a time, resolving each page
/// to a host pointer through the active page tables (demand-committing absent
/// pages). `on_chunk(host_ptr, offset_into_request, chunk_len)`. Replaces the
/// old "VA is a contiguous host pointer" model: under real paging the frames a
/// VA range lands on are scattered, so every guest access is page-split here.
#[inline]
fn for_chunks(addr: usize, len: usize, mut on_chunk: impl FnMut(*mut u8, usize, usize)) {
    let mut off = 0;
    while off < len {
        let a = addr + off;
        let page_off = a & 0xFFF;
        let chunk = core::cmp::min(len - off, 4096 - page_off);
        let host = paging::space_resolve(a as u32);
        on_chunk(host, off, chunk);
        off += chunk;
    }
}

/// Register state + address-space handle for one execution context. The shape
/// is shared across backends, so it is `arch_abi::Vcpu<P>` parameterized over
/// this backend's page-table type. Guest-memory access comes from the blanket
/// `GuestBytes for Vcpu<P>` impl in `arch-abi`, which forwards to the
/// `GuestBytes for RootPageTable` impl below.
pub type Vcpu = arch_abi::Vcpu<crate::backend::Interp>;

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
        let mut v = core::mem::MaybeUninit::<T>::uninit();
        let dst = v.as_mut_ptr() as *mut u8;
        for_chunks(addr, size, |host, off, n| unsafe {
            for i in 0..n { dst.add(off + i).write((host as *const u8).add(i).read_volatile()); }
        });
        unsafe { v.assume_init() }
    }
    fn write<T: Copy>(&mut self, addr: usize, val: T) {
        let size = core::mem::size_of::<T>();
        let src = &val as *const T as *const u8;
        for_chunks(addr, size, |host, off, n| unsafe {
            for i in 0..n { host.add(i).write_volatile(src.add(off + i).read()); }
        });
        crate::engine::invalidate_code_range(addr as u32, size as u32);
    }
    fn copy_from(&self, addr: usize, dst: &mut [u8]) {
        for_chunks(addr, dst.len(), |host, off, n| unsafe {
            for i in 0..n { dst[off + i] = (host as *const u8).add(i).read_volatile(); }
        });
    }
    fn copy_to(&mut self, addr: usize, src: &[u8]) {
        for_chunks(addr, src.len(), |host, off, n| unsafe {
            for i in 0..n { host.add(i).write_volatile(src[off + i]); }
        });
        crate::engine::invalidate_code_range(addr as u32, src.len() as u32);
    }
    fn copy_cstr(&self, addr: usize, dst: &mut [u8]) -> usize {
        let mut n = 0;
        while n < dst.len() {
            let b = unsafe { (paging::space_resolve((addr + n) as u32) as *const u8).read_volatile() };
            if b == 0 { break; }
            dst[n] = b;
            n += 1;
        }
        n
    }
    fn zero(&mut self, addr: usize, len: usize) {
        for_chunks(addr, len, |host, _off, n| unsafe {
            core::ptr::write_bytes(host, 0, n);
        });
        crate::engine::invalidate_code_range(addr as u32, len as u32);
    }
    fn copy_within(&mut self, src: usize, dst: usize, len: usize) {
        // Frames are scattered under real paging, so there is no single aliased
        // region: resolve each byte through the page tables in the overlap-safe
        // direction. Not on the guest hot path (DOS loaders, relocation).
        if dst > src {
            for i in (0..len).rev() {
                let b = unsafe { (paging::space_resolve((src + i) as u32) as *const u8).read_volatile() };
                unsafe { paging::space_resolve((dst + i) as u32).write_volatile(b); }
            }
        } else {
            for i in 0..len {
                let b = unsafe { (paging::space_resolve((src + i) as u32) as *const u8).read_volatile() };
                unsafe { paging::space_resolve((dst + i) as u32).write_volatile(b); }
            }
        }
        crate::engine::invalidate_code_range(dst as u32, len as u32);
    }
}

/// The live execution context while the kernel runs (the interpreter's analogue
/// of metal's `traps::REGS`). Single-core: one global Vcpu that `do_arch_execute`
/// syncs to/from the software CPU before/after each run slice.
pub static mut REGS: Vcpu = Vcpu::new(Regs::empty(), RootPageTable::empty());

/// Seed the live execution context. The `static mut` access is confined here.
pub fn set_current_vcpu(v: Vcpu) {
    unsafe { REGS = v; }
}

/// Initialize guest memory: create the initial address space. The `len`
/// argument is vestigial (the MMU reserves the full user VA range per space);
/// kept for surface compatibility with the bring-up call site.
pub fn init_guest_ram(_len: usize) {
    mmu::init();
}

/// Host pointer for a guest address in the active space, demand-committing the
/// page. Under real paging the backing frames are scattered, so the returned
/// pointer is valid only within the page containing `addr` — callers that span
/// more than one page must page-split (`for_chunks` / the `GuestBytes` impl).
#[inline]
fn host_ptr(addr: usize, _len: usize) -> *mut u8 {
    paging::space_resolve(addr as u32)
}

/// The active address space's memory interface — `arch::mem()`. THE place the
/// kernel touches guest memory; the backend detail (software MMU vs page
/// tables) stays behind this identical API.
#[derive(Clone, Copy)]
pub struct GuestMem(());

#[inline]
pub fn mem() -> GuestMem { GuestMem(()) }

// The slice/at views below hand out a contiguous host reference, which under
// real paging is only sound within one page. They are arch-internal and (per
// audit) span at most a single small struct/cell, so the page guard holds; the
// kernel-facing API is the page-splitting `GuestBytes` impl above.
impl GuestMem {
    pub fn slice(self, addr: usize, len: usize) -> &'static [u8] {
        debug_assert!((addr & 0xFFF) + len <= 4096, "GuestMem::slice crosses a page");
        unsafe { core::slice::from_raw_parts(host_ptr(addr, len), len) }
    }
    pub fn slice_mut(self, addr: usize, len: usize) -> &'static mut [u8] {
        debug_assert!((addr & 0xFFF) + len <= 4096, "GuestMem::slice_mut crosses a page");
        unsafe { core::slice::from_raw_parts_mut(host_ptr(addr, len), len) }
    }
    pub fn c_str(self, addr: usize, max: usize) -> &'static [u8] {
        unsafe {
            let p = host_ptr(addr, max);
            let mut len = 0;
            while len < max && (addr & 0xFFF) + len < 4096 && *p.add(len) != 0 { len += 1; }
            core::slice::from_raw_parts(p, len)
        }
    }
    pub fn read<T: Copy>(self, addr: usize) -> T {
        RootPageTable::empty().read::<T>(addr)
    }
    pub fn write<T: Copy>(self, addr: usize, val: T) {
        RootPageTable::empty().write::<T>(addr, val);
    }
    pub fn at<T>(self, addr: usize) -> &'static mut T {
        debug_assert!((addr & 0xFFF) + core::mem::size_of::<T>() <= 4096, "GuestMem::at crosses a page");
        unsafe { &mut *(host_ptr(addr, core::mem::size_of::<T>()) as *mut T) }
    }
    pub fn zero(self, addr: usize, len: usize) {
        RootPageTable::empty().zero(addr, len);
    }
    pub fn write_bytes(self, addr: usize, src: &[u8]) {
        RootPageTable::empty().copy_to(addr, src);
    }
    pub fn copy_within(self, src: usize, dst: usize, len: usize) {
        RootPageTable::empty().copy_within(src, dst, len);
    }
}
