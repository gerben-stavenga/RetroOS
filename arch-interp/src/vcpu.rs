//! Vcpu and guest-memory access for the interpreter backend.
//!
//! User mappings are walked explicitly, then bytes are copied through their
//! physical backing. Kernel copies supply their own demand/COW backing.

use crate::paging;
use crate::space::RootPageTable;
use arch_abi::{GuestBytes, Regs};

/// Walk `[addr, addr+len)` one page-bounded chunk at a time, resolving each page
/// to a host pointer through the active page tables (demand-committing absent
/// pages). `on_chunk(host_ptr, offset_into_request, chunk_len)`. Replaces the
/// old "VA is a contiguous host pointer" model: under real paging the frames a
/// VA range lands on are scattered, so every guest access is page-split here.
#[cfg(feature = "tcg")]
#[inline]
fn for_chunks(addr: usize, len: usize, write: bool, mut on_chunk: impl FnMut(*mut u8, usize, usize)) {
    let mut off = 0;
    while off < len {
        let a = addr + off;
        let page_off = a & 0xFFF;
        let chunk = core::cmp::min(len - off, 4096 - page_off);
        let host = if write { paging::space_resolve_write(a as u32) } else { paging::space_resolve(a as u32) };
        on_chunk(host, off, chunk);
        off += chunk;
    }
}

#[cfg(feature = "tcg")]
fn copy_chunks(address: u64, len: usize, write: bool,
    mut copy: impl FnMut(*mut u8, usize, usize)) -> Option<()>
{
    if address.checked_add(len as u64)? > 0xc0000000 { return None; }
    let mut offset = 0;
    while offset < len {
        let at = address as usize + offset;
        let n = (len - offset).min(4096 - (at & 4095));
        copy(paging::copy_resolve(at as u32, write)?, offset, n);
        offset += n;
    }
    Some(())
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
#[cfg(feature = "tcg")]
impl GuestBytes for crate::backend::Interp {
    fn read<T: Copy>(&self, addr: u64) -> T {
        let addr = low_address(addr, core::mem::size_of::<T>());
        let size = core::mem::size_of::<T>();
        let mut v = core::mem::MaybeUninit::<T>::uninit();
        let dst = v.as_mut_ptr() as *mut u8;
        for_chunks(addr, size, false, |host, off, n| unsafe {
            for i in 0..n { dst.add(off + i).write((host as *const u8).add(i).read_volatile()); }
        });
        unsafe { v.assume_init() }
    }
    fn write<T: Copy>(&mut self, addr: u64, val: T) {
        let addr = low_address(addr, core::mem::size_of::<T>());
        let size = core::mem::size_of::<T>();
        let src = &val as *const T as *const u8;
        for_chunks(addr, size, true, |host, off, n| unsafe {
            for i in 0..n { host.add(i).write_volatile(src.add(off + i).read()); }
        });
        crate::engine::invalidate_code_range(addr as u32, size as u32);
    }
    fn copy_from(&self, addr: u64, dst: &mut [u8], pages: arch_abi::page_supply::PageInput) -> (Option<()>, arch_abi::page_supply::PageInput) {
        crate::phys::with_input(pages, || copy_chunks(addr, dst.len(), false, |host, offset, n| unsafe {
            for i in 0..n { dst[offset + i] = host.add(i).read_volatile(); }
        }))
    }
    fn copy_to(&mut self, addr: u64, src: &[u8], pages: arch_abi::page_supply::PageInput) -> (Option<()>, arch_abi::page_supply::PageInput) {
        let result = crate::phys::with_input(pages, || copy_chunks(addr, src.len(), true, |host, offset, n| unsafe {
            for i in 0..n { host.add(i).write_volatile(src[offset + i]); }
        }));
        if addr < 0xc0000000 { crate::engine::invalidate_code_range(addr as u32, src.len() as u32); }
        result
    }
    fn copy_cstr(&self, addr: u64, dst: &mut [u8]) -> usize {
        let addr = low_address(addr, dst.len());
        let mut n = 0;
        while n < dst.len() {
            let b = unsafe { (paging::space_resolve((addr + n) as u32) as *const u8).read_volatile() };
            if b == 0 { break; }
            dst[n] = b;
            n += 1;
        }
        n
    }
    fn zero(&mut self, addr: u64, len: usize) {
        let addr = low_address(addr, len);
        for_chunks(addr, len, true, |host, _off, n| unsafe {
            core::ptr::write_bytes(host, 0, n);
        });
        crate::engine::invalidate_code_range(addr as u32, len as u32);
    }
    fn copy_within(&mut self, src: u64, dst: u64, len: usize) {
        let src = low_address(src, len);
        let dst = low_address(dst, len);
        // Frames are scattered under real paging, so there is no single aliased
        // region: resolve each byte through the page tables in the overlap-safe
        // direction. Not on the guest hot path (DOS loaders, relocation).
        if dst > src {
            for i in (0..len).rev() {
                let b = unsafe { (paging::space_resolve((src + i) as u32) as *const u8).read_volatile() };
                unsafe { paging::space_resolve_write((dst + i) as u32).write_volatile(b); }
            }
        } else {
            for i in 0..len {
                let b = unsafe { (paging::space_resolve((src + i) as u32) as *const u8).read_volatile() };
                unsafe { paging::space_resolve_write((dst + i) as u32).write_volatile(b); }
            }
        }
        crate::engine::invalidate_code_range(dst as u32, len as u32);
    }
}

/// The live execution context while the kernel runs (the interpreter's analogue
/// of metal's `traps::REGS`). Single-core: one global Vcpu that `do_arch_execute`
/// syncs to/from the software CPU before/after each run slice.
pub static mut REGS: Vcpu = Vcpu::new(Regs::empty(), RootPageTable::empty());


/// Install caller-owned fixed paging storage. No allocation occurs here.
/// # Safety
/// The contiguous PAGING_PAGES frames must be zeroed, resident and exclusively
/// owned for the lifetime of this CPU.
pub unsafe fn init_guest_ram(storage: u64, ownership: arch_abi::page_supply::FrameOwnership) {
    crate::phys::configure(ownership);
    unsafe { paging::initialize(storage); }
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
        crate::backend::Interp.read::<T>(addr as u64)
    }
    pub fn write<T: Copy>(self, addr: usize, val: T) {
        crate::backend::Interp.write::<T>(addr as u64, val);
    }
    pub fn at<T>(self, addr: usize) -> &'static mut T {
        debug_assert!((addr & 0xFFF) + core::mem::size_of::<T>() <= 4096, "GuestMem::at crosses a page");
        unsafe { &mut *(host_ptr(addr, core::mem::size_of::<T>()) as *mut T) }
    }
    pub fn zero(self, addr: usize, len: usize) {
        crate::backend::Interp.zero(addr as u64, len);
    }
    pub fn write_bytes(self, addr: usize, src: &[u8]) {
        for (index, byte) in src.iter().enumerate() { crate::backend::Interp.write(addr as u64 + index as u64, *byte); }
    }
    pub fn copy_within(self, src: usize, dst: usize, len: usize) {
        crate::backend::Interp.copy_within(src as u64, dst as u64, len);
    }
}

#[cfg(any(feature = "tcg", test))]
fn low_address(address: u64, length: usize) -> usize {
    assert!(address.checked_add(length as u64).is_some_and(|end| end <= 0xc0000000), "unsupported guest address");
    address as usize
}

#[cfg(test)]
mod tests {
    #[test]
    #[should_panic(expected = "unsupported guest address")]
    fn high_guest_address_cannot_alias_low_memory() {
        super::low_address(0x1_0000_1000, 1);
    }
}
