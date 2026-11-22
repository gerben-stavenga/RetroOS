//! Vcpu and guest-memory access for the interpreter backend.
//!
//! User mappings are walked explicitly, then bytes are copied through their
//! physical backing. Kernel copies supply their own demand/COW backing.

use crate::paging;
use crate::space::AddressSpace;
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

/// Saved CPU state and its parked address space.
pub type Vcpu = arch_abi::Vcpu<crate::backend::Interp>;

/// Copy bytes through the currently active guest mappings.
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
pub static mut REGS: Vcpu = Vcpu::new(Regs::empty(), AddressSpace::empty());


/// Start the hosted backend and hand control to the supplied kernel entry.
///
/// # Safety
/// Call once on the thread that will run this backend. The caller must keep
/// the ownership metadata resident and reserve `boot_paging_frames()` for arch.
pub unsafe fn boot<S>(
    ownership: arch_abi::page_supply::FrameOwnership,
    config: &arch_abi::BootConfig,
    storage: S,
    kernel_entry: fn(&mut crate::Interp, &arch_abi::BootConfig, S) -> !,
) -> ! {
    unsafe { boot_cpu(crate::phys::boot_paging_frames().start, ownership); }
    kernel_entry(&mut crate::Interp::local(), config, storage)
}

/// # Safety
/// The paging frames must be zeroed, resident and exclusively owned.
/// The ownership metadata must remain resident for the lifetime of the CPU.
pub(crate) unsafe fn boot_cpu(storage: u64, ownership: arch_abi::page_supply::FrameOwnership) {
    crate::phys::configure(ownership);
    unsafe { paging::initialize(storage); }
}

/// Local access to the current guest mappings for hosted diagnostics and tests.
#[derive(Clone, Copy)]
pub struct GuestMem(core::marker::PhantomData<*mut ()>);

#[inline]
pub fn mem() -> GuestMem { GuestMem(core::marker::PhantomData) }

impl GuestMem {
    pub fn read<T: Copy>(self, addr: usize) -> T {
        crate::backend::Interp::local().read::<T>(addr as u64)
    }
    pub fn write<T: Copy>(self, addr: usize, val: T) {
        crate::backend::Interp::local().write::<T>(addr as u64, val);
    }
    pub fn zero(self, addr: usize, len: usize) {
        crate::backend::Interp::local().zero(addr as u64, len);
    }
    pub fn write_bytes(self, addr: usize, src: &[u8]) {
        for (index, byte) in src.iter().enumerate() { crate::backend::Interp::local().write(addr as u64 + index as u64, *byte); }
    }
    pub fn copy_within(self, src: usize, dst: usize, len: usize) {
        crate::backend::Interp::local().copy_within(src as u64, dst as u64, len);
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
