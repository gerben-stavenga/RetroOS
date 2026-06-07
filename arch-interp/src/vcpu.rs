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

/// The one real guest-memory primitive on this backend: index the active
/// guest-RAM buffer (`mem()`). The forwarders that used to be inherent methods
/// on `Vcpu` now hang off the page-table handle, which is where `arch-abi`'s
/// blanket `Vcpu`/`Arch` `GuestBytes` impls route. `self` (the space id) is not
/// consulted — `mem()` is the *active* space, matching the prior behaviour.
impl GuestBytes for RootPageTable {
    fn slice(&self, addr: usize, len: usize) -> &[u8] { mem().slice(addr, len) }
    fn slice_mut(&mut self, addr: usize, len: usize) -> &mut [u8] { mem().slice_mut(addr, len) }
    fn c_str(&self, addr: usize, max: usize) -> &[u8] { mem().c_str(addr, max) }
    fn read<T: Copy>(&self, addr: usize) -> T { mem().read(addr) }
    fn write<T: Copy>(&mut self, addr: usize, val: T) { mem().write(addr, val) }
    fn zero(&mut self, addr: usize, len: usize) { mem().zero(addr, len) }
    fn write_bytes(&mut self, addr: usize, src: &[u8]) { mem().write_bytes(addr, src) }
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
