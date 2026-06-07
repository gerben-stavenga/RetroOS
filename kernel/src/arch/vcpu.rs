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

use crate::Regs;
use arch_abi::GuestBytes;
use super::paging2::RootPageTable;

/// Register state + address-space handle for one execution context. The shape is
/// shared across backends, so it is `arch_abi::Vcpu<P>` over this backend's
/// page-table type. Derefs to `Regs` so every `regs.rax` / `regs.mode()` keeps
/// working and a `&mut Vcpu` coerces where a `&mut Regs` is expected. Guest
/// memory comes from the blanket `GuestBytes for Vcpu<P>` impl in `arch-abi`,
/// forwarding to the `GuestBytes for RootPageTable` impl below.
pub type Vcpu = arch_abi::Vcpu<RootPageTable>;

/// The metal guest-memory primitive: on the ring-1 kernel a guest-linear address
/// *is* a host pointer (shared page tables), so these dereference it directly via
/// `mem()`. The raw access stays confined here; kernel/dos code holds no
/// `unsafe`. `self` (the page-table root) is not consulted — `mem()` reaches the
/// active mapping, matching the prior `Vcpu` forwarder behaviour.
impl GuestBytes for RootPageTable {
    fn slice(&self, addr: usize, len: usize) -> &[u8] { mem().slice(addr, len) }
    fn slice_mut(&mut self, addr: usize, len: usize) -> &mut [u8] { mem().slice_mut(addr, len) }
    fn c_str(&self, addr: usize, max: usize) -> &[u8] { mem().c_str(addr, max) }
    fn read<T: Copy>(&self, addr: usize) -> T { mem().read(addr) }
    fn write<T: Copy>(&mut self, addr: usize, val: T) { mem().write(addr, val) }
    fn zero(&mut self, addr: usize, len: usize) { mem().zero(addr, len) }
    fn write_bytes(&mut self, addr: usize, src: &[u8]) { mem().write_bytes(addr, src) }
}

/// The active address space's memory interface — `arch::mem()`.
///
/// This is THE place the kernel touches guest memory. On the hardware backend
/// the ring-1 kernel shares the guest's page tables, so a guest-linear address
/// is already a valid host pointer and these methods dereference it; the raw
/// access is confined here. A software-interpreter backend would index its
/// guest-RAM buffer instead, behind the identical API — so `kernel`/`dos` code
/// calls `arch::mem()` and never learns which backend is underneath, and holds
/// no `unsafe` of its own.
///
/// Memory belongs to the *address space*, not the per-core registers: many
/// vcpus (cores) can share one address space, so this is keyed off the active
/// space, not a specific Vcpu. `mem()` returns the current space; a
/// space-parameterized form is the natural extension for cross-space access.
///
/// `addr` is a guest-linear address as `usize` (the 32-bit kernel addresses all
/// guest memory within 4 GiB).
#[derive(Clone, Copy)]
pub struct GuestMem(());

/// Memory interface for the currently-active address space (see `GuestMem`).
#[inline]
pub fn mem() -> GuestMem { GuestMem(()) }

/// Seed the live execution context with `v`. Used for the very first thread,
/// which is entered directly rather than through a context switch (the swap
/// path otherwise owns `REGS`). The `static mut` access is confined here.
pub fn set_current_vcpu(v: Vcpu) {
    unsafe { *(&raw mut crate::arch::REGS) = v; }
}

impl GuestMem {
    /// Read `len` bytes at `addr` as a slice.
    pub fn slice(self, addr: usize, len: usize) -> &'static [u8] {
        unsafe { core::slice::from_raw_parts(addr as *const u8, len) }
    }
    /// Mutably borrow `len` bytes at `addr`.
    pub fn slice_mut(self, addr: usize, len: usize) -> &'static mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, len) }
    }
    /// Borrow a NUL-terminated C string (excluding the NUL), scanning ≤ `max`.
    pub fn c_str(self, addr: usize, max: usize) -> &'static [u8] {
        unsafe {
            let p = addr as *const u8;
            let mut len = 0;
            while len < max && *p.add(len) != 0 { len += 1; }
            core::slice::from_raw_parts(p, len)
        }
    }
    /// Read a `T` (unaligned-safe).
    pub fn read<T: Copy>(self, addr: usize) -> T {
        unsafe { core::ptr::read_unaligned(addr as *const T) }
    }
    /// Write a `T` (unaligned-safe).
    pub fn write<T: Copy>(self, addr: usize, val: T) {
        unsafe { core::ptr::write_unaligned(addr as *mut T, val); }
    }
    /// Borrow the `T` living at `addr` in guest memory in place. Used for the
    /// DOS struct overlays (PSP, low-memory BIOS area) that mutate fields
    /// directly; an interpreter backend reinterprets its buffer here.
    pub fn at<T>(self, addr: usize) -> &'static mut T {
        unsafe { &mut *(addr as *mut T) }
    }
    /// Zero `len` bytes at `addr`.
    pub fn zero(self, addr: usize, len: usize) {
        unsafe { core::ptr::write_bytes(addr as *mut u8, 0, len); }
    }
    /// Copy `src` into guest memory at `addr`.
    pub fn write_bytes(self, addr: usize, src: &[u8]) {
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), addr as *mut u8, src.len()); }
    }
    /// Copy `len` bytes within guest memory (`src` → `dst`), overlap-safe.
    pub fn copy_within(self, src: usize, dst: usize, len: usize) {
        unsafe { core::ptr::copy(src as *const u8, dst as *mut u8, len); }
    }
}
