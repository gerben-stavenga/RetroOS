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
use super::paging2::RootPageTable;

/// Register state + address-space handle for one execution context.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Vcpu {
    /// Architectural register state, including the program counter
    /// (`regs.frame.rip`) and the mode (32/64/VM86, derived from CS/EFLAGS).
    pub regs: Regs,
    /// Handle to the address space these registers execute in. For single-core
    /// this is the full per-thread page-table root; the arch context switch
    /// swaps it into the constant root page on entry.
    pub space: RootPageTable,
}

/// A Vcpu *is* its registers plus a way to reach the memory they run against.
/// Deref to `Regs` so every `regs.rax` / `regs.mode()` keeps working when a
/// `&mut Vcpu` is passed where a `&mut Regs` used to be, and so an unconverted
/// `fn f(regs: &mut Regs)` still accepts a `&mut Vcpu` by coercion. The extra
/// surface a Vcpu adds over Regs is the user-memory API below.
impl core::ops::Deref for Vcpu {
    type Target = Regs;
    fn deref(&self) -> &Regs { &self.regs }
}
impl core::ops::DerefMut for Vcpu {
    fn deref_mut(&mut self) -> &mut Regs { &mut self.regs }
}

impl Vcpu {
    pub const fn empty() -> Self {
        Vcpu { regs: Regs::empty(), space: RootPageTable::empty() }
    }

    // ── User-memory access ──────────────────────────────────────────────
    //
    // These borrow the Vcpu (hence the thread and its address space), so a
    // slice/ref handed out here cannot outlive a teardown of that space:
    // anything that resets / forks / execs the address space needs `&mut`
    // access that conflicts with a live borrow from one of these. That turns
    // the old "read_c_str -> &'static -> use after arch_user_clean()" foot-gun
    // into a borrow-check error.
    //
    // Implementation note: on real hardware the ring-1 kernel shares the active
    // page tables with the running thread, so a user virtual address is simply
    // a pointer. The borrow is a *contract* tying the access to this Vcpu's
    // lifetime, not physical containment — an emulator backend would index its
    // guest-RAM buffer here instead, with the same signatures.
    //
    // `addr` is a user virtual address as `usize` (the 32-bit kernel addresses
    // all user memory, including 64-bit compat-mode apps, within 4 GiB).

    /// Borrow `len` user bytes at `addr` as a read-only slice.
    pub fn slice(&self, addr: usize, len: usize) -> &[u8] {
        unsafe { core::slice::from_raw_parts(addr as *const u8, len) }
    }

    /// Borrow `len` user bytes at `addr` as a mutable slice.
    pub fn slice_mut(&mut self, addr: usize, len: usize) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, len) }
    }

    /// Borrow a NUL-terminated user C string (excluding the NUL), scanning at
    /// most `max` bytes.
    pub fn c_str(&self, addr: usize, max: usize) -> &[u8] {
        unsafe {
            let p = addr as *const u8;
            let mut len = 0;
            while len < max && *p.add(len) != 0 { len += 1; }
            core::slice::from_raw_parts(p, len)
        }
    }

    /// Read a `T` from user memory (unaligned-safe).
    pub fn read<T: Copy>(&self, addr: usize) -> T {
        unsafe { core::ptr::read_unaligned(addr as *const T) }
    }

    /// Write a `T` to user memory (unaligned-safe).
    pub fn write<T: Copy>(&mut self, addr: usize, val: T) {
        unsafe { core::ptr::write_unaligned(addr as *mut T, val); }
    }

    /// Zero `len` user bytes at `addr`.
    pub fn zero(&mut self, addr: usize, len: usize) {
        unsafe { core::ptr::write_bytes(addr as *mut u8, 0, len); }
    }

    /// Copy `src` into user memory at `addr`.
    pub fn write_bytes(&mut self, addr: usize, src: &[u8]) {
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), addr as *mut u8, src.len()); }
    }
}
