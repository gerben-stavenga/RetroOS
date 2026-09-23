//! Reusable temporary mapping for copying to and from physical memory.
//!
//! The aperture is a fixed virtual window below the framebuffer.  It is
//! remapped to one 64 KiB physical chunk at a time and is intentionally
//! exposed only through copy operations, so callers cannot retain a pointer
//! after the mapping changes.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::arch_call;
use crate::paging2;

pub(crate) const APERTURE_SIZE: usize = 64 * 1024;
pub(crate) const APERTURE_END: usize = arch_abi::FB_WINDOW_BASE;
pub(crate) const APERTURE_BASE: usize = APERTURE_END - APERTURE_SIZE;
pub(crate) const APERTURE_PAGES: usize = APERTURE_SIZE / paging2::PAGE_SIZE;

const _: () = {
    assert!(APERTURE_SIZE.is_power_of_two());
    assert!(APERTURE_SIZE.is_multiple_of(paging2::PAGE_SIZE));
    assert!(APERTURE_BASE.is_multiple_of(paging2::PAGE_SIZE));
    assert!(APERTURE_PAGES == 16);
};

static BUSY: AtomicBool = AtomicBool::new(false);
static MAPPED_VALID: AtomicBool = AtomicBool::new(false);
static MAPPED_LOW: AtomicU32 = AtomicU32::new(0);
static MAPPED_HIGH: AtomicU32 = AtomicU32::new(0);

struct ApertureGuard;

impl Drop for ApertureGuard {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::Release);
    }
}

fn acquire() -> ApertureGuard {
    while BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
    ApertureGuard
}

fn cached_base() -> Option<u64> {
    if !MAPPED_VALID.load(Ordering::Acquire) {
        return None;
    }
    Some((MAPPED_HIGH.load(Ordering::Relaxed) as u64) << 32
        | MAPPED_LOW.load(Ordering::Relaxed) as u64)
}

fn set_cached_base(base: u64) {
    MAPPED_LOW.store(base as u32, Ordering::Relaxed);
    MAPPED_HIGH.store((base >> 32) as u32, Ordering::Relaxed);
    MAPPED_VALID.store(true, Ordering::Release);
}

/// Prepare the page-table parent covering the aperture.
///
/// Must run at ring 0 after the physical allocator and heap are initialized,
/// and before the ring-1 kernel can request a remap.
pub fn init() {
    paging2::prepare_kernel_mapping(APERTURE_BASE / paging2::PAGE_SIZE, APERTURE_PAGES);
    MAPPED_VALID.store(false, Ordering::Release);
}

/// Request one fixed aperture remap from the ring-1 kernel to ring 0.
fn request_remap(base: u64) -> bool {
    let mut result: u32;
    unsafe {
        asm!(
            "int 0x80",
            inlateout("eax") arch_call::REMAP_PHYSICAL_APERTURE as u32 => result,
            in("edx") base as u32,
            in("ecx") (base >> 32) as u32,
        );
    }
    result != 0
}

/// Copy bytes from physical memory into a kernel buffer.
/// Task context only: callers share a serialized aperture with physical writes.
pub fn copy_from_physical(physical: u64, destination: &mut [u8]) -> bool {
    copy_physical(physical, destination.as_mut_ptr(), destination.len(), false)
}

/// Copy bytes from a kernel buffer into loader-owned physical RAM.
/// Task context only; interrupt handlers must not use the shared aperture.
pub fn copy_to_physical(physical: u64, source: &[u8]) -> bool {
    copy_physical(physical, source.as_ptr() as *mut u8, source.len(), true)
}

fn copy_physical(physical: u64, buffer: *mut u8, len: usize, write: bool) -> bool {
    if len == 0 {
        return true;
    }
    let buffer_start = buffer as usize;
    let buffer_end = match buffer_start.checked_add(len) {
        Some(end) => end,
        None => return false,
    };
    if physical.checked_add(len as u64).is_none() {
        return false;
    }
    assert!(buffer_end <= APERTURE_BASE || buffer_start >= APERTURE_END,
        "physical aperture copy buffer overlaps the aperture");

    let mut physical = physical;
    let mut copied = 0usize;
    while copied < len {
        let base = physical & !(APERTURE_SIZE as u64 - 1);
        let offset = (physical - base) as usize;
        let amount = (len - copied).min(APERTURE_SIZE - offset);
        let _guard = acquire();
        if cached_base() != Some(base) {
            if !request_remap(base) {
                return false;
            }
            set_cached_base(base);
        }
        unsafe {
            let aperture = (APERTURE_BASE + offset) as *mut u8;
            if write {
                core::ptr::copy_nonoverlapping(buffer.add(copied), aperture, amount);
            } else {
                core::ptr::copy_nonoverlapping(aperture, buffer.add(copied), amount);
            }
        }
        copied += amount;
        physical += amount as u64;
    }
    true
}

/// Ring-0 implementation of the dedicated remap call.
pub(crate) fn remap(physical_base: u64) -> bool {
    if !physical_base.is_multiple_of(APERTURE_SIZE as u64) {
        return false;
    }
    paging2::map_kernel_foreign_range(
        APERTURE_BASE / paging2::PAGE_SIZE,
        physical_base / paging2::PAGE_SIZE as u64,
        APERTURE_PAGES,
    )
}
