//! Hosted physical RAM backing: one shared mapping addressed by frame number.
//! The kernel owns allocation, accounting, reference counts and reclamation.

const PAGE: usize = 4096;

/// Size of the guest physical address space the interpreter models. Sparse
/// (only touched frames consume host RAM), so this is generous — it bounds the
/// `ppage` values the kernel's allocator may hand out.
pub const PHYS_SIZE: usize = 512 << 20; // 512 MiB

/// The memfd backing guest physical RAM, and a persistent kernel-side mapping
/// of the whole thing (the interpreter "kernel" is this host process, so its
/// view of a frame is just a host pointer into this mapping).
struct Phys {
    #[cfg(test)]
    fd: i32,
    view: *mut u8,
}
// Single-threaded interp CPU owns this; the raw pointer is to a fixed mapping
// that lives for the process, so sharing/sending the handle is sound.
unsafe impl Sync for Phys {}
unsafe impl Send for Phys {}

static PHYS: std::sync::OnceLock<Phys> = std::sync::OnceLock::new();

/// Base of the persistent kernel-side mapping of the whole guest-physical memfd.
/// This is the single region handed to unicorn (`mem_map_ptr(0, PHYS_SIZE, …)`):
/// with CR0.PG set, unicorn's softmmu walks our page tables and indexes here, so
/// guest physical address `pa` lives at `region_base() + pa`.
pub fn region_base() -> *mut u8 {
    phys().view
}

/// Resolve a page-aligned kernel view back to its guest-physical RAM range.
pub(crate) fn kernel_frame(base: core::ptr::NonNull<u8>, count: usize) -> u64 {
    let offset = (base.as_ptr() as usize).checked_sub(region_base() as usize).unwrap();
    assert!(offset.is_multiple_of(PAGE));
    assert!(count.checked_mul(PAGE).and_then(|len| offset.checked_add(len))
        .is_some_and(|end| end <= PHYS_SIZE));
    (offset / PAGE) as u64
}

fn phys() -> &'static Phys {
    PHYS.get_or_init(|| {
        let name = b"retroos-guest-phys\0";
        let fd = unsafe { libc::memfd_create(name.as_ptr() as *const _, libc::MFD_CLOEXEC) };
        assert!(fd >= 0, "memfd_create for guest phys failed");
        let r = unsafe { libc::ftruncate(fd, PHYS_SIZE as libc::off_t) };
        assert!(r == 0, "ftruncate guest phys failed");
        let view = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                PHYS_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        assert!(view != libc::MAP_FAILED, "kernel-view mmap of guest phys failed");
        #[cfg(not(test))]
        unsafe { libc::close(fd); }
        Phys { #[cfg(test)] fd, view: view as *mut u8 }
    })
}

/// Host pointer to physical page `ppage` through the kernel's persistent view.
/// Both the kernel (rendering planes, COW copies) and guest mappings of the
/// same frame see one storage.
pub fn frame_ptr(ppage: u64) -> *mut u8 {
    let off = (ppage as usize) * PAGE;
    assert!(off < PHYS_SIZE, "phys frame {ppage:#x} out of range");
    unsafe { phys().view.add(off) }
}

/// Alias `count` pages of physical memory (starting at `ppage`) into the host
/// VA window starting at `dst` (a guest address-space page). After this the
/// guest VA and the kernel `frame_ptr` view share storage. Returns success.
///
/// # Safety
/// `dst` must be a writable reservation slot (inside a `Space`'s VA window);
/// the caller invalidates any Unicorn mapping of these pages afterwards.
#[cfg(test)]
pub unsafe fn alias_into(dst: *mut u8, ppage: u64, count: usize) -> bool {
    let off = (ppage as usize) * PAGE;
    assert!(off + count * PAGE <= PHYS_SIZE, "phys alias out of range");
    let r = libc::mmap(
        dst as *mut _,
        count * PAGE,
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        libc::MAP_SHARED | libc::MAP_FIXED,
        phys().fd,
        off as libc::off_t,
    );
    r != libc::MAP_FAILED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_shares_storage() {
        crate::phys::init_test_ram();
        // Two frames; write via the kernel view, alias into a scratch
        // reservation, and confirm the alias sees the same bytes (and writes
        // back through it land in the kernel view) — i.e. one physical frame,
        // two mappings.
        let base = test_memory::alloc_backed_pages(2);
        unsafe {
            *frame_ptr(base) = 0xAB;
            *frame_ptr(base + 1) = 0xCD;
        }
        // A scratch 2-page reservation to alias into.
        let scratch = unsafe {
            libc::mmap(core::ptr::null_mut(), 2 * PAGE, libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
        };
        assert!(scratch != libc::MAP_FAILED);
        let ok = unsafe { alias_into(scratch as *mut u8, base, 2) };
        assert!(ok);
        unsafe {
            // Alias reads the kernel-view writes.
            assert_eq!(*(scratch as *const u8), 0xAB);
            assert_eq!(*((scratch as *const u8).add(PAGE)), 0xCD);
            // Write through the alias; the kernel view observes it.
            *(scratch as *mut u8) = 0x99;
            assert_eq!(*frame_ptr(base), 0x99);
            libc::munmap(scratch, 2 * PAGE);
        }
    }
}

fn read_owned(page: u64, offset: usize, bytes: &mut [u8]) {
    assert!(offset <= PAGE && bytes.len() <= PAGE - offset);
    unsafe { core::ptr::copy_nonoverlapping(frame_ptr(page).add(offset), bytes.as_mut_ptr(), bytes.len()); }
}
fn write_owned(page: u64, offset: usize, bytes: &[u8]) {
    assert!(offset <= PAGE && bytes.len() <= PAGE - offset);
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), frame_ptr(page).add(offset), bytes.len()); }
}
pub(crate) fn io() -> arch_abi::PhysicalFrameIo {
    arch_abi::PhysicalFrameIo { read: read_owned, write: write_owned }
}

pub fn ram() -> (*mut u8, usize) { (region_base(), PHYS_SIZE) }

#[cfg(test)]
pub fn init_test_ram() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| unsafe { test_memory::init_direct_ram(region_base(), PHYS_SIZE); });
    thread_local! { static READY: Cell<bool> = const { Cell::new(false) }; }
    use std::cell::Cell;
    READY.with(|ready| {
        if ready.replace(true) { return; }
        unsafe { crate::vcpu::init_guest_ram(test_memory::alloc_backed_pages(crate::paging::PAGING_PAGES)); }
        unsafe {
            (*supply()).ownership = test_memory::ownership();
            test_memory::replenish_supply(supply());
        }
        let mut input = Box::new(arch_abi::page_supply::PageInput::new());
        for _ in 0..64 {
            input.pages[input.count] = test_memory::alloc_backed_pages(1);
            input.count += 1;
        }
        set_input(Box::into_raw(input));
    });
}

#[cfg(test)]
use crate::test_memory;

use arch_abi::page_supply::{PageSupply, PageInput, FAULT_PAGES};
thread_local! {
    static SUPPLY: core::cell::UnsafeCell<PageSupply> = const { core::cell::UnsafeCell::new(PageSupply::new()) };
    static INPUT: core::cell::Cell<*mut PageInput> = const { core::cell::Cell::new(core::ptr::null_mut()) };
}
pub(crate) fn supply() -> *mut PageSupply { SUPPLY.with(|s| s.get()) }
pub(crate) fn set_input(input: *mut PageInput) -> *mut PageInput { INPUT.with(|p| p.replace(input)) }
pub(crate) fn can_fault() -> bool { unsafe { (*supply()).count >= FAULT_PAGES } }
pub(crate) fn take_input() -> Option<u64> {
    INPUT.with(|p| unsafe { p.get().as_mut().and_then(PageInput::take) }).map(zero)
}
pub(crate) fn take_fault() -> Option<u64> {
    unsafe {
        let state = &mut *supply();
        let page = state.take()?;
        state.fault_pages_used += 1;
        Some(zero(page))
    }
}
fn zero(page: u64) -> u64 {
    unsafe { core::ptr::write_bytes(frame_ptr(page), 0, PAGE); }
    page
}
pub(crate) fn retain(page: u64) {
    assert!(unsafe { (*supply()).ownership.retain(page) });
}
pub(crate) fn shared(page: u64) -> bool {
    unsafe { (*supply()).ownership.references(page) > 1 }
}
pub(crate) fn release(page: u64) {
    unsafe {
        let state = &mut *supply();
        if !state.ownership.release_shared(page) { return; }
        if state.count < state.pages.len() { state.donate(page); }
        else {
            frame_ptr(page).cast::<u64>().write(state.returned_head);
            state.returned_head = page;
            state.returned_count += 1;
        }
    }
}
