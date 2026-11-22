//! Hosted physical RAM backing: one shared mapping addressed by frame number.
//! The kernel allocates RAM; arch maintains references to donated frames.

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

pub fn ram() -> (*mut u8, usize) { (region_base(), PHYS_SIZE) }

/// Paging storage owned by arch before the kernel starts allocating frames.
pub fn boot_paging_frames() -> core::ops::Range<u64> {
    let first = (arch_abi::vm::IMAGE_LIMIT / PAGE) as u64;
    first..first + crate::paging::PAGING_PAGES as u64
}

/// Physical frame layout supplied by the hosted backend at boot.
pub fn frame_layout() -> &'static arch_abi::page_supply::FrameLayout {
    use arch_abi::page_supply::{FrameLayout, MemoryRegion};
    static LAYOUT: std::sync::OnceLock<FrameLayout> = std::sync::OnceLock::new();

    LAYOUT.get_or_init(|| {
        let mut layout = FrameLayout::from_memory_map(
            core::iter::once(MemoryRegion { base: 0, length: PHYS_SIZE as u64, usable: true }),
            (PHYS_SIZE / PAGE) as u64,
        );
        layout.exclude(0, (arch_abi::vm::IMAGE_LIMIT / PAGE) as u64);
        layout
    })
}

#[cfg(test)]
pub fn init_test_ram() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| unsafe { test_memory::init_direct_ram(region_base(), PHYS_SIZE); });
    thread_local! { static READY: Cell<bool> = const { Cell::new(false) }; }
    use std::cell::Cell;
    READY.with(|ready| {
        if ready.replace(true) { return; }
        unsafe { crate::vcpu::boot_cpu(test_memory::alloc_backed_pages(crate::paging::PAGING_PAGES), test_memory::ownership()); }
        refill_test_reserve();
        #[cfg(feature = "tcg")]
        {
            let mut input = PageInput::new();
            for _ in 0..64 { input.push(test_memory::alloc_backed_pages(1)); }
            INPUT.with(|p| p.replace(input));
        }
    });
}

#[cfg(test)]
use crate::test_memory;

#[cfg(any(feature = "tcg", test))]
use arch_abi::page_supply::PageInput;
#[cfg(feature = "tcg")]
use arch_abi::page_supply::PageSupply;
#[cfg(feature = "tcg")]
use arch_abi::page_supply::FAULT_PAGES;
#[cfg(feature = "tcg")]
thread_local! {
    static SUPPLY: core::cell::UnsafeCell<PageSupply> = const { core::cell::UnsafeCell::new(PageSupply::new()) };
    static INPUT: core::cell::RefCell<PageInput> = const { core::cell::RefCell::new(PageInput::new()) };
}
#[cfg(feature = "tcg")]
fn supply() -> *mut PageSupply { SUPPLY.with(|s| s.get()) }
#[cfg(feature = "tcg")]
pub(crate) fn supply_status() -> arch_abi::page_supply::SupplyStatus {
    unsafe { (*supply()).status() }
}
#[cfg(feature = "kvm")]
pub(crate) use crate::kvm::supply_status;
#[cfg(feature = "tcg")]
pub(crate) fn with_input<R>(pages: PageInput, operation: impl FnOnce() -> R) -> (R, PageInput) {
    struct Restore(PageInput);
    impl Drop for Restore {
        fn drop(&mut self) { INPUT.with(|p| *p.borrow_mut() = core::mem::take(&mut self.0)); }
    }
    let _restore = Restore(INPUT.with(|p| p.replace(pages)));
    let result = operation();
    (result, INPUT.with(|p| p.take()))
}
#[cfg(feature = "tcg")]
pub(crate) fn configure(ownership: arch_abi::page_supply::FrameOwnership) {
    unsafe { (*supply()).ownership = ownership; }
}
#[cfg(feature = "kvm")]
thread_local! {
    static OWNERSHIP: core::cell::Cell<arch_abi::page_supply::FrameOwnership> = const {
        core::cell::Cell::new(arch_abi::page_supply::FrameOwnership::EMPTY)
    };
}
#[cfg(feature = "kvm")]
pub(crate) fn configure(ownership: arch_abi::page_supply::FrameOwnership) { OWNERSHIP.with(|slot| slot.set(ownership)); }
#[cfg(feature = "tcg")]
pub(crate) fn supply_pages(mut pages: PageInput) -> (usize, PageInput) {
    let state = unsafe { &mut *supply() };
    while state.reserve.len() < arch_abi::page_supply::SUPPLY_CAPACITY {
        let Some(page) = pages.take() else { break; };
        state.donate(page);
    }
    while pages.count < pages.pages.len() && state.returned_head != 0 {
        let page = state.returned_head;
        state.returned_head = unsafe { frame_ptr(page).cast::<u64>().read() };
        state.returned_count -= 1;
        pages.push(page);
    }
    (arch_abi::page_supply::SUPPLY_CAPACITY - state.reserve.len(), pages)
}
#[cfg(feature = "tcg")]
pub(crate) fn can_fault() -> bool { unsafe { (*supply()).reserve.len() >= FAULT_PAGES } }
#[cfg(feature = "tcg")]
pub(crate) fn take_input() -> Option<u64> {
    INPUT.with(|p| p.borrow_mut().take()).map(zero)
}
#[cfg(feature = "tcg")]
pub(crate) fn take_fault() -> Option<u64> {
    unsafe {
        let state = &mut *supply();
        let page = state.take()?;
        state.fault_pages_used += 1;
        Some(zero(page))
    }
}
#[cfg(feature = "tcg")]
fn zero(page: u64) -> u64 {
    unsafe { core::ptr::write_bytes(frame_ptr(page), 0, PAGE); }
    page
}
#[cfg(feature = "tcg")]
pub(crate) fn retain(page: u64) {
    assert!(unsafe { (*supply()).ownership.retain(page) });
}
#[cfg(feature = "tcg")]
pub(crate) fn shared(page: u64) -> bool {
    unsafe { (*supply()).ownership.references(page) > 1 }
}
#[cfg(feature = "tcg")]
pub(crate) fn release(page: u64) {
    unsafe {
        let state = &mut *supply();
        if !state.ownership.release_shared(page) { return; }
        if state.reserve.len() < arch_abi::page_supply::SUPPLY_CAPACITY { state.donate(page); }
        else {
            frame_ptr(page).cast::<u64>().write(state.returned_head);
            state.returned_head = page;
            state.returned_count += 1;
        }
    }
}


#[cfg(test)]
pub(crate) fn refill_test_reserve() {
    let (needed, mut returned) = supply_pages(PageInput::new());
    while let Some(page) = returned.take() { test_memory::free_phys_page(page); }
    let mut pages = PageInput::new();
    for _ in 0..needed { pages.push(test_memory::alloc_backed_pages(1)); }
    assert_eq!(supply_pages(pages).1.count, 0);
}

#[cfg(feature = "kvm")]
pub(crate) fn ownership() -> arch_abi::page_supply::FrameOwnership { OWNERSHIP.with(|slot| slot.get()) }
#[cfg(all(feature = "kvm", test))]
pub(crate) fn supply_pages(pages: PageInput) -> (usize, PageInput) { arch_abi::Memory::supply_pages(&crate::Interp::local(), pages) }
