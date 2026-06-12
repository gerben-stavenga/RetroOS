//! Guest physical memory model for the interpreter.
//!
//! Metal has real physical frames: two virtual mappings can point at the same
//! frame (the VGA A0000 window aliasing a plane, a COW page shared by parent
//! and child, an MMIO BAR). The interpreter had no such namespace — each
//! address space was its own flat anonymous arena, so `map_phys_range` could
//! only hand back fresh zeroed RAM and `alloc_phys_contig` was unimplemented.
//!
//! This backs "guest physical RAM" with a single `memfd`: a physical frame is
//! an offset into it. Aliasing is then ordinary `mmap(MAP_FIXED, …, memfd,
//! off)` — map the same file page at two guest VAs (or into the kernel's own
//! view) and they share storage, exactly like a real frame mapped by two PTEs.
//! The fd is sparse, so the large reservation costs only the frames actually
//! touched. This is the substrate the kernel's phys allocator, the VGA
//! plane-aliasing, and COW fork all build on; on metal the same kernel code
//! drives real frames through `map_phys_range`.

use std::sync::atomic::{AtomicUsize, Ordering};

const PAGE: usize = 4096;

/// Size of the guest physical address space the interpreter models. Sparse
/// (only touched frames consume host RAM), so this is generous — it bounds the
/// `ppage` values the kernel's allocator may hand out.
pub const PHYS_SIZE: usize = 512 << 20; // 512 MiB

/// The memfd backing guest physical RAM, and a persistent kernel-side mapping
/// of the whole thing (the interpreter "kernel" is this host process, so its
/// view of a frame is just a host pointer into this mapping).
struct Phys {
    fd: i32,
    view: *mut u8,
}
// Single-threaded interp CPU owns this; the raw pointer is to a fixed mapping
// that lives for the process, so sharing/sending the handle is sound.
unsafe impl Sync for Phys {}
unsafe impl Send for Phys {}

static PHYS: std::sync::OnceLock<Phys> = std::sync::OnceLock::new();

/// Bump allocator over the phys backing. Frame 0 is reserved (a null-ish
/// sentinel so a 0 ppage reads as "unallocated"). The kernel frees rarely
/// enough (VGA teardown, reaped DMA buffers) that a simple high-water bump
/// with no reuse is acceptable for now; `free` is a no-op stub.
static NEXT_FRAME: AtomicUsize = AtomicUsize::new(1);

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
        Phys { fd, view: view as *mut u8 }
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

/// Allocate `count` contiguous frames; returns the starting page. Bump-only.
pub fn alloc_frames(count: usize) -> u64 {
    let start = NEXT_FRAME.fetch_add(count, Ordering::Relaxed);
    assert!((start + count) * PAGE <= PHYS_SIZE, "guest phys exhausted");
    start as u64
}

/// Free is a no-op for the bump allocator (see `NEXT_FRAME`). Kept so callers
/// mirror the metal allocator's free/alloc symmetry.
pub fn free_frames(_start: u64, _count: usize) {}

/// Alias `count` pages of physical memory (starting at `ppage`) into the host
/// VA window starting at `dst` (a guest address-space page). After this the
/// guest VA and the kernel `frame_ptr` view share storage. Returns success.
///
/// # Safety
/// `dst` must be a writable reservation slot (inside a `Space`'s VA window);
/// the caller invalidates any Unicorn mapping of these pages afterwards.
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
        // Two frames; write via the kernel view, alias into a scratch
        // reservation, and confirm the alias sees the same bytes (and writes
        // back through it land in the kernel view) — i.e. one physical frame,
        // two mappings.
        let base = alloc_frames(2);
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
