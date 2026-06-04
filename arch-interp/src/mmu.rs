//! Software MMU for the interpreter backend.
//!
//! Each guest address space is an `mmap`-reserved (`PROT_NONE`) region covering
//! the whole user VA range, demand-committed a page at a time. So a guest-linear
//! address is a *contiguous* host pointer — exactly the property the metal
//! backend gets from real page tables ("VA is the pointer"), which is what lets
//! `GuestMem` hand out multi-page slices and what keeps the kernel unaware of
//! the backend. Reservation is sparse (`MAP_NORESERVE`); only touched pages cost
//! RAM, so a guest with a stack near 0xBFFF_F000 is cheap.
//!
//! Demand-paging and (later) COW are arch-internal, mirroring metal: the kernel
//! only sees a `PageFault` event for a genuinely illegal access (null-guard or
//! out-of-range). Everything else demand-commits transparently.
//!
//! Milestone 3 scope: demand-zero paging, the paging arch calls, and per-space
//! switching. COW fork is Milestone 4 — for now `arch_user_fork` copies.

use std::cell::RefCell;
use std::collections::BTreeMap;

const PAGE: usize = 4096;

/// User VA span `[0, KERNEL_BASE)`. Matches the metal layout's user/kernel split.
pub const GUEST_VA_SIZE: usize = 0xC000_0000;
const NUM_PAGES: usize = GUEST_VA_SIZE / PAGE;

/// First 64 KiB is the null-pointer guard: accesses here are never demand-paged.
const NULL_GUARD: usize = 0x1_0000;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Perm {
    present: bool,
    writable: bool,
}

/// One address space: a reserved host VA window plus per-page state.
struct Space {
    base: *mut u8,
    perm: Vec<Perm>,
}

impl Space {
    fn new() -> Space {
        let base = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                GUEST_VA_SIZE,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert!(base != libc::MAP_FAILED, "mmap guest VA reservation failed");
        Space { base: base as *mut u8, perm: vec![Perm::default(); NUM_PAGES] }
    }

    #[inline]
    fn page_ptr(&self, vpage: usize) -> *mut u8 {
        unsafe { self.base.add(vpage * PAGE) }
    }

    /// Commit a page (zero-filled by the kernel via anonymous mmap) with the
    /// given writability. Idempotent re-commit just adjusts protection.
    fn commit(&mut self, vpage: usize, writable: bool) {
        let prot = libc::PROT_READ | libc::PROT_EXEC | if writable { libc::PROT_WRITE } else { 0 };
        unsafe {
            libc::mprotect(self.page_ptr(vpage) as *mut _, PAGE, prot);
        }
        self.perm[vpage] = Perm { present: true, writable };
    }

    /// Drop a page back to absent (re-zeroes on next commit).
    fn decommit(&mut self, vpage: usize) {
        if !self.perm[vpage].present {
            return;
        }
        unsafe {
            libc::madvise(self.page_ptr(vpage) as *mut _, PAGE, libc::MADV_DONTNEED);
            libc::mprotect(self.page_ptr(vpage) as *mut _, PAGE, libc::PROT_NONE);
        }
        self.perm[vpage] = Perm::default();
    }
}

impl Drop for Space {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.base as *mut _, GUEST_VA_SIZE);
        }
    }
}

struct State {
    spaces: BTreeMap<u32, Space>,
    active: u32,
    next_id: u32,
}

thread_local! {
    static STATE: RefCell<State> =
        RefCell::new(State { spaces: BTreeMap::new(), active: 0, next_id: 0 });
}

fn with_active<R>(f: impl FnOnce(&mut Space) -> R) -> R {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        let active = s.active;
        f(s.spaces.get_mut(&active).expect("active space missing"))
    })
}

/// Create the initial address space (id 0) and make it active. The `len`
/// argument is ignored — the reservation is always the full user VA range.
pub fn init() {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        if !s.spaces.is_empty() {
            return;
        }
        s.spaces.insert(0, Space::new());
        s.active = 0;
        s.next_id = 1;
    });
}

/// Create a fresh empty address space; returns its id. (Threads/fork hand the
/// kernel a `RootPageTable(id)`; for now this is the interp-side allocator.)
pub fn new_space() -> u32 {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        let id = s.next_id;
        s.next_id += 1;
        s.spaces.insert(id, Space::new());
        id
    })
}

/// Make `id` the active space.
pub fn switch_to(id: u32) {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        assert!(s.spaces.contains_key(&id), "switch to unknown space {id}");
        s.active = id;
    });
}

pub fn active_id() -> u32 {
    STATE.with(|s| s.borrow().active)
}

/// Host pointer of the active space's base (for `GuestMem`). A guest address
/// `a` lives at `active_base().add(a)` once committed.
pub fn active_base() -> *mut u8 {
    with_active(|sp| sp.base)
}

#[inline]
fn page_range(addr: usize, len: usize) -> core::ops::Range<usize> {
    let first = addr / PAGE;
    let last = (addr + len.max(1) - 1) / PAGE;
    first..last + 1
}

/// Ensure `[addr, addr+len)` is committed in the active space, demand-zeroing
/// any absent pages as writable. Used by `GuestMem`: when the kernel touches
/// guest memory, the page must exist (the metal kernel's ring-1 access would
/// fault it in transparently).
pub fn ensure_committed(addr: usize, len: usize) {
    with_active(|sp| {
        for p in page_range(addr, len) {
            if p < NUM_PAGES && !sp.perm[p].present {
                sp.commit(p, true);
            }
        }
    });
}

/// Resolve a guest fault from the software CPU. `Some(writable)` means the page
/// was demand-committed and execution should retry; `None` means a genuinely
/// illegal access that must bubble to the kernel as `PageFault`.
pub fn demand(addr: usize) -> Option<bool> {
    if addr < NULL_GUARD || addr >= GUEST_VA_SIZE {
        return None;
    }
    let vpage = addr / PAGE;
    with_active(|sp| {
        if sp.perm[vpage].present {
            return Some(sp.perm[vpage].writable);
        }
        sp.commit(vpage, true);
        Some(true)
    })
}

// ── Paging arch-call primitives (operate on the active space) ──────────────

/// Replace `count` pages at `vpage` with fresh anonymous RW frames (committed).
pub fn map_fresh(vpage: usize, count: usize) {
    with_active(|sp| {
        for p in vpage..(vpage + count).min(NUM_PAGES) {
            sp.decommit(p);
            sp.commit(p, true);
        }
    });
}

/// Set writability over `count` present pages. (Executability is relaxed in M3;
/// committed pages are always executable.)
pub fn set_flags(vpage: usize, count: usize, writable: bool) {
    with_active(|sp| {
        for p in vpage..(vpage + count).min(NUM_PAGES) {
            if sp.perm[p].present {
                sp.commit(p, writable);
            }
        }
    });
}

/// Clear entries to absent (next access demand-zeroes).
pub fn unmap(vpage: usize, count: usize) {
    with_active(|sp| {
        for p in vpage..(vpage + count).min(NUM_PAGES) {
            sp.decommit(p);
        }
    });
}

/// Free `count` pages (decommit). Mirrors the metal `FREE_RANGE` effect for the
/// interp (no physical identity alias to restore).
pub fn free(vpage: usize, count: usize) {
    unmap(vpage, count);
}

/// Copy page contents+state src→dst (the interp owns frames per VA, so this is
/// a byte copy rather than a refcount-shared PTE copy — same observable result).
pub fn copy_entries(src: usize, dst: usize, count: usize) {
    with_active(|sp| {
        for i in 0..count {
            let (s, d) = (src + i, dst + i);
            if s >= NUM_PAGES || d >= NUM_PAGES {
                break;
            }
            if sp.perm[s].present {
                sp.commit(d, sp.perm[s].writable);
                unsafe {
                    core::ptr::copy_nonoverlapping(sp.page_ptr(s), sp.page_ptr(d), PAGE);
                }
            } else {
                sp.decommit(d);
            }
        }
    });
}

/// Swap page contents+state a↔b.
pub fn swap_entries(a: usize, b: usize, count: usize) {
    with_active(|sp| {
        for i in 0..count {
            let (x, y) = (a + i, b + i);
            if x >= NUM_PAGES || y >= NUM_PAGES {
                break;
            }
            // Commit both so the byte swap is valid, then swap perms back.
            let (px, py) = (sp.perm[x], sp.perm[y]);
            if !px.present {
                sp.commit(x, true);
            }
            if !py.present {
                sp.commit(y, true);
            }
            unsafe {
                let mut tmp = [0u8; PAGE];
                core::ptr::copy_nonoverlapping(sp.page_ptr(x), tmp.as_mut_ptr(), PAGE);
                core::ptr::copy_nonoverlapping(sp.page_ptr(y), sp.page_ptr(x), PAGE);
                core::ptr::copy_nonoverlapping(tmp.as_ptr(), sp.page_ptr(y), PAGE);
            }
            sp.perm[x] = py;
            sp.perm[y] = px;
            if !py.present {
                sp.decommit(x);
            }
            if !px.present {
                sp.decommit(y);
            }
        }
    });
}

/// Map `count` "physical" pages as committed RW (the interp has no separate
/// physical frame namespace, so this is anonymous RW like `map_fresh`).
pub fn map_phys(vpage: usize, count: usize) {
    map_fresh(vpage, count);
}

/// Map the first 1 MB user-accessible (committed RW). The metal call splits
/// this into BIOS/VGA/ROM regions for VM86; the interp's flat-PM target doesn't
/// need that split, so it is plain anonymous RW.
pub fn map_low_mem() {
    map_fresh(0, 0x100);
}

/// Free every committed page in the active space (arch CLEAN).
pub fn clean() {
    with_active(|sp| {
        for p in 0..NUM_PAGES {
            if sp.perm[p].present {
                sp.decommit(p);
            }
        }
    });
}

/// Copy the whole of `src` space into a new space and return its id. Used by
/// `arch_user_fork` until COW lands in M4 (correct, just not lazy).
pub fn fork_copy(src: u32) -> u32 {
    let dst = new_space();
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        let present: Vec<(usize, bool)> = s.spaces[&src]
            .perm
            .iter()
            .enumerate()
            .filter(|(_, p)| p.present)
            .map(|(i, p)| (i, p.writable))
            .collect();
        for (vpage, writable) in present {
            let sbase = s.spaces[&src].base;
            let dspace = s.spaces.get_mut(&dst).unwrap();
            dspace.commit(vpage, writable);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    sbase.add(vpage * PAGE),
                    dspace.page_ptr(vpage),
                    PAGE,
                );
            }
        }
    });
    dst
}
