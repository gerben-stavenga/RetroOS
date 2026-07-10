//! Real x86 paging under the interpreter (work in progress).
//!
//! The interpreter has run unicorn with paging OFF — guest linear = physical,
//! demand-mapped a page at a time via `uc_mem_map_ptr`, one unicorn region per
//! page. For a large/streaming working set (Doom) that explodes the region/
//! flatview machinery (`render_memory_region`, `qemu_ram_alloc_from_ptr`) into
//! an O(n²) cost.
//!
//! The fix is to run RetroOS's paging *for real*, exactly as QEMU runs any
//! paging OS: guest physical RAM is ONE region, the kernel's real x86 page
//! tables live in that RAM, CR3/CR0.PG are set, and unicorn's softmmu walks
//! the tables on a TLB miss. Per-page work becomes a bounded TLB fill, not a
//! region creation.
//!
//! This module starts with a standalone proof that unicorn does the page-table
//! walk with tables we build (a non-identity virtual→physical mapping), then
//! grows into the real memory backend.

use crate::phys;

/// 32-bit non-PAE page-table format. A page directory and each page table are
/// one physical frame of 1024 × 4-byte entries. We address frames by physical
/// page number (ppage); the entry stores the target ppage in bits 31:12.
const PRESENT: u32 = 1 << 0;
const WRITABLE: u32 = 1 << 1;
const USER: u32 = 1 << 2;
const ENTRY_FLAGS: u32 = PRESENT | WRITABLE | USER;
/// Software PTE bit (bits 9-11 are ignored by the CPU/unicorn page walk): marks
/// a copy-on-write page. Such a page is mapped PRESENT|USER read-only (W=0), so
/// a write #PFs; `space_cow_fault` then privatises the frame and clears COW.
const COW: u32 = 1 << 9;

#[inline]
fn pde_index(vaddr: u32) -> usize {
    (vaddr >> 22) as usize
}
#[inline]
fn pte_index(vaddr: u32) -> usize {
    ((vaddr >> 12) & 0x3FF) as usize
}

/// Read entry `i` of the table in frame `ppage`.
fn read_entry(ppage: u64, i: usize) -> u32 {
    unsafe {
        let p = phys::frame_ptr(ppage).add(i * 4) as *const u32;
        p.read_unaligned()
    }
}
/// Write entry `i` of the table in frame `ppage`. This is the single funnel
/// every 2-level mutation goes through, so it also advances the long-mode
/// twin's invalidation generation (see `active_pml4`).
fn write_entry(ppage: u64, i: usize, v: u32) {
    LONG_GEN.with(|g| g.set(g.get() + 1));
    unsafe {
        let p = phys::frame_ptr(ppage).add(i * 4) as *mut u32;
        p.write_unaligned(v);
    }
}

/// Allocate and zero a fresh page-table frame; returns its ppage.
fn alloc_table() -> u64 {
    let ppage = phys::alloc_frames(1);
    unsafe { core::ptr::write_bytes(phys::frame_ptr(ppage), 0, 4096) };
    ppage
}

/// Create a new (empty) address space: a zeroed page directory frame. Returns
/// its ppage — this is the value loaded into CR3.
pub fn new_page_dir() -> u64 {
    alloc_table()
}

/// Map virtual page `vaddr` (page-aligned) to physical frame `paddr_ppage` in
/// the address space rooted at page directory `pd`. Allocates the intermediate
/// page table on first use. `writable` clears the W bit when false (read-only).
pub fn map_page(pd: u64, vaddr: u32, paddr_ppage: u64, writable: bool) {
    let pde_i = pde_index(vaddr);
    let pde = read_entry(pd, pde_i);
    let pt = if pde & PRESENT != 0 {
        (pde >> 12) as u64
    } else {
        let pt = alloc_table();
        write_entry(pd, pde_i, ((pt as u32) << 12) | ENTRY_FLAGS);
        pt
    };
    let flags = if writable { ENTRY_FLAGS } else { PRESENT | USER };
    write_entry(pt, pte_index(vaddr), ((paddr_ppage as u32) << 12) | flags);
}

/// Cache-Disable (PCD) PTE bit — the regular x86 device-memory attribute. On a
/// present=0 PTE it is the MMIO trap marker: `space_demand` faults it to the
/// kernel instead of committing RAM (present + PCD would be passthrough device
/// memory, but the interp has no cache so it's inert there).
pub const CACHE_DISABLE: u32 = 1 << 4;

/// Map `count` pages at `vpage` as an MMIO trap window: present=0 + PCD, so
/// guest accesses fault to the kernel (the page is not backed — `ppage` is
/// irrelevant). The metal twin maps the same present=0 + `CACHE_DISABLE`.
pub fn space_map_mmio(vpage: usize, count: usize) {
    with_active_pd(|pd| {
        for i in 0..count {
            let vaddr = ((vpage + i) * 4096) as u32;
            let pde_i = pde_index(vaddr);
            let pde = read_entry(pd, pde_i);
            let pt = if pde & PRESENT != 0 {
                (pde >> 12) as u64
            } else {
                let pt = alloc_table();
                write_entry(pd, pde_i, ((pt as u32) << 12) | ENTRY_FLAGS);
                pt
            };
            write_entry(pt, pte_index(vaddr), CACHE_DISABLE); // present=0 + PCD
        }
    });
}

/// Raw leaf PTE for `vaddr` (0 if its page table is absent) — lets the fault
/// path peek software markers on a not-present page.
fn pte_raw(pd: u64, vaddr: u32) -> u32 {
    let pde = read_entry(pd, pde_index(vaddr));
    if pde & PRESENT == 0 {
        return 0;
    }
    read_entry((pde >> 12) as u64, pte_index(vaddr))
}

/// Clear the mapping for `vaddr` (page granularity). Leaves the page table
/// frame in place (cheap; reclaimed only when the whole space is freed).
pub fn unmap_page(pd: u64, vaddr: u32) {
    let pde = read_entry(pd, pde_index(vaddr));
    if pde & PRESENT != 0 {
        write_entry((pde >> 12) as u64, pte_index(vaddr), 0);
    }
}

/// Software walk: translate guest virtual `vaddr` to a guest physical address,
/// or `None` if unmapped. Used by the kernel's guest-memory accessors (the
/// kernel is host code; it can't lean on the CPU MMU like the metal kernel).
pub fn translate(pd: u64, vaddr: u32) -> Option<u32> {
    let pde = read_entry(pd, pde_index(vaddr));
    if pde & PRESENT == 0 {
        return None;
    }
    let pte = read_entry((pde >> 12) as u64, pte_index(vaddr));
    if pte & PRESENT == 0 {
        return None;
    }
    Some((pte & !0xFFF) | (vaddr & 0xFFF))
}

/// Physical address (for CR3 / page-table walk) of a table frame.
#[inline]
pub fn frame_phys(ppage: u64) -> u32 {
    (ppage as u32) << 12
}

#[cfg(all(test, feature = "tcg"))] // proofs drive Unicorn directly
mod proof {
    use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
    use unicorn_engine::{RegisterX86, Unicorn};

    /// 32-bit PDE/PTE flags: present | writable | user.
    const PRW: u32 = 0b111;

    /// Build a flat 32-bit segment descriptor (base 0, 4 GiB limit).
    fn flat_desc(access: u8) -> [u8; 8] {
        [0xFF, 0xFF, 0x00, 0x00, 0x00, access, 0xCF, 0x00]
    }

    /// Pack the `uc_x86_mmr` layout (selector:u16, base:u64@8, limit:u32@16).
    fn mmr(base: u64, limit: u32) -> [u8; 24] {
        let mut b = [0u8; 24];
        b[8..16].copy_from_slice(&base.to_le_bytes());
        b[16..20].copy_from_slice(&limit.to_le_bytes());
        b
    }

    #[test]
    fn unicorn_walks_our_page_tables() {
        // One physical RAM region (the "QEMU pc.ram" topology): 16 MiB at
        // physical 0, a single unicorn region.
        let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).expect("uc");
        uc.mem_map(0, 16 << 20, Prot::ALL).expect("map phys");

        // Physical layout we lay down:
        //   0x0500  GDT (null, flat code 0x08, flat data 0x10)
        //   0x1000  page directory
        //   0x2000  page table for the test virtual address 0x4000_0000
        //   0x3000  page table identity-mapping the low 4 MiB (GDT + tables)
        //   0x100000 the test code, reached only via virtual 0x4000_0000
        let w32 = |uc: &mut Unicorn<()>, addr: u64, v: u32| {
            uc.mem_write(addr, &v.to_le_bytes()).unwrap();
        };

        // GDT.
        uc.mem_write(0x500, &[0u8; 8]).unwrap();
        uc.mem_write(0x508, &flat_desc(0x9A)).unwrap(); // 0x08 ring0 code32
        uc.mem_write(0x510, &flat_desc(0x92)).unwrap(); // 0x10 ring0 data32

        // Page directory: PDE[0] → identity PT, PDE[256] → the 0x4000_0000 PT.
        w32(&mut uc, 0x1000, 0x3000 | PRW);
        w32(&mut uc, 0x1000 + 256 * 4, 0x2000 | PRW); // 0x4000_0000 >> 22 = 256

        // Identity page table for the low 4 MiB.
        for i in 0..1024u64 {
            w32(&mut uc, 0x3000 + i * 4, (i as u32 * 0x1000) | PRW);
        }
        // The test virtual address's page table: PTE[0] → physical 0x100000.
        w32(&mut uc, 0x2000, 0x100000 | PRW);

        // Test code at PHYSICAL 0x100000 — only reachable via virtual
        // 0x4000_0000 if the page-table walk works. `mov eax, 0xDEADBEEF; jmp $`.
        uc.mem_write(0x100000, &[0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEB, 0xFE]).unwrap();

        // Enter protected mode with paging: GDTR, segs, CR3, CR0 = PE|PG.
        uc.reg_write_long(RegisterX86::GDTR, &mmr(0x500, 0x17)).unwrap();
        uc.reg_write(RegisterX86::CR3, 0x1000).unwrap();
        uc.reg_write(RegisterX86::CR4, 0).unwrap(); // non-PAE
        uc.reg_write(RegisterX86::CR0, 0x8000_0001).unwrap(); // PG | PE
        uc.reg_write(RegisterX86::CS, 0x08).unwrap();
        for r in [RegisterX86::DS, RegisterX86::ES, RegisterX86::SS] {
            uc.reg_write(r, 0x10).unwrap();
        }
        uc.reg_write(RegisterX86::EAX, 0).unwrap();

        // Run a few instructions starting at the VIRTUAL address.
        uc.emu_start(0x4000_0000, 0, 0, 4).expect("emu_start under paging");

        let eax = uc.reg_read(RegisterX86::EAX).unwrap();
        assert_eq!(
            eax, 0xDEAD_BEEF,
            "paging walk failed: ran code at virtual 0x40000000 (→ phys 0x100000) \
             should have set EAX, got {eax:#x}"
        );
    }
}

#[cfg(test)]
mod tables {
    use super::*;

    #[test]
    fn map_walk_roundtrip() {
        let pd = new_page_dir();
        // Map a few non-identity pages, including two in the same 4 MiB region
        // (shared page table) and one far away (separate page table).
        let f1 = phys::alloc_frames(1);
        let f2 = phys::alloc_frames(1);
        let f3 = phys::alloc_frames(1);
        map_page(pd, 0x4000_0000, f1, true);
        map_page(pd, 0x4000_1000, f2, true); // same PDE as above
        map_page(pd, 0x8012_3000, f3, false); // different PDE, read-only

        assert_eq!(translate(pd, 0x4000_0000), Some((f1 as u32) << 12));
        assert_eq!(translate(pd, 0x4000_0abc), Some(((f1 as u32) << 12) | 0xabc));
        assert_eq!(translate(pd, 0x4000_1000), Some((f2 as u32) << 12));
        assert_eq!(translate(pd, 0x8012_3000), Some((f3 as u32) << 12));
        assert_eq!(translate(pd, 0x5000_0000), None); // unmapped

        // The two adjacent virtual pages share one page table (one PDE).
        let pde0 = read_entry(pd, pde_index(0x4000_0000));
        assert_eq!(pde0 >> 12, read_entry(pd, pde_index(0x4000_1000)) >> 12);

        // Read-only page clears the W bit in its PTE.
        let pde = read_entry(pd, pde_index(0x8012_3000));
        let pte = read_entry((pde >> 12) as u64, pte_index(0x8012_3000));
        assert_eq!(pte & WRITABLE, 0);

        unmap_page(pd, 0x4000_0000);
        assert_eq!(translate(pd, 0x4000_0000), None);
        assert_eq!(translate(pd, 0x4000_1000), Some((f2 as u32) << 12)); // sibling intact
    }
}

#[cfg(all(test, feature = "tcg"))] // proofs drive Unicorn directly
mod integration {
    use super::*;
    use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Prot};
    use unicorn_engine::{RegisterX86, Unicorn};

    fn flat_desc(access: u8) -> [u8; 8] {
        [0xFF, 0xFF, 0x00, 0x00, 0x00, access, 0xCF, 0x00]
    }
    fn mmr(base: u64, limit: u32) -> [u8; 24] {
        let mut b = [0u8; 24];
        b[8..16].copy_from_slice(&base.to_le_bytes());
        b[16..20].copy_from_slice(&limit.to_le_bytes());
        b
    }
    fn write_phys(paddr: u32, bytes: &[u8]) {
        let ppage = (paddr >> 12) as u64;
        let off = (paddr & 0xFFF) as usize;
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), phys::frame_ptr(ppage).add(off), bytes.len());
        }
    }

    /// The keystone: guest physical RAM is ONE unicorn region (the memfd), the
    /// kernel's page tables live in it, paging is on, and an access to an
    /// UNMAPPED virtual page demand-commits via the #PF handler and retries —
    /// the model the whole migration rests on.
    #[test]
    fn one_region_paging_with_demand_fault() {
        // Track #PF demand-commits via a thread-local because the intr hook
        // closure can't borrow test locals across emu_start.
        thread_local! { static PD: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
        thread_local! { static FAULTS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) }; }

        let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).expect("uc");

        // ONE region: all guest physical RAM = the memfd, mapped once. (16 MiB
        // window is plenty for the test; the real backend maps PHYS_SIZE.)
        let base = phys::frame_ptr(0);
        unsafe {
            uc.mem_map_ptr(0, 16 << 20, Prot::ALL, base as *mut core::ffi::c_void)
                .expect("map the one phys region");
        }

        let pd = new_page_dir();
        PD.with(|c| c.set(pd));

        // Lay out and map: GDT at virtual 0x1000, code at virtual 0x40_0000.
        let gdt_frame = phys::alloc_frames(1);
        let code_frame = phys::alloc_frames(1);
        map_page(pd, 0x1000, gdt_frame, true);
        map_page(pd, 0x40_0000, code_frame, true);

        write_phys(frame_phys(gdt_frame), &[0u8; 8]);
        write_phys(frame_phys(gdt_frame) + 8, &flat_desc(0x9A));
        write_phys(frame_phys(gdt_frame) + 16, &flat_desc(0x92));

        // Code: write 0x42 to the UNMAPPED virtual page 0x80_0000 (demand
        // fault), read it back into EAX, halt. mov [0x800000],0x42; mov eax,[..]; jmp$
        write_phys(
            frame_phys(code_frame),
            &[
                0xC7, 0x05, 0x00, 0x00, 0x80, 0x00, 0x42, 0x00, 0x00, 0x00, // mov dword [0x800000],0x42
                0xA1, 0x00, 0x00, 0x80, 0x00, // mov eax,[0x800000]
                0xEB, 0xFE, // jmp $
            ],
        );

        uc.reg_write_long(RegisterX86::GDTR, &mmr(0x1000, 0x17)).unwrap();
        uc.reg_write(RegisterX86::CR3, frame_phys(pd) as u64).unwrap();
        uc.reg_write(RegisterX86::CR4, 0).unwrap();
        uc.reg_write(RegisterX86::CR0, 0x8000_0001).unwrap();
        uc.reg_write(RegisterX86::CS, 0x08).unwrap();
        for r in [RegisterX86::DS, RegisterX86::ES, RegisterX86::SS] {
            uc.reg_write(r, 0x10).unwrap();
        }

        // Drive: run from the code's virtual address; on a #PF stop, retry from
        // the current EIP (the page is now mapped).
        let mut eip = 0x40_0000u64;
        for _ in 0..8 {
            let _ = uc.emu_start(eip, 0, 0, 8);
            let neip = uc.reg_read(RegisterX86::EIP).unwrap();
            if neip == 0x40_0000 + 15 { break; } // reached the jmp $ self-loop
            if neip == eip {
                // No progress = a paging fault. Demand-commit the page at CR2.
                let cr2 = uc.reg_read(RegisterX86::CR2).unwrap() as u32;
                if translate(PD.with(|c| c.get()), cr2).is_none() {
                    let frame = phys::alloc_frames(1);
                    PD.with(|c| map_page(c.get(), cr2 & !0xFFF, frame, true));
                    FAULTS.with(|c| c.set(c.get() + 1));
                    // Flush unicorn's softmmu TLB so it re-walks the updated PTE.
                    let cr3 = uc.reg_read(RegisterX86::CR3).unwrap();
                    uc.reg_write(RegisterX86::CR3, cr3).unwrap();
                }
            }
            eip = neip;
        }

        assert_eq!(FAULTS.with(|c| c.get()), 1, "expected exactly one demand fault");
        assert_eq!(uc.reg_read(RegisterX86::EAX).unwrap(), 0x42,
            "guest wrote+read the demand-committed page");
        // The kernel-side software walk sees the same byte the guest wrote.
        let phys_of_data = translate(pd, 0x80_0000).expect("0x800000 mapped after fault");
        let byte = unsafe { *phys::frame_ptr((phys_of_data >> 12) as u64) };
        assert_eq!(byte, 0x42, "translate() + phys read matches the guest store");
        let _ = MemType::WRITE; let _ = HookType::MEM_UNMAPPED; // keep imports used
    }
}

// ── Address-space layer ─────────────────────────────────────────────────────
//
// The page-table-based replacement for mmu.rs's `Space` model. An address space
// IS a page directory (a CR3 value); these are the operations the Arch memory
// methods drive. Built on the primitives above; the live wiring (cpu.rs
// build/configure/execute, calls.rs) swaps onto these.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

struct Spaces {
    /// id → page-directory ppage. id 0 is the boot space.
    pd: BTreeMap<u32, u64>,
    active: u32,
    next: u32,
}

thread_local! {
    static SPACES: RefCell<Spaces> =
        const { RefCell::new(Spaces { pd: BTreeMap::new(), active: 0, next: 0 }) };
}

/// Create the boot address space (id 0) and make it active.
pub fn space_init() {
    SPACES.with(|s| {
        let mut s = s.borrow_mut();
        if s.pd.is_empty() {
            let pd = new_page_dir();
            map_kernel_windows(pd);
            s.pd.insert(0, pd);
            s.active = 0;
            s.next = 1;
        }
    });
}

/// Page-directory ppage of the active space (the CR3 value to load).
pub fn active_pd() -> u64 {
    SPACES.with(|s| {
        let s = s.borrow();
        *s.pd.get(&s.active).expect("active space missing")
    })
}

fn with_active_pd<R>(f: impl FnOnce(u64) -> R) -> R {
    f(active_pd())
}

/// Create a fresh empty address space; returns its id.
pub fn space_new() -> u32 {
    SPACES.with(|s| {
        let mut s = s.borrow_mut();
        let id = s.next;
        s.next += 1;
        let pd = new_page_dir();
        map_kernel_windows(pd);
        s.pd.insert(id, pd);
        id
    })
}

/// Switch the active space.
pub fn space_switch(id: u32) {
    SPACES.with(|s| s.borrow_mut().active = id);
}

/// Id of the active space.
pub fn active_id() -> u32 {
    SPACES.with(|s| s.borrow().active)
}


/// Map `count` pages at `vpage` to fresh zeroed frames (the memfd reads zero
/// for never-written frames, and the bump allocator never reuses one).
pub fn space_map_fresh(vpage: usize, count: usize) {
    with_active_pd(|pd| {
        for i in 0..count {
            let v = ((vpage + i) * 4096) as u32;
            let frame = phys::alloc_frames(1);
            map_page(pd, v, frame, true);
        }
    });
}

/// Map `count` guest pages at `vpage` onto physical frames at `ppage`.
pub fn space_map_phys(vpage: usize, count: usize, ppage: u64, writable: bool) {
    with_active_pd(|pd| {
        for i in 0..count {
            map_page(pd, ((vpage + i) * 4096) as u32, ppage + i as u64, writable);
        }
    });
}

/// Set writability across `count` present pages.
pub fn space_set_writable(vpage: usize, count: usize, writable: bool) {
    with_active_pd(|pd| {
        for i in 0..count {
            let v = ((vpage + i) * 4096) as u32;
            let pde = read_entry(pd, pde_index(v));
            if pde & PRESENT == 0 {
                continue;
            }
            let pt = (pde >> 12) as u64;
            let pte = read_entry(pt, pte_index(v));
            if pte & PRESENT == 0 {
                continue;
            }
            let nf = if writable { pte | WRITABLE } else { pte & !WRITABLE };
            write_entry(pt, pte_index(v), nf);
        }
    });
}

/// Clear `count` pages to absent (next access demand-faults).
pub fn space_unmap(vpage: usize, count: usize) {
    with_active_pd(|pd| {
        for i in 0..count {
            unmap_page(pd, ((vpage + i) * 4096) as u32);
        }
    });
}

/// Translate a guest virtual address in the active space.
pub fn space_translate(vaddr: u32) -> Option<u32> {
    translate(active_pd(), vaddr)
}

/// Copy-on-write fork: clone the page-table *structure* into a new space, but
/// share every leaf data frame read-only + COW-marked (bumping its refcount)
/// instead of copying it. A later write in either space #PFs into
/// `space_cow_fault`, which privatises just that one frame. The parent's own
/// PTEs are downgraded to RO+COW too, so its writes fault as well — every slice
/// reloads CR3, so the parent re-walks the new flags on resume. Kernel windows
/// (already mapped shared-writable into the fresh space by `space_new`) are left
/// untouched: the CPL0 trampoline writes its iret frame there.
pub fn space_fork(src: u32) -> u32 {
    let src_pd = SPACES.with(|s| *s.borrow().pd.get(&src).expect("fork src"));
    let dst = space_new();
    let dst_pd = SPACES.with(|s| *s.borrow().pd.get(&dst).unwrap());
    for pde_i in 0..1024usize {
        let pde = read_entry(src_pd, pde_i);
        if pde & PRESENT == 0 {
            continue;
        }
        let src_pt = (pde >> 12) as u64;
        for pte_i in 0..1024usize {
            let pte = read_entry(src_pt, pte_i);
            if pte & PRESENT == 0 {
                continue;
            }
            let v = ((pde_i << 22) | (pte_i << 12)) as u32;
            // Kernel windows are pre-mapped (shared, writable) into the fresh
            // space — never share-COW them (the trampoline writes there).
            if translate(dst_pd, v).is_some() {
                continue;
            }
            let frame = (pte >> 12) as u64;
            if pte & WRITABLE != 0 || pte & COW != 0 {
                // Writable, OR already a COW page from an earlier fork (RO but
                // privately writable): both sides go RO+COW over the one shared
                // frame. Marking src is idempotent when it's already COW — the
                // point is to never demote a COW page to plain-RO, or a
                // grandchild's legitimate write would fault unresolved.
                write_entry(src_pt, pte_i, ((frame as u32) << 12) | PRESENT | USER | COW);
                map_page_cow(dst_pd, v, frame);
            } else {
                // Genuinely read-only (code/rodata): share as-is, no COW needed.
                map_page(dst_pd, v, frame, false);
            }
            phys::inc_ref(frame);
        }
    }
    dst
}

/// Map `vaddr` to `frame` as a copy-on-write page: PRESENT|USER, W=0, COW=1.
fn map_page_cow(pd: u64, vaddr: u32, frame: u64) {
    let pde_i = pde_index(vaddr);
    let pde = read_entry(pd, pde_i);
    let pt = if pde & PRESENT != 0 {
        (pde >> 12) as u64
    } else {
        let pt = alloc_table();
        write_entry(pd, pde_i, ((pt as u32) << 12) | ENTRY_FLAGS);
        pt
    };
    write_entry(pt, pte_index(vaddr), ((frame as u32) << 12) | PRESENT | USER | COW);
}

/// Resolve a write #PF on a present COW page in the active space: privatise the
/// frame (copy if still shared with another space, else just re-enable write)
/// and clear the COW mark. Returns false if `vaddr` isn't a COW page — a
/// genuine read-only/illegal write the kernel must surface as a fault.
pub fn space_cow_fault(vaddr: u32) -> bool {
    with_active_pd(|pd| {
        let pde = read_entry(pd, pde_index(vaddr));
        if pde & PRESENT == 0 {
            return false;
        }
        let pt = (pde >> 12) as u64;
        let pte_i = pte_index(vaddr);
        let pte = read_entry(pt, pte_i);
        if pte & PRESENT == 0 || pte & COW == 0 {
            return false;
        }
        let frame = (pte >> 12) as u64;
        if phys::is_shared(frame) {
            // Still aliased by another space — copy into a private frame.
            let new = phys::alloc_frames(1);
            unsafe {
                core::ptr::copy_nonoverlapping(phys::frame_ptr(frame), phys::frame_ptr(new), 4096);
            }
            write_entry(pt, pte_i, ((new as u32) << 12) | ENTRY_FLAGS);
            phys::free_frames(frame, 1); // drop this space's reference
        } else {
            // Sole owner — no copy; just re-enable write and clear COW.
            write_entry(pt, pte_i, ((frame as u32) << 12) | ENTRY_FLAGS);
        }
        true
    })
}

// ── Kernel windows: mappings every address space must carry ──────────────────
//
// The interpreter's PM/VM86 entry runs a CPL0 `iretd` trampoline through real
// descriptor tables (GDT/LDT) that live in guest physical RAM. Those tables and
// the trampoline are reachable only if mapped in the page directory unicorn
// walks — so every space gets the same high "system" window (and any future
// kernel-side window) at a fixed linear address backed by globally-shared
// frames. The client never touches it; it exists for the segment loads + iret.

thread_local! {
    static KERNEL_WINDOWS: RefCell<Vec<(u32, u64, usize)>> = const { RefCell::new(Vec::new()) };
}

/// Register a linear→physical window (page-granular) that every address space —
/// existing and future — must map. `vaddr`/`count` in pages, `ppage` the shared
/// starting frame. Idempotent enough for one-time setup at backend init.
pub fn register_kernel_window(vpage: usize, ppage: u64, count: usize) {
    KERNEL_WINDOWS.with(|w| w.borrow_mut().push((vpage as u32, ppage, count)));
    // Retro-map into every space that already exists (the boot space).
    SPACES.with(|s| {
        for &pd in s.borrow().pd.values() {
            for i in 0..count {
                map_page(pd, ((vpage + i) * 4096) as u32, ppage + i as u64, true);
            }
        }
    });
}

fn map_kernel_windows(pd: u64) {
    KERNEL_WINDOWS.with(|w| {
        for &(vpage, ppage, count) in w.borrow().iter() {
            for i in 0..count {
                map_page(pd, (vpage as usize + i) as u32 * 4096, ppage + i as u64, true);
            }
        }
    });
}

/// Kernel-side resolve: translate `vaddr` in the active space to a host pointer,
/// demand-committing a fresh zero frame if the page is absent. Mirrors the old
/// `mmu::ensure_committed` (the metal kernel's ring-1 access faults the page in
/// transparently); the interpreter "kernel" is host code, so it does the commit.
pub fn space_resolve(vaddr: u32) -> *mut u8 {
    resolve_in(active_pd(), vaddr)
}

/// Resolve `vaddr` to a host pointer through a SPECIFIC page directory `pd`
/// (a ppage, i.e. CR3>>12), not the ambient active space. Demand-commits an
/// absent page exactly like `space_resolve`.
///
/// The sensitive-instruction monitor must read/write the *interpreted thread's*
/// memory regardless of which space is globally active: a windowed run's
/// render/focus path can move `active` between the slice and the post-slice
/// monitor decode, so binding to the running CR3 (not `active_pd()`) is what
/// keeps the IVT/stack/code reads pointing at the right space. Reproducer:
/// windowed DN #GP'ing on its first INT 21h read a stale space's IVT → wild
/// `0xFFFFFFFE` jump; headless (single space) never diverged.
pub fn resolve_in(pd: u64, vaddr: u32) -> *mut u8 {
    let pa = match translate(pd, vaddr) {
        Some(pa) => pa,
        None => {
            let frame = phys::alloc_frames(1);
            map_page(pd, vaddr & !0xFFF, frame, true);
            (frame as u32) << 12 | (vaddr & 0xFFF)
        }
    };
    unsafe { phys::frame_ptr((pa >> 12) as u64).add((pa & 0xFFF) as usize) }
}

/// Guest-fault resolve from the software CPU (#PF, no EIP progress + CR2). Returns
/// `true` if the page was demand-committed (retry) and `false` for a genuinely
/// illegal access (null guard / out of range) that must bubble as `PageFault`.
const NULL_GUARD: u32 = 0x1_0000;
pub fn space_demand(vaddr: u32) -> bool {
    let page = vaddr & !0xFFF;
    let pd = active_pd();
    if translate(pd, vaddr).is_some() {
        return true; // already present — spurious refault, just retry
    }
    // MMIO/device aperture (present=0 + PCD, e.g. the planar VGA window mapped
    // with MAP_MMIO): trap to the kernel, never demand-commit RAM.
    if pte_raw(pd, vaddr) & CACHE_DISABLE != 0 {
        return false;
    }
    if vaddr < NULL_GUARD || (vaddr as usize) >= 0xC000_0000 {
        return false;
    }
    let frame = phys::alloc_frames(1);
    map_page(pd, page, frame, true);
    true
}

/// Copy `count` page mappings src→dst with fresh frames (content copy — the
/// interp owns a frame per VA, same observable result as a refcount-shared PTE).
pub fn space_copy_entries(src: usize, dst: usize, count: usize) {
    with_active_pd(|pd| {
        for i in 0..count {
            let sv = ((src + i) * 4096) as u32;
            let dv = ((dst + i) * 4096) as u32;
            // Drop the reference dst currently holds before clobbering it, or the
            // old frame leaks (mirror metal's copy_page_entries / unmap).
            if let Some(old_pa) = translate(pd, dv) {
                phys::free_frames((old_pa >> 12) as u64, 1);
            }
            match translate(pd, sv) {
                Some(spa) => {
                    // ALIAS dst onto src's physical frame — do NOT snapshot it
                    // into a fresh frame. The sole caller is the A20-wrap setup
                    // (HMA pages onto low memory), where the two ranges are the
                    // SAME storage on real hardware (A20 forces address bit 20
                    // to 0). A content copy froze HMA at boot, so writes through
                    // low memory never appeared via the wrap and DN/COMMAND read
                    // stale code (the ffbf garbage-execution crash on panel
                    // launch). Metal copies the PTE + bumps a shared refcount;
                    // match that so the two views truly share storage.
                    let frame = (spa >> 12) as u64;
                    let pde = read_entry(pd, pde_index(sv));
                    let pte = read_entry((pde >> 12) as u64, pte_index(sv));
                    map_page(pd, dv, frame, pte & WRITABLE != 0);
                    phys::inc_ref(frame);
                }
                None => unmap_page(pd, dv),
            }
        }
    });
}

/// Swap `count` page mappings a↔b (PTE swap — no content move needed since each
/// VA already owns its frame).
pub fn space_swap_entries(a: usize, b: usize, count: usize) {
    with_active_pd(|pd| {
        for i in 0..count {
            let av = ((a + i) * 4096) as u32;
            let bv = ((b + i) * 4096) as u32;
            let (apde, bpde) = (read_entry(pd, pde_index(av)), read_entry(pd, pde_index(bv)));
            // Ensure both PDEs have a page table so we can write either slot.
            let apt = if apde & PRESENT != 0 { (apde >> 12) as u64 } else {
                let pt = alloc_table(); write_entry(pd, pde_index(av), ((pt as u32) << 12) | ENTRY_FLAGS); pt };
            let bpt = if bpde & PRESENT != 0 { (bpde >> 12) as u64 } else {
                let pt = alloc_table(); write_entry(pd, pde_index(bv), ((pt as u32) << 12) | ENTRY_FLAGS); pt };
            let (ae, be) = (read_entry(apt, pte_index(av)), read_entry(bpt, pte_index(bv)));
            write_entry(apt, pte_index(av), be);
            write_entry(bpt, pte_index(bv), ae);
        }
    });
}

/// Map the first 1 MB of the active space as fresh RW (VM86/DOS low memory:
/// IVT, BDA, BIOS, PSPs). The metal call splits this into BIOS/VGA/ROM regions;
/// the interp's emulated devices don't need that split here.
pub fn space_map_low_mem() {
    space_map_fresh(0, 0x100);
}

/// Free every user page in the active space (arch CLEAN): drop the PTEs and
/// return the frames to the allocator. Kernel windows (high) are left intact.
pub fn space_clean() {
    with_active_pd(free_user_frames);
}

fn free_user_frames(pd: u64) {
    for pde_i in 0..(0xC000_0000usize >> 22) {
        let pde = read_entry(pd, pde_i);
        if pde & PRESENT == 0 {
            continue;
        }
        let pt = (pde >> 12) as u64;
        for pte_i in 0..1024usize {
            let pte = read_entry(pt, pte_i);
            if pte & PRESENT != 0 {
                phys::free_frames((pte >> 12) as u64, 1);
                write_entry(pt, pte_i, 0);
            }
        }
    }
}

/// Destroy a space entirely (reaped thread): free its user frames and forget it.
/// Page-table frames and the PD are leaked back to the bump allocator's reuse
/// only for user frames; id 0 (boot space) is permanent.
pub fn space_destroy(id: u32) {
    if id == 0 {
        return;
    }
    let pd = SPACES.with(|s| s.borrow().pd.get(&id).copied());
    if let Some(pd) = pd {
        free_user_frames(pd);
    }
    SPACES.with(|s| {
        let mut s = s.borrow_mut();
        if s.active == id {
            s.active = 0;
        }
        s.pd.remove(&id);
    });
    LONG_TWINS.with(|t| {
        if let Some(tw) = t.borrow_mut().remove(&id) {
            for f in tw.frames {
                phys::free_frames(f, 1);
            }
        }
    });
}

// ── Long-mode (4-level) twin ─────────────────────────────────────────────────
//
// 64-bit user slices run with PAE 4-level tables; the 2-level tree above stays
// the single source of truth for every mutation (map/unmap/COW/fork/clean).
// Rather than keeping a second tree in lockstep at each of those sites, the
// twin is derived lazily: `write_entry` (the one funnel all mutations pass
// through) bumps a generation, and a 64-bit slice entry calls `active_pml4()`,
// which rebuilds the active space's 4-level tree iff the generation moved
// since the last build. A 32-bit leaf PTE zero-extends into a 64-bit PTE
// unchanged — PRESENT/W/USER/PCD/COW sit at the same bit positions, the frame
// stays in bits 31:12, and bit 63 (NX) stays 0 — so the twin is a bit-faithful
// mirror of the source tree, software markers included. Not-present markers
// (the PCD MMIO trap, COW leftovers) mirror too: the hardware walk #PFs and
// the kernel resolves against the 2-level tree as always, which bumps the
// generation and refreshes the twin on the next 64-bit entry.

/// Intermediate-level (PML4E/PDPTE/PDE) flags: present | writable | user.
const ENTRY_FLAGS64: u64 = ENTRY_FLAGS as u64;

struct LongTwin {
    /// PML4 root frame (ppage) — `frame_phys(pml4)` is the long-mode CR3.
    pml4: u64,
    /// Every table frame of the twin (PML4 included), for wholesale free.
    frames: Vec<u64>,
    /// `LONG_GEN` at build time; any later 2-level write invalidates. Coarse
    /// (a write in space A invalidates B's twin too) but safe, and rebuilds
    /// are a handful of tables for a typical space.
    built_at: u64,
}

thread_local! {
    static LONG_GEN: Cell<u64> = const { Cell::new(1) };
    static LONG_TWINS: RefCell<BTreeMap<u32, LongTwin>> = const { RefCell::new(BTreeMap::new()) };
}

fn read_entry64(ppage: u64, i: usize) -> u64 {
    unsafe { (phys::frame_ptr(ppage).add(i * 8) as *const u64).read_unaligned() }
}
fn write_entry64(ppage: u64, i: usize, v: u64) {
    unsafe { (phys::frame_ptr(ppage).add(i * 8) as *mut u64).write_unaligned(v) }
}

/// Build a fresh 4-level tree mirroring the 2-level tree at `pd`. User VAs are
/// all below 4 GiB, so the shape is PML4[0] → one PDPT → up to 4 PDs → PTs;
/// each 32-bit page table (4 MiB reach) feeds two 64-bit ones (2 MiB reach).
fn build_long_twin(pd: u64) -> (u64, Vec<u64>) {
    let mut frames = Vec::new();
    let fresh = |frames: &mut Vec<u64>| {
        let f = alloc_table();
        frames.push(f);
        f
    };
    let pml4 = fresh(&mut frames);
    let pdpt = fresh(&mut frames);
    write_entry64(pml4, 0, (pdpt << 12) | ENTRY_FLAGS64);
    for pde_i in 0..1024usize {
        let pde = read_entry(pd, pde_i);
        if pde & PRESENT == 0 {
            continue;
        }
        let pt32 = (pde >> 12) as u64;
        for pte_i in 0..1024usize {
            let pte = read_entry(pt32, pte_i);
            if pte == 0 {
                continue; // mirror every non-zero entry, markers included
            }
            let v = ((pde_i << 22) | (pte_i << 12)) as u64;
            let pdpt_i = ((v >> 30) & 0x1FF) as usize;
            let pd_i = ((v >> 21) & 0x1FF) as usize;
            let pt_i = ((v >> 12) & 0x1FF) as usize;
            let pdpte = read_entry64(pdpt, pdpt_i);
            let pd64 = if pdpte & (PRESENT as u64) != 0 {
                pdpte >> 12
            } else {
                let f = fresh(&mut frames);
                write_entry64(pdpt, pdpt_i, (f << 12) | ENTRY_FLAGS64);
                f
            };
            let pde64 = read_entry64(pd64, pd_i);
            let pt64 = if pde64 & (PRESENT as u64) != 0 {
                pde64 >> 12
            } else {
                let f = fresh(&mut frames);
                write_entry64(pd64, pd_i, (f << 12) | ENTRY_FLAGS64);
                f
            };
            write_entry64(pt64, pt_i, pte as u64);
        }
    }
    (pml4, frames)
}

/// PML4 root (ppage — `frame_phys` of it is the CR3 value) for a long-mode
/// slice of the ACTIVE space: the lazily (re)built 4-level twin.
pub fn active_pml4() -> u64 {
    let id = active_id();
    let pd = active_pd();
    let gen = LONG_GEN.with(|g| g.get());
    LONG_TWINS.with(|t| {
        let mut t = t.borrow_mut();
        if let Some(tw) = t.get(&id) {
            if tw.built_at == gen {
                return tw.pml4;
            }
        }
        if let Some(old) = t.remove(&id) {
            for f in old.frames {
                phys::free_frames(f, 1);
            }
        }
        let (pml4, frames) = build_long_twin(pd);
        t.insert(id, LongTwin { pml4, frames, built_at: gen });
        pml4
    })
}

/// 4-level software walk (tests + diagnostics): virtual → physical through a
/// twin rooted at `pml4`, or None on the first not-present entry.
#[cfg(test)]
fn translate64(pml4: u64, vaddr: u64) -> Option<u64> {
    let mut table = pml4;
    for shift in [39u32, 30, 21, 12] {
        let e = read_entry64(table, ((vaddr >> shift) & 0x1FF) as usize);
        if e & (PRESENT as u64) == 0 {
            return None;
        }
        table = (e >> 12) & 0xF_FFFF_FFFF;
        if shift == 12 {
            return Some((table << 12) | (vaddr & 0xFFF));
        }
    }
    unreachable!()
}

#[cfg(test)]
mod space_ops {
    use super::*;

    #[test]
    fn long_twin_mirrors_and_tracks_changes() {
        space_init();
        let s = space_new();
        space_switch(s);
        space_map_fresh(0x10, 2);
        let pml4 = active_pml4();
        assert_eq!(
            translate64(pml4, 0x10_000),
            space_translate(0x10_000).map(u64::from),
            "twin translates a mapped page to the same frame"
        );
        assert_eq!(translate64(pml4, 0x12_000), None, "unmapped stays unmapped");
        assert_eq!(active_pml4(), pml4, "no mutation → same twin, no rebuild");
        // Mutate the source tree → the twin refreshes on next request.
        space_map_fresh(0x12, 1);
        let pml4b = active_pml4();
        assert_eq!(
            translate64(pml4b, 0x12_000),
            space_translate(0x12_000).map(u64::from),
            "rebuilt twin sees the new page"
        );
        // Read-only source PTE mirrors as read-only (W bit clear).
        space_set_writable(0x10, 1, false);
        let pml4c = active_pml4();
        let pa = translate64(pml4c, 0x10_000).expect("still mapped");
        assert_eq!(pa >> 12, space_translate(0x10_000).unwrap() as u64 >> 12);
    }

    #[test]
    fn map_fork_translate() {
        space_init();
        let s = space_new();
        space_switch(s);
        space_map_fresh(0x10, 2); // vpages 0x10,0x11
        let p = space_translate(0x10_000).expect("mapped");
        // Write a marker through the frame and confirm fork copies it.
        unsafe { *phys::frame_ptr((p >> 12) as u64) = 0x7E };
        let child = space_fork(s);
        space_switch(child);
        // Fork is COW: the child shares the parent's frame read-only until a
        // write; the first write privatises through the COW fault path.
        let shared = space_translate(0x10_000).expect("child mapped");
        assert_eq!(p >> 12, shared >> 12, "fork shares the frame (COW)");
        assert!(space_cow_fault(0x10_000), "COW fault privatises the page");
        let cp = space_translate(0x10_000).expect("child mapped after COW");
        assert_ne!(p >> 12, cp >> 12, "COW gave the child its own frame");
        assert_eq!(unsafe { *phys::frame_ptr((cp >> 12) as u64) }, 0x7E, "contents copied");
        // Mutating the child doesn't touch the parent (separate frames).
        unsafe { *phys::frame_ptr((cp >> 12) as u64) = 0x11 };
        assert_eq!(unsafe { *phys::frame_ptr((p >> 12) as u64) }, 0x7E, "parent unchanged");

        space_set_writable(0x10, 1, false);
        let pde = read_entry(active_pd(), pde_index(0x10_000));
        let pte = read_entry((pde >> 12) as u64, pte_index(0x10_000));
        assert_eq!(pte & WRITABLE, 0);
        space_unmap(0x10, 1);
        assert_eq!(space_translate(0x10_000), None);
    }
}

#[cfg(all(test, feature = "tcg"))] // proofs drive Unicorn directly
mod vm86 {
    use super::*;
    use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
    use unicorn_engine::{RegisterX86, Unicorn};

    fn flat_desc(access: u8) -> [u8; 8] { [0xFF,0xFF,0,0,0,access,0xCF,0] }
    fn mmr(base: u64, limit: u32) -> [u8;24] {
        let mut b=[0u8;24]; b[8..16].copy_from_slice(&base.to_le_bytes());
        b[16..20].copy_from_slice(&limit.to_le_bytes()); b }
    fn wphys(paddr: u32, bytes: &[u8]) {
        let pp=(paddr>>12) as u64; let off=(paddr&0xFFF) as usize;
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), phys::frame_ptr(pp).add(off), bytes.len()); }
    }

    /// Can unicorn run a VM86 task (real-mode addressing) THROUGH page tables?
    /// This is what per-thread DOS isolation needs: the VM86 guest's real-mode
    /// linear address (seg<<4 + off) must be translated by the page tables to a
    /// per-thread physical frame — NOT a shared physical address.
    #[test]
    fn vm86_runs_paged() {
        let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).expect("uc");
        let base = phys::frame_ptr(0);
        unsafe { uc.mem_map_ptr(0, 16<<20, Prot::ALL, base as *mut core::ffi::c_void).unwrap(); }

        let pd = new_page_dir();
        // GDT identity-mapped low so the CPL0 trampoline can load flat selectors.
        let gdt = phys::alloc_frames(1);
        map_page(pd, frame_phys(gdt) & !0xFFF, gdt, true); // identity
        wphys(frame_phys(gdt), &[0u8;8]);
        wphys(frame_phys(gdt)+8, &flat_desc(0x9A));   // sel 0x08: ring0 code
        wphys(frame_phys(gdt)+16, &flat_desc(0x92));  // sel 0x10: ring0 data

        // CPL0 trampoline page (identity): a single `iretd` (0xCF) that pops the
        // VM86 frame below and enters the v86 task. This mirrors configure_pm:
        // VM86 is entered by IRET into a frame whose EFLAGS image has VM=1 — the
        // only architecturally valid entry, and how a real kernel does it.
        let tramp = phys::alloc_frames(1);
        let tramp_va = 0x2000u32;
        map_page(pd, tramp_va, tramp, true);
        wphys(frame_phys(tramp), &[0xCFu8]); // iretd

        // Trampoline stack page (identity): holds the 32-bit VM86 iret frame.
        let stk = phys::alloc_frames(1);
        let stk_va = 0x3000u32;
        map_page(pd, stk_va, stk, true);

        // VM86 code lives at linear 0x10000 (CS=0x1000, IP=0) but is mapped to a
        // NON-identity physical frame — proving the translation, not a coincidence.
        let code_frame = phys::alloc_frames(1);
        map_page(pd, 0x10000, code_frame, true);
        // mov ax, 0x1234 (real-mode/16-bit) ; jmp $   →  B8 34 12  EB FE
        wphys(frame_phys(code_frame), &[0xB8, 0x34, 0x12, 0xEB, 0xFE]);
        // A VM86 stack so the v86 task has somewhere to point SS:SP (linear 0x1FFF0).
        let v86stk = phys::alloc_frames(1);
        map_page(pd, 0x1F000, v86stk, true);

        // VM86 iret frame (32-bit iretd from CPL0 to VM86 pops 9 dwords):
        //   EIP, CS, EFLAGS, ESP, SS, ES, DS, FS, GS
        let vm_flags = (1u32 << 17) | 2; // VM | reserved
        let frame: [u32; 9] = [
            0x0000,  // EIP
            0x1000,  // CS  (base 0x10000)
            vm_flags,// EFLAGS with VM=1
            0xFFF0,  // ESP
            0x1000,  // SS  (base 0x10000) — within v86stk page region
            0x1000,  // ES
            0x1000,  // DS
            0x0000,  // FS
            0x0000,  // GS
        ];
        let frame_va = stk_va + 0x800; // some room
        for (i, v) in frame.iter().enumerate() {
            wphys(frame_phys(stk) + 0x800 + (i as u32) * 4, &v.to_le_bytes());
        }

        // Bring CPL0 up the way configure_pm does: real-mode SS load fixes the
        // cached DPL to 0, then PE, then load flat selectors, then enable PG last.
        uc.reg_write(RegisterX86::CR0, 0x10).unwrap();            // real mode (ET)
        uc.reg_write(RegisterX86::SS, 0).unwrap();                // cached DPL 0
        uc.reg_write_long(RegisterX86::GDTR, &mmr((frame_phys(gdt)&!0xFFF) as u64, 0x17)).unwrap();
        uc.reg_write(RegisterX86::CR0, 0x11).unwrap();            // PE on, PG off
        uc.reg_write(RegisterX86::CS, 0x08).unwrap();
        uc.reg_write(RegisterX86::SS, 0x10).unwrap();
        uc.reg_write(RegisterX86::EFLAGS, 2).unwrap();
        uc.reg_write(RegisterX86::ESP, frame_va as u64).unwrap();
        uc.reg_write(RegisterX86::EAX, 0).unwrap();
        // Enable paging (CR3 before PG).
        uc.reg_write(RegisterX86::CR4, 0).unwrap();
        uc.reg_write(RegisterX86::CR3, frame_phys(pd) as u64).unwrap();
        uc.reg_write(RegisterX86::CR0, 0x8000_0011).unwrap();     // PE|PG (+ET)

        use std::cell::Cell;
        thread_local!{ static VEC: Cell<i32> = const { Cell::new(-1) }; }
        uc.add_intr_hook(|_uc, intno| { VEC.with(|c| c.set(intno as i32)); }).unwrap();
        // iretd + mov + a couple jmp-self spins.
        let r = uc.emu_start(tramp_va as u64, 0, 0, 4);
        let cr2 = uc.reg_read(RegisterX86::CR2).unwrap();
        let eip = uc.reg_read(RegisterX86::EIP).unwrap();
        let ax = uc.reg_read(RegisterX86::EAX).unwrap() & 0xFFFF;
        let vm = uc.reg_read(RegisterX86::EFLAGS).unwrap() & (1<<17);
        eprintln!("vm86_paged: r={r:?} ax={ax:#x} vm_flag={vm:#x} intr={} cr2={cr2:#x} eip={eip:#x}",
                  VEC.with(|c| c.get()));
        assert_eq!(ax, 0x1234, "VM86 code ran through the page-table translation");
        assert!(vm != 0, "still in VM86 mode after entry");
    }
}

#[cfg(all(test, feature = "tcg"))] // proofs drive Unicorn directly
mod proof64 {
    use super::*;
    use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
    use unicorn_engine::{RegisterX86, Unicorn};

    /// `uc_x86_msr { rid: u32, value: u64 }` (repr C: 4 bytes pad after rid).
    fn msr_bytes(rid: u32, value: u64) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&rid.to_le_bytes());
        b[8..16].copy_from_slice(&value.to_le_bytes());
        b
    }

    /// Long-mode keystone: a 64-bit unicorn walks the 4-level twin that
    /// `active_pml4()` derived from the ordinary 2-level space — 64-bit code
    /// fetched through a non-identity virtual mapping runs, and a full-width
    /// (REX.W) result reads back. This is the page-table foundation the KVM
    /// and TCG Mode64 slice paths both stand on.
    #[test]
    fn unicorn_walks_the_long_mode_twin() {
        space_init();
        let s = space_new();
        space_switch(s);

        // Code page at virtual 0x40_0000, backed by whatever frame the space
        // allocator picked (non-identity by construction).
        space_map_fresh(0x400, 1);
        let code_pa = space_translate(0x40_0000).expect("mapped");
        // movabs rax, 0x1122334455667788 ; jmp $
        let code: [u8; 12] = [0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xEB, 0xFE];
        unsafe {
            core::ptr::copy_nonoverlapping(
                code.as_ptr(),
                phys::frame_ptr((code_pa >> 12) as u64),
                code.len(),
            );
        }

        let pml4 = active_pml4();

        let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).expect("uc64");
        // ONE region: all guest physical RAM = the memfd (same topology as the
        // 32-bit proofs and the real backend).
        unsafe {
            uc.mem_map_ptr(0, phys::PHYS_SIZE as u64, Prot::ALL, phys::region_base() as *mut core::ffi::c_void)
                .expect("map the one phys region");
        }

        // Bring up the long-mode MMU: PAE, EFER.LME|LMA, CR3 → the twin, PG on.
        // (MODE_64 unicorn already presents a 64-bit CS; only paging is off.)
        uc.reg_write(RegisterX86::CR4, 1 << 5).unwrap(); // PAE
        uc.reg_write(RegisterX86::CR3, frame_phys(pml4) as u64).unwrap();
        uc.reg_write_long(RegisterX86::MSR, &msr_bytes(0xC000_0080, (1 << 8) | (1 << 10)))
            .unwrap(); // EFER = LME | LMA
        uc.reg_write(RegisterX86::CR0, 0x8000_0011).unwrap(); // PG | PE (+ET)

        uc.reg_write(RegisterX86::RAX, 0).unwrap();
        let r = uc.emu_start(0x40_0000, 0, 0, 2);
        let rax = uc.reg_read(RegisterX86::RAX).unwrap();
        let rip = uc.reg_read(RegisterX86::RIP).unwrap();
        eprintln!("proof64: r={r:?} rax={rax:#x} rip={rip:#x}");
        assert_eq!(
            rax, 0x1122_3344_5566_7788,
            "64-bit code at virtual 0x400000 should run through the twin's walk"
        );
    }
}
