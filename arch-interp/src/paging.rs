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
/// Write entry `i` of the table in frame `ppage`.
fn write_entry(ppage: u64, i: usize, v: u32) {
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

#[cfg(test)]
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
        w32(&mut uc, 0x1000 + 0 * 4, 0x3000 | PRW);
        w32(&mut uc, 0x1000 + 256 * 4, 0x2000 | PRW); // 0x4000_0000 >> 22 = 256

        // Identity page table for the low 4 MiB.
        for i in 0..1024u64 {
            w32(&mut uc, 0x3000 + i * 4, (i as u32 * 0x1000) | PRW);
        }
        // The test virtual address's page table: PTE[0] → physical 0x100000.
        w32(&mut uc, 0x2000 + 0 * 4, 0x100000 | PRW);

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
