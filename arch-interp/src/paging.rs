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
