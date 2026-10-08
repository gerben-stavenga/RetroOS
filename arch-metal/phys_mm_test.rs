//! Exercise the metal allocator against firmware maps without privileged I/O.
#![allow(dead_code)]

extern crate alloc;

pub static ZERO_PAGE: [u8; 4096] = [0; 4096];
pub struct MultibootMmapEntry { pub base: u64, pub length: u64, pub typ: u32 }
mod paging2 {
    pub const PAGE_SIZE: usize = 4096;
    pub const KERNEL_BASE: usize = 0xc0b00000;
    pub const KERNEL_PHYS: usize = 0x100000;
    #[derive(PartialEq)]
    pub enum CpuMode { Legacy, Pae }
    pub fn cpu_mode() -> CpuMode { CpuMode::Pae }
    pub fn physical_page(_: usize) -> u64 { 0 }
    pub fn unmap_kernel_page(_: usize) { panic!("test must not unmap hardware"); }
}
mod x86 {
    pub fn cpuid(leaf: u32) -> (u32,u32,u32,u32) {
        (if leaf == 0x80000000 { 0x80000008 } else { 36 }, 0,0,0)
    }
}
#[path = "src/phys_mm.rs"]
mod phys_mm;

#[test]
fn firmware_holes_high_ram_and_exhaustion() {
    use phys_mm::*;
    let map = [
        MultibootMmapEntry { base: 0, length: 0x100000, typ: 1 },
        // Integrated graphics/firmware has reserved the first 256 MiB.
        MultibootMmapEntry { base: 0x100000, length: 0xff00000, typ: 2 },
        MultibootMmapEntry { base: 0x10000000, length: 3 * 4096, typ: 1 },
        MultibootMmapEntry { base: 0x1_0000_0000, length: 4096, typ: 1 },
    ];
    init_phys_mm(&map, map.len(), 256, 258);
    complete_initialization();
    assert_eq!(free_page_count(), 4);
    assert_eq!(alloc_phys_page(), Some(0x10000));
    assert_eq!(alloc_phys_page(), Some(0x10001));
    assert_eq!(alloc_phys_page(), Some(0x10002));
    assert_eq!(alloc_phys_page(), Some(0x100000));
    assert_eq!(alloc_phys_page(), None);
    free_phys_page(0x10001);
    assert_eq!(alloc_phys_page(), Some(0x10001));
    assert!(inc_shared_count(0x10001));
    free_phys_page(0x10001);
    assert_eq!(get_ref_count(0x10001), 1);
    free_phys_page(0x10001);
    assert_eq!(alloc_phys_contig(1), Some(0x10001));
    free_phys_contig(0x10001, 1);
    assert_eq!(free_page_count(), 1);
    assert_eq!(alloc_phys_contig(usize::MAX), None);

    // A small, fully allocated machine must terminate after wrapping even
    // when the last successful allocation ended at the tracked RAM limit.
    let small = [MultibootMmapEntry { base: 0, length: 259 * 4096, typ: 1 }];
    init_phys_mm(&small, 1, 256, 258);
    complete_initialization();
    assert_eq!(alloc_phys_page(), Some(258));
    assert_eq!(alloc_phys_page(), None);
    assert_eq!(free_page_count(), 0);
}
