//! Unified paging with recursive scheme
//!
//! Supports both legacy 32-bit paging and PAE paging with a common interface.
//!
//! Memory layout (common for both modes):
//! ```text
//! 0x00000000 - 0xBFFFFFFF  User space (3 GB)
//! 0xC0000000 - 0xC07FFFFF  Recursive page tables (8 MB)
//! 0xC0800000 - 0xC09FFFFF  PML4 region (2 MB, for future long mode)
//! 0xC0A00000 - 0xC0AFFFFF  Low memory (1 MB, VGA/BIOS)
//! 0xC0B00000 - ...         Kernel code/data
//! ```
//!
//! Legacy mode: PD[768] → PD (recursive)
//! PAE mode:    PDPT[3] → PDPT (recursive, PDPT acts as 512-entry "virtual PD")

use core::ops::{Index, IndexMut};

/// Page size in bytes
pub const PAGE_SIZE: usize = 4096;

#[derive(Clone)]
#[repr(C, align(4096))]
pub struct RawPage([u8; PAGE_SIZE]);

/// Recursive mapping base - page tables accessible here (PDPT[0-3], 8MB)
pub const PAGE_TABLE_BASE: usize = 0xC000_0000;

/// Page index where page tables start (PAGE_TABLE_BASE / PAGE_SIZE)
pub const PAGE_TABLE_BASE_IDX: usize = PAGE_TABLE_BASE / PAGE_SIZE;

/// PML4 region for long mode page tables (PDPT[4], 2MB)
pub const PML4_BASE: usize = 0xC080_0000;

/// Low memory (first 1MB) mapped here for VGA, BIOS, etc. (PDPT[5] first half)
pub const LOW_MEM_BASE: usize = 0xC0A0_0000;

/// Kernel space starts here (PDPT[5+], after low memory)
pub const KERNEL_BASE: usize = 0xC0B0_0000;

/// Kernel physical base address (set during paging init)
static mut KERNEL_PHYS_BASE: usize = 0;

/// Convert kernel virtual address to physical
pub fn virt_to_phys(virt: usize) -> usize {
    unsafe { virt - KERNEL_BASE + KERNEL_PHYS_BASE }
}

/// Set kernel physical base (must be called after paging enabled)
pub fn set_kernel_phys_base(phys: usize) {
    unsafe { KERNEL_PHYS_BASE = phys };
}

// =============================================================================
// Entry types - 32-bit and 64-bit page table entries
// =============================================================================

pub mod flags {
    pub const PRESENT: u64 = 1 << 0;
    pub const READ_WRITE: u64 = 1 << 1;
    pub const USER: u64 = 1 << 2;
    pub const WRITE_THROUGH: u64 = 1 << 3;
    pub const CACHE_DISABLE: u64 = 1 << 4;
    pub const ACCESSED: u64 = 1 << 5;
    pub const DIRTY: u64 = 1 << 6;
    pub const PAGE_SIZE_BIT: u64 = 1 << 7;
    /// Software read-only flag - page is semantically read-only
    /// When set, page can never become writable (e.g., .text, .rodata)
    /// When clear (default), page is semantically writable
    pub const SOFT_RO: u64 = 1 << 9;
    pub const NO_EXECUTE: u64 = 1 << 63;  // NX bit (PAE/long mode only)
}

/// Page table entry trait
pub trait Entry: Copy + Sized + Default + 'static {
    const ADDR_MASK: u64;
    /// Page index where user entries end (recursive entry location)
    const USER_ENTRY_LIMIT: usize;
    /// Page index where root page table starts (via recursive mapping)
    const ROOT_IDX: usize;

    fn raw(&self) -> u64;
    fn set_raw(&mut self, val: u64);

    fn addr(&self) -> usize { (self.raw() & Self::ADDR_MASK) as usize }
    fn page(&self) -> usize { self.addr() >> 12 }

    fn present(&self) -> bool { self.raw() & flags::PRESENT != 0 }
    fn writable(&self) -> bool { self.raw() & flags::READ_WRITE != 0 }
    fn user(&self) -> bool { self.raw() & flags::USER != 0 }
    fn soft_ro(&self) -> bool { self.raw() & flags::SOFT_RO != 0 }

    fn set_flag(&mut self, flag: u64, v: bool) {
        if v { self.set_raw(self.raw() | flag); }
        else { self.set_raw(self.raw() & !flag); }
    }

    fn set_present(&mut self, v: bool) { self.set_flag(flags::PRESENT, v); }
    fn set_writable(&mut self, v: bool) { self.set_flag(flags::READ_WRITE, v); }
    fn set_user(&mut self, v: bool) { self.set_flag(flags::USER, v); }
    fn set_soft_ro(&mut self, v: bool) { self.set_flag(flags::SOFT_RO, v); }
    fn set_no_execute(&mut self, v: bool) { if nx_enabled() { self.set_flag(flags::NO_EXECUTE, v); } }

    fn new(page: usize, writable: bool, user: bool) -> Self {
        let mut e = Self::default();
        e.set_raw((page << 12) as u64 | flags::PRESENT);
        e.set_writable(writable);
        e.set_user(user);
        e
    }
}

#[derive(Copy, Clone, Default)]
#[repr(transparent)]
pub struct Entry32(pub u32);

impl Entry for Entry32 {
    const ADDR_MASK: u64 = 0xFFFF_F000;
    const USER_ENTRY_LIMIT: usize = 0xC0300;  // PD[768]
    const ROOT_IDX: usize = 0xC0000;  // PD via recursive mapping
    fn raw(&self) -> u64 { self.0 as u64 }
    fn set_raw(&mut self, val: u64) { self.0 = val as u32; }
}

#[derive(Copy, Clone, Default)]
#[repr(transparent)]
pub struct Entry64(pub u64);

impl Entry for Entry64 {
    const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    const USER_ENTRY_LIMIT: usize = 0xC0603;  // PDPT[3]
    const ROOT_IDX: usize = 0xC0600;  // PDPT via recursive mapping
    fn raw(&self) -> u64 { self.0 }
    fn set_raw(&mut self, val: u64) { self.0 = val; }
}

// =============================================================================
// Typed page tables
// =============================================================================

/// Legacy mode page table: 1024 x 32-bit entries = 4KB
#[derive(Clone)]
#[repr(transparent)]
pub struct PageTable32(pub RawPage);

impl PageTable32 {
    pub fn phys_addr(&self) -> usize {
        self as *const _ as usize
    }

    pub fn phys_page(&self) -> usize {
        self.phys_addr() >> 12
    }
}

impl Index<usize> for PageTable32 {
    type Output = Entry32;
    fn index(&self, idx: usize) -> &Entry32 { 
        unsafe { &core::mem::transmute::<_, &[Entry32; 1024]>(self)[idx] }
    }
}

impl IndexMut<usize> for PageTable32 {
    fn index_mut(&mut self, idx: usize) -> &mut Entry32 { 
        unsafe { &mut core::mem::transmute::<_, &mut [Entry32; 1024]>(self)[idx] }
    }
}

/// PAE mode page table: 512 x 64-bit entries = 4KB
#[derive(Clone)]
#[repr(transparent)]
pub struct PageTable64(pub RawPage);

impl PageTable64 {
    pub fn phys_addr(&self) -> usize {
        self as *const _ as usize
    }

    pub fn phys_page(&self) -> usize {
        self.phys_addr() >> 12
    }
}

impl Index<usize> for PageTable64 {
    type Output = Entry64;
    fn index(&self, idx: usize) -> &Entry64 { 
        unsafe { &core::mem::transmute::<_, &[Entry64; 512]>(self)[idx] }
    }
}

impl IndexMut<usize> for PageTable64 {
    fn index_mut(&mut self, idx: usize) -> &mut Entry64 { 
        unsafe { &mut core::mem::transmute::<_, &mut [Entry64; 512]>(self)[idx] } 
    }
}

// =============================================================================
// Kernel page tables - separate structs for each mode, unified via union
// =============================================================================

/// Legacy mode kernel page tables (3 pages = 12KB)
///
/// PD[768] = PD (recursive, 0xC0000000)
/// PD[770] = pt_kernel (0xC0800000-0xC0BFFFFF: PML4 + low mem + kernel)
/// Identity mapping uses SCRATCH page (temporary, removed after boot)
#[derive(Clone)]
#[repr(C)]
pub struct LegacyPages {
    /// Page Directory
    pub pd: PageTable32,
    /// Page table for kernel region (0xC0800000-0xC0BFFFFF)
    /// PT[0-511]: PML4 region, PT[512-767]: low mem, PT[768-1023]: kernel
    pub pt_kernel: PageTable32,
}

/// PAE mode kernel page tables (3 pages = 12KB)
///
/// With PDPT[3] = PDPT (recursive), the PDPT acts as a 512-entry "virtual PD"
/// for addresses 0xC0000000-0xFFFFFFFF. PDPT[4-511] become kernel PD entries.
/// Identity mapping uses SCRATCH page as both PD and PT (temporary, removed after boot)
/// Assumes kernel < 1MB (same as legacy mode)
#[derive(Clone)]
#[repr(C)]
pub struct PaePages {
    /// PDPT - also acts as "virtual PD" via PDPT[3] recursion
    /// PDPT[0] = scratch (identity), PDPT[3] = PDPT, PDPT[4] = pt_pml4, PDPT[5] = pt_kernel
    pub pdpt: PageTable64,
    /// Page table for PML4 region (PDPT[4], covers 0xC0800000-0xC09FFFFF)
    pub pt_pml4: PageTable64,
    /// Page table for low mem + kernel (PDPT[5], 0xC0A00000-0xC0BFFFFF)
    pub pt_kernel: PageTable64,
}

/// Kernel page tables (3 pages for PAE, 2 for legacy)
pub struct KernelPages {
    pages: [RawPage; 3]
}

impl KernelPages {
    pub fn legacy(&mut self) -> &mut LegacyPages {
        unsafe { core::mem::transmute(self) }
    }

    pub fn pae(&mut self) -> &mut PaePages {
        unsafe {
            core::mem::transmute(self)
        }
    }
}

/// PML4 for long mode - shared with PAE via PML4[0] = PDPT
static mut PML4: PageTable64 = PageTable64(RawPage([0; PAGE_SIZE]));

/// Set up long mode page tables (call after enable_pae)
/// Links PML4[0] = PDPT and PDPT[4] = PML4
pub fn setup_long_mode_tables(pdpt_phys: usize) {
    let pml4_phys = virt_to_phys(unsafe { (&raw const PML4) as usize });

    // PML4[0] = PDPT (so long mode uses same mappings)
    unsafe { PML4[0] = Entry64::new(pdpt_phys >> 12, true, false); }

    // PDPT[4] = PML4 (so we can access PML4 via PML4_BASE)
    // PDPT is at entries[0xC0600] (address 0xC0603000)
    // Note: this is only called in PAE mode
    if let Entries::Pae(e) = entries() {
        e[0xC0600 + 4] = Entry64::new(pml4_phys >> 12, true, false);
    }
}

/// Get PML4 physical address for long mode CR3
pub fn pml4_phys() -> u32 {
    virt_to_phys(unsafe { (&raw const PML4) as usize }) as u32
}

/// Get PDPT physical address for PAE CR3
pub fn pdpt_phys() -> u32 {
    // PDPT physical = current CR3 in PAE mode
    crate::x86::read_cr3()
}

// =============================================================================
// Paging mode and entries access
// =============================================================================

/// Total number of pages in address space
pub const NUM_PAGES: usize = 1 << 20;  // 1M pages = 4GB

/// Paging mode indicator (internal)
#[derive(Copy, Clone, PartialEq, Eq)]
enum PagingMode {
    Legacy,
    Pae,
}

/// Current paging mode (set during boot)
static mut PAGING_MODE: PagingMode = PagingMode::Legacy;

/// Page table entries - either legacy 32-bit or PAE 64-bit
pub enum Entries {
    Legacy(&'static mut [Entry32; NUM_PAGES]),
    Pae(&'static mut [Entry64; NUM_PAGES]),
}

/// Get page table entries for current paging mode
#[inline]
pub fn entries() -> Entries {
    unsafe {
        match PAGING_MODE {
            PagingMode::Legacy => Entries::Legacy(&mut *(PAGE_TABLE_BASE as *mut [Entry32; NUM_PAGES])),
            PagingMode::Pae => Entries::Pae(&mut *(PAGE_TABLE_BASE as *mut [Entry64; NUM_PAGES])),
        }
    }
}

/// Check if PAE mode is active
#[inline]
pub fn is_pae() -> bool {
    unsafe { PAGING_MODE == PagingMode::Pae }
}

// =============================================================================
// Runtime paging operations
// =============================================================================

/// Get page index from virtual address
#[inline]
pub const fn page_idx(vaddr: usize) -> usize {
    vaddr / PAGE_SIZE
}

/// Get physical page number for a virtual address
pub fn physical_page(vaddr: usize) -> usize {
    let idx = page_idx(vaddr);
    match entries() {
        Entries::Legacy(e) => e[idx].page(),
        Entries::Pae(e) => e[idx].page(),
    }
}

/// Switch to a new page directory
pub fn switch_page_dir(phys_addr: u32) {
    unsafe { crate::x86::write_cr3(phys_addr) };
}

/// Get current CR3 value (page directory physical address)
pub fn current_cr3() -> usize {
    (crate::x86::read_cr3() & !(PAGE_SIZE as u32 - 1)) as usize
}

/// Flush TLB
pub fn flush_tlb() {
    crate::x86::flush_tlb();
}

/// Remove identity mapping (call after switching to virtual addresses)
///
/// Clears the first root entry (PD[0] for legacy, PDPT[0] for PAE)
fn remove_identity_mapping<E: Entry>(entries: &mut [E]) {
    entries[E::ROOT_IDX] = E::default();
    flush_tlb();
}

/// Finish paging setup after stack switch
/// - Removes identity mapping
/// - Enables NX if available
/// - Sets up long mode tables if supported
/// - Hardens kernel memory
pub fn finish_setup_paging() {
    match entries() {
        Entries::Legacy(e) => {
            crate::println!("Paging: Legacy (32-bit)");
            remove_identity_mapping(e);
            harden_kernel(e);
        }
        Entries::Pae(e) => {
            crate::println!("Paging: PAE (64-bit entries)");
            if cpu_supports_long_mode() {
                crate::println!("CPU supports Long Mode (64-bit)");

                // Before removing id map copy the compat <-> legacy protmode 
                // to identity mapped page
                copy_trampoline();

                // Set up long mode page tables
                let pdpt = pdpt_phys() as usize;
                setup_long_mode_tables(pdpt);
                crate::println!("Long mode tables set up");
            }

            remove_identity_mapping(e);

            if cpu_supports_nx() {
                crate::println!("CPU supports NX");
                enable_nx();
            }
            harden_kernel(e);
            flush_tlb();
        }
    }
}

/// Check if CPU supports PAE (CPUID.1:EDX bit 6)
pub fn cpu_supports_pae() -> bool {
    let (_, _, _, edx) = crate::x86::cpuid(1);
    edx & (1 << 6) != 0
}

/// Check if CPU supports long mode (CPUID.80000001:EDX bit 29)
pub fn cpu_supports_long_mode() -> bool {
    let (max_ext, _, _, _) = crate::x86::cpuid(0x80000000);
    if max_ext < 0x80000001 { return false; }
    let (_, _, _, edx) = crate::x86::cpuid(0x80000001);
    edx & (1 << 29) != 0
}

/// Check if CPU supports NX/XD bit (CPUID.80000001:EDX bit 20)
pub fn cpu_supports_nx() -> bool {
    let (max_ext, _, _, _) = crate::x86::cpuid(0x80000000);
    if max_ext < 0x80000001 { return false; }
    let (_, _, _, edx) = crate::x86::cpuid(0x80000001);
    edx & (1 << 20) != 0
}

/// NX enabled flag (set when EFER.NXE is enabled)
static mut NX_ENABLED: bool = false;

/// Check if NX is currently enabled
pub fn nx_enabled() -> bool {
    unsafe { NX_ENABLED }
}

/// Enable NX bit support (sets EFER.NXE)
pub fn enable_nx() {
    if !cpu_supports_nx() || !is_pae() {
        return;  // NX requires PAE or long mode
    }
    unsafe {
        let efer = crate::x86::rdmsr(crate::x86::EFER_MSR);
        crate::x86::wrmsr(crate::x86::EFER_MSR, efer | crate::x86::efer::NXE);
        NX_ENABLED = true;
    }
}

/// Enable legacy paging (32-bit, 2-level)
///
/// PD[0] = identity map first 4MB (uses scratch page, temporary)
/// PD[768] = recursive (0xC0000000 >> 22 = 768)
/// PD[770] = kernel region (0xC0800000 >> 22 = 770)
///   PT[0-511]: PML4 region (0xC0800000-0xC09FFFFF)
///   PT[512-767]: low mem (0xC0A00000-0xC0AFFFFF)
///   PT[768-1023]: kernel (0xC0B00000-0xC0BFFFFF)
pub fn enable_legacy(kpages: &mut LegacyPages, scratch: &mut PageTable32, kernel_phys: usize, kernel_pages: usize) {
    // Identity map first 4MB (1024 pages) using scratch page
    for i in 0..1024 {
        scratch[i] = Entry32::new(i, true, false);
    }

    // Map low memory (first 1MB) at LOW_MEM_BASE (0xC0A00000)
    // PT index for 0xC0A00000: (0xC0A00000 >> 12) & 0x3FF = 512
    for i in 0..256 {
        kpages.pt_kernel[512 + i] = Entry32::new(i, true, false);
    }

    // Map kernel at KERNEL_BASE (0xC0B00000)
    // PT index for 0xC0B00000: (0xC0B00000 >> 12) & 0x3FF = 768
    for i in 0..kernel_pages.min(256) {
        kpages.pt_kernel[768 + i] = Entry32::new(kernel_phys / PAGE_SIZE + i, true, false);
    }

    // Setup page directory
    // PD[0] = identity (first 4MB) using scratch
    kpages.pd[0] = Entry32::new(scratch.phys_page(), true, false);

    // PD[768] = recursive (0xC0000000 >> 22 = 768)
    kpages.pd[768] = Entry32::new(kpages.pd.phys_page(), true, false);

    // PD[770] = kernel region (0xC0800000 >> 22 = 770)
    kpages.pd[770] = Entry32::new(kpages.pt_kernel.phys_page(), true, false);

    unsafe {
        // Load CR3 and enable paging
        crate::x86::write_cr3(kpages.pd.phys_addr() as u32);
        let cr0 = crate::x86::read_cr0();
        crate::x86::write_cr0(cr0 | crate::x86::cr0::PG | crate::x86::cr0::WP);
    }
}

/// Enable PAE paging (3-level with 64-bit entries)
///
/// PAE structure: PDPT (4 entries) -> PD (512 entries) -> PT (512 entries)
/// With PDPT[3] = PDPT (recursive), PDPT becomes a 512-entry "virtual PD"
///
/// PDPT[0] = scratch (identity, scratch[0] = scratch for self-referential PD+PT)
/// PDPT[3] = PDPT itself (recursive, for 0xC0000000-0xFFFFFFFF)
/// PDPT[4] = pt_pml4 (0xC0800000-0xC09FFFFF, PML4 region)
/// PDPT[5] = pt_kernel (0xC0A00000-0xC0BFFFFF, low mem + kernel)
/// Assumes kernel < 1MB (same as legacy mode)
///
pub fn enable_pae(kpages: &mut PaePages, scratch: &mut PageTable64, kernel_phys: usize, kernel_pages: usize) {
    // Identity map using scratch as both PD and PT (self-referential)
    // scratch[0] = scratch itself, so scratch acts as PD with scratch as PT for first 2MB
    scratch[0] = Entry64::new(scratch.phys_page(), true, false);
    for i in 1..512 {
        scratch[i] = Entry64::new(i, true, false);
    }
    // Note: page 0xF is preserved in remove_identity_mapping() for mode switching trampoline

    // Map low memory (first 1MB) at LOW_MEM_BASE (0xC0A00000)
    // PT index 0-255 maps physical 0x00000000-0x000FFFFF
    for i in 0..256 {
        kpages.pt_kernel[i] = Entry64::new(i, true, false);
    }

    // Map kernel at KERNEL_BASE (0xC0B00000)
    // PT index 256-511 maps kernel (up to 1MB)
    for i in 0..kernel_pages.min(256) {
        kpages.pt_kernel[256 + i] = Entry64::new(kernel_phys / PAGE_SIZE + i, true, false);
    }

    // Setup PDPT entries
    // Note: PDPT[0-3] are read as PDPTEs in PAE mode, where bits 1-2 are reserved.
    // However, PDPT[0] is also accessed via recursive mapping as a PDE, where bit 1 = R/W.
    // We set bit 1 for PDE functionality; QEMU/real hardware may not enforce reserved bits
    // for supervisor-mode accesses (or cache PDPTEs on CR3 load).
    // PDPT[3] can use pdpte() since it's only needed for the recursive self-reference.

    // PDPT[0] = scratch (acts as both PD and PT for identity mapping)
    kpages.pdpt[0] = Entry64::new(scratch.phys_page(), true, false);

    // PDPT[3] = PDPT itself (recursive - makes PDPT act as "virtual PD")
    // Note: This is read as PDPTE (bits 1-2 "reserved") but also as PDE via recursion.
    // We set R/W=1 for writability. QEMU/KVM caches PDPTEs on CR3 load and doesn't
    // re-check reserved bits on every access. Real hardware may vary.
    kpages.pdpt[3] = Entry64::new(kpages.pdpt.phys_page(), true, false);

    // PDPT[4] = pt_pml4 (for PML4 region, accessed only via recursive mapping)
    kpages.pdpt[4] = Entry64::new(kpages.pt_pml4.phys_page(), true, false);

    // PDPT[5] = pt_kernel (low mem + kernel, accessed only via recursive mapping)
    kpages.pdpt[5] = Entry64::new(kpages.pt_kernel.phys_page(), true, false);

    // Enable PAE in CR4
    let cr4 = crate::x86::read_cr4();
    unsafe {
        crate::x86::write_cr4(cr4 | crate::x86::cr4::PAE);

        // Load CR3 and enable paging
        crate::x86::write_cr3(kpages.pdpt.phys_addr() as u32);
        let cr0 = crate::x86::read_cr0();
        crate::x86::write_cr0(cr0 | crate::x86::cr0::PG | crate::x86::cr0::WP);
    }
}

/// Enable paging with auto-detected mode
/// scratch is used for identity mapping (temporary, can be reused after remove_identity_mapping)
pub fn enable_paging(kpages: *mut KernelPages, scratch: *mut RawPage, kernel_phys: usize, kernel_pages: usize) {
    // Note: KERNEL_PHYS_BASE set later via set_kernel_phys_base() after paging enabled
    let m = if !cpu_supports_pae() {
        let scratch32 = unsafe { &mut *(scratch as *mut PageTable32) };
        enable_legacy(unsafe { (*kpages).legacy() }, scratch32, kernel_phys, kernel_pages);
        PagingMode::Legacy
    } else {
        let scratch64 = unsafe { &mut *(scratch as *mut PageTable64) };
        enable_pae(unsafe { (*kpages).pae() }, scratch64, kernel_phys, kernel_pages);
        PagingMode::Pae
    };
    unsafe { PAGING_MODE = m };
}

// =============================================================================
// Page directory pool for fork
// =============================================================================

/// Temporary mapping area for fork operations (within PML4 region)
pub const FORK_PAGE_TAB: usize = 0xC090_0000;

/// Pool of pre-allocated page directories
const NUM_PAGE_DIRS: usize = 1024;
static mut PAGE_DIR_POOL: [usize; NUM_PAGE_DIRS] = [0; NUM_PAGE_DIRS];
static mut NUM_FREE_PAGE_DIRS: usize = 0;

/// Initialize the page directory pool
pub fn init_page_dir_pool() {
    unsafe {
        for i in 0..NUM_PAGE_DIRS {
            PAGE_DIR_POOL[i] = LOW_MEM_BASE - (i + 1) * PAGE_SIZE;
        }
        NUM_FREE_PAGE_DIRS = NUM_PAGE_DIRS;
    }
}

/// Allocate a page directory from the pool
fn alloc_page_dir() -> Option<usize> {
    unsafe {
        if NUM_FREE_PAGE_DIRS == 0 {
            return None;
        }
        NUM_FREE_PAGE_DIRS -= 1;
        Some(PAGE_DIR_POOL[NUM_FREE_PAGE_DIRS])
    }
}

/// Free a page directory back to the pool
fn free_page_dir(pd: usize) {
    unsafe {
        if NUM_FREE_PAGE_DIRS < NUM_PAGE_DIRS {
            PAGE_DIR_POOL[NUM_FREE_PAGE_DIRS] = pd;
            NUM_FREE_PAGE_DIRS += 1;
        }
    }
}

// =============================================================================
// Fork and free operations
// =============================================================================

/// Get entries per page for an Entry type
const fn entries_per_page_for<E: Entry>() -> usize {
    PAGE_SIZE / core::mem::size_of::<E>()
}

/// Get child page index in recursive hierarchy
fn child_page_idx_for<E: Entry>(parent_idx: usize, entry_idx: usize) -> usize {
    let entries = entries_per_page_for::<E>();
    (parent_idx - PAGE_TABLE_BASE_IDX) * entries + entry_idx
}

/// Recursively copy page tables for fork, marking user pages as COW
fn recursively_copy_page_table_generic<E: Entry>(
    entries: &mut [E],
    page_idx: usize,
) -> usize {
    use crate::phys_mm;

    let fork_page_tab_idx = FORK_PAGE_TAB / PAGE_SIZE;
    let epp = entries_per_page_for::<E>();

    if page_idx >= PAGE_TABLE_BASE_IDX {
        // This is a page table/directory - copy it
        let dst_offset = page_idx - PAGE_TABLE_BASE_IDX;

        for i in 0..epp {
            let src_idx = page_idx * epp + i;
            // Copy entry values before mutable borrow
            let present = entries[src_idx].present();
            let user = entries[src_idx].user();
            let readonly = entries[src_idx].soft_ro();
            let phys = entries[src_idx].page();

            if present && user {
                let child_page = recursively_copy_page_table_generic(
                    entries,
                    child_page_idx_for::<E>(page_idx, i),
                );

                // Write to fork area
                let dst_idx = (fork_page_tab_idx + dst_offset) * epp + i;
                let mut e = E::new(child_page, !readonly, user);
                e.set_soft_ro(readonly);
                entries[dst_idx] = e;
            } else if present {
                // Copy entry as-is to fork area
                let dst_idx = (fork_page_tab_idx + dst_offset) * epp + i;
                let mut e = E::new(phys, !readonly, user);
                e.set_soft_ro(readonly);
                entries[dst_idx] = e;
            }
        }

        // Return physical page of destination
        entries[fork_page_tab_idx + dst_offset].page()
    } else {
        // User space page - increment ref count, mark read-only for COW
        let phys_page = entries[page_idx].page();
        phys_mm::inc_shared_count(phys_page);

        // Make read-only if it was writable (COW sharing)
        if entries[page_idx].writable() {
            entries[page_idx].set_writable(false);
        }

        phys_page
    }
}

/// Fork the current address space (generic over Entry type)
fn fork_current_generic<E: Entry>(entries: &mut [E], pd_phys_page: usize, new_pd_idx: usize) {
    let epp = entries_per_page_for::<E>();

    // Recursively copy the page tables
    let _root_page = recursively_copy_page_table_generic(entries, NUM_PAGES - 1);

    // Set up the new page directory - copy kernel mappings
    let kernel_start_idx = KERNEL_BASE / PAGE_SIZE / epp;
    for i in kernel_start_idx..(epp - 1) {
        let src_idx = (NUM_PAGES - epp) + i;  // Current page directory entries
        if entries[src_idx].present() {
            let phys = entries[src_idx].page();
            let dst_idx = new_pd_idx * epp + i;
            entries[dst_idx] = E::new(phys, true, false);  // kernel, writable
        }
    }

    // Set up recursive mapping for the new address space
    let last_entry_idx = new_pd_idx * epp + (epp - 1);
    entries[last_entry_idx] = E::new(pd_phys_page, true, false);  // kernel, writable

    // Clear FORK_PAGE_TAB entry in new page directory
    let fork_entry_idx = new_pd_idx * epp + (epp - 2);
    entries[fork_entry_idx] = E::default();
}

/// Fork the current address space
/// Returns physical address of new page directory, or None on failure
pub fn fork_current() -> Option<u32> {
    use crate::phys_mm;

    // Allocate a page directory from pool
    let new_pd = alloc_page_dir()?;

    // Allocate a physical page for the new page directory content
    let pd_phys_page = phys_mm::alloc_phys_page()?;

    let new_pd_idx = page_idx(new_pd);

    // Map the new page directory at FORK_PAGE_TAB temporarily (kernel, writable)
    match entries() {
        Entries::Legacy(e) => {
            e[new_pd_idx] = Entry32::new(pd_phys_page, true, false);
            flush_tlb();
            fork_current_generic(e, pd_phys_page, new_pd_idx);
            e[new_pd_idx] = Entry32::default();
        }
        Entries::Pae(e) => {
            e[new_pd_idx] = Entry64::new(pd_phys_page, true, false);
            flush_tlb();
            fork_current_generic(e, pd_phys_page, new_pd_idx);
            e[new_pd_idx] = Entry64::default();
        }
    }
    flush_tlb();

    Some((pd_phys_page * PAGE_SIZE) as u32)
}

/// Recursively free all pages in current address space (generic)
fn recurse_free_pages_generic<E: Entry>(entries: &mut [E], page_idx: usize) {
    use crate::phys_mm;

    if !entries[page_idx].present() {
        return;
    }

    let epp = entries_per_page_for::<E>();

    if page_idx >= PAGE_TABLE_BASE_IDX {
        // Page table - recurse into it
        for i in 0..epp {
            let entry_idx = page_idx * epp + i;
            if entries[entry_idx].present() && entries[entry_idx].user() {
                let child_idx = child_page_idx_for::<E>(page_idx, i);
                recurse_free_pages_generic(entries, child_idx);
            }
        }
    }

    phys_mm::free_phys_page(entries[page_idx].page());
}

/// Free all user pages in current address space
pub fn free_user_pages() {
    match entries() {
        Entries::Legacy(e) => recurse_free_pages_generic(e, NUM_PAGES - 1),
        Entries::Pae(e) => recurse_free_pages_generic(e, NUM_PAGES - 1),
    }
}

// =============================================================================
// Mode switching trampoline support
// =============================================================================

/// Trampoline page physical address (last page of first 64KB)
pub const TRAMPOLINE_PAGE: usize = 0xF;  // page 15 = address 0xF000
pub const TRAMPOLINE_ADDR: usize = TRAMPOLINE_PAGE * PAGE_SIZE;

/// Copy trampoline code to physical address 0xF000
/// Uses LOW_MEM_BASE mapping to access the destination
pub fn copy_trampoline() {
    unsafe extern "C" {
        static trampoline_start: u8;
        static trampoline_end: u8;
    }

    unsafe {
        let src = &raw const trampoline_start;
        let end = &raw const trampoline_end;
        let size = end as usize - src as usize;

        // Destination is physical 0xF000, mapped at LOW_MEM_BASE + 0xF000
        let dst = (LOW_MEM_BASE + TRAMPOLINE_ADDR) as *mut u8;

        core::ptr::copy_nonoverlapping(src, dst, size);
    }
}

/// Harden kernel memory permissions
/// - .text: read-only, executable
/// - .rodata: read-only, non-executable (if NX available)
/// - .data/.bss: read-write, non-executable (if NX available)
fn harden_kernel<E: Entry>(entries: &mut [E]) {
    // Get linker symbols
    unsafe extern "C" {
        static _start: u8;
        static _etext: u8;
        static _erodata: u8;
        static _data: u8;
        static _end: u8;
    }

    let text_start = (&raw const _start) as usize;
    let text_end = (&raw const _etext) as usize;
    let rodata_end = (&raw const _erodata) as usize;
    let data_start = (&raw const _data) as usize;
    let data_end = (&raw const _end) as usize;

    let text_start_page = page_idx(text_start);
    let text_end_page = page_idx(text_end + PAGE_SIZE - 1);
    let rodata_end_page = page_idx(rodata_end + PAGE_SIZE - 1);
    let data_start_page = page_idx(data_start);
    let data_end_page = page_idx(data_end + PAGE_SIZE - 1);

    crate::println!("Hardening kernel:");
    crate::println!("  .text:   {:#x}-{:#x} (pages {}-{}): R-X",
        text_start, text_end, text_start_page, text_end_page);
    crate::println!("  .rodata: {:#x}-{:#x} (pages {}-{}): R-- NX",
        text_end, rodata_end, text_end_page, rodata_end_page);
    crate::println!("  .data:   {:#x}-{:#x} (pages {}-{}): RW- NX",
        data_start, data_end, data_start_page, data_end_page);

    // .text: read-only, executable (no NX)
    for i in text_start_page..text_end_page {
        entries[i].set_writable(false);
    }

    // .rodata: read-only, non-executable
    for i in text_end_page..rodata_end_page {
        entries[i].set_writable(false);
        entries[i].set_no_execute(true);
    }

    // .data/.bss: read-write, non-executable
    for i in data_start_page..data_end_page {
        entries[i].set_no_execute(true);
    }

    flush_tlb();
    crate::println!("Kernel hardening complete");
}
