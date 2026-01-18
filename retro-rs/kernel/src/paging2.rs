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

use core::mem::size_of;
use core::ops::{Index, IndexMut};

/// Page size in bytes
pub const PAGE_SIZE: usize = 4096;

#[derive(Clone)]
#[repr(C, align(4096))]
pub struct RawPage([u8; PAGE_SIZE]);

/// Recursive mapping base - page tables accessible here (PDPT[0-3], 8MB)
pub const PAGE_TABLE_BASE: usize = 0xC000_0000;

/// PML4 region for long mode page tables (PDPT[4], 2MB)
pub const PML4_BASE: usize = 0xC080_0000;

/// Low memory (first 1MB) mapped here for VGA, BIOS, etc. (PDPT[5] first half)
pub const LOW_MEM_BASE: usize = 0xC0A0_0000;

/// Kernel space starts here (PDPT[5+], after low memory)
pub const KERNEL_BASE: usize = 0xC0B0_0000;

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
    pub const COW: u64 = 1 << 9;
}

/// Page table entry trait
pub trait Entry: Copy + Sized + Default + 'static {
    const ADDR_MASK: u64;

    fn raw(&self) -> u64;
    fn set_raw(&mut self, val: u64);

    fn addr(&self) -> usize { (self.raw() & Self::ADDR_MASK) as usize }
    fn page(&self) -> usize { self.addr() >> 12 }

    fn present(&self) -> bool { self.raw() & flags::PRESENT != 0 }
    fn writable(&self) -> bool { self.raw() & flags::READ_WRITE != 0 }
    fn user(&self) -> bool { self.raw() & flags::USER != 0 }
    fn cow(&self) -> bool { self.raw() & flags::COW != 0 }

    fn set_flag(&mut self, flag: u64, v: bool) {
        if v { self.set_raw(self.raw() | flag); }
        else { self.set_raw(self.raw() & !flag); }
    }

    fn set_present(&mut self, v: bool) { self.set_flag(flags::PRESENT, v); }
    fn set_writable(&mut self, v: bool) { self.set_flag(flags::READ_WRITE, v); }
    fn set_user(&mut self, v: bool) { self.set_flag(flags::USER, v); }
    fn set_cow(&mut self, v: bool) { self.set_flag(flags::COW, v); }

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
    fn raw(&self) -> u64 { self.0 as u64 }
    fn set_raw(&mut self, val: u64) { self.0 = val as u32; }
}

#[derive(Copy, Clone, Default)]
#[repr(transparent)]
pub struct Entry64(pub u64);

impl Entry for Entry64 {
    const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
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

// =============================================================================
// Paging mode detection and setup
// =============================================================================

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum PagingMode {
    Legacy,
    Pae,
}

/// Current paging mode (set during boot)
static mut PAGING_MODE: PagingMode = PagingMode::Legacy;

/// Get current paging mode
#[inline]
pub fn mode() -> PagingMode {
    unsafe { PAGING_MODE }
}

/// Number of entries per page table
#[inline]
pub const fn entries_per_page(mode: PagingMode) -> usize {
    match mode {
        PagingMode::Legacy => 1024,
        PagingMode::Pae => 512,
    }
}

/// Entry size in bytes
#[inline]
pub const fn entry_size(mode: PagingMode) -> usize {
    match mode {
        PagingMode::Legacy => 4,
        PagingMode::Pae => 8,
    }
}

/// Total number of pages in address space
pub const NUM_PAGES: usize = 1 << 20;  // 1M pages = 4GB

// =============================================================================
// Runtime paging operations
// =============================================================================

/// Get page index from virtual address
#[inline]
pub const fn page_idx(vaddr: usize) -> usize {
    vaddr / PAGE_SIZE
}

/// Get page table entry for a page index (legacy mode)
#[inline]
pub fn get_entry32(page_idx: usize) -> &'static mut Entry32 {
    unsafe { &mut *((PAGE_TABLE_BASE + page_idx * 4) as *mut Entry32) }
}

/// Get page table entry for a page index (PAE mode)
#[inline]
pub fn get_entry64(page_idx: usize) -> &'static mut Entry64 {
    unsafe { &mut *((PAGE_TABLE_BASE + page_idx * 8) as *mut Entry64) }
}

/// Get physical page number for a virtual address
pub fn physical_page(vaddr: usize) -> usize {
    let idx = page_idx(vaddr);
    match mode() {
        PagingMode::Legacy => get_entry32(idx).page(),
        PagingMode::Pae => get_entry64(idx).page(),
    }
}

/// Check if a page is present
pub fn is_present(page_idx: usize) -> bool {
    match mode() {
        PagingMode::Legacy => get_entry32(page_idx).present(),
        PagingMode::Pae => get_entry64(page_idx).present(),
    }
}

/// Check if a page is user-accessible
pub fn is_user(page_idx: usize) -> bool {
    match mode() {
        PagingMode::Legacy => get_entry32(page_idx).user(),
        PagingMode::Pae => get_entry64(page_idx).user(),
    }
}

/// Check if a page is writable
pub fn is_writable(page_idx: usize) -> bool {
    match mode() {
        PagingMode::Legacy => get_entry32(page_idx).writable(),
        PagingMode::Pae => get_entry64(page_idx).writable(),
    }
}

/// Check if a page is COW
pub fn is_cow(page_idx: usize) -> bool {
    match mode() {
        PagingMode::Legacy => get_entry32(page_idx).cow(),
        PagingMode::Pae => get_entry64(page_idx).cow(),
    }
}

/// Get physical page from page table entry
pub fn get_phys_page(page_idx: usize) -> usize {
    match mode() {
        PagingMode::Legacy => get_entry32(page_idx).page(),
        PagingMode::Pae => get_entry64(page_idx).page(),
    }
}

/// Set page table entry
pub fn set_entry(page_idx: usize, phys_page: usize, writable: bool, user: bool, cow: bool) {
    match mode() {
        PagingMode::Legacy => {
            let mut e = Entry32::new(phys_page, writable, user);
            e.set_cow(cow);
            *get_entry32(page_idx) = e;
        }
        PagingMode::Pae => {
            let mut e = Entry64::new(phys_page, writable, user);
            e.set_cow(cow);
            *get_entry64(page_idx) = e;
        }
    }
}

/// Clear page table entry
pub fn clear_entry(page_idx: usize) {
    match mode() {
        PagingMode::Legacy => *get_entry32(page_idx) = Entry32::default(),
        PagingMode::Pae => *get_entry64(page_idx) = Entry64::default(),
    }
}

/// Set COW flag and clear writable
pub fn mark_cow(page_idx: usize) {
    match mode() {
        PagingMode::Legacy => {
            let e = get_entry32(page_idx);
            e.set_cow(true);
            e.set_writable(false);
        }
        PagingMode::Pae => {
            let e = get_entry64(page_idx);
            e.set_cow(true);
            e.set_writable(false);
        }
    }
}

/// Clear COW flag and set writable
pub fn clear_cow(page_idx: usize) {
    match mode() {
        PagingMode::Legacy => {
            let e = get_entry32(page_idx);
            e.set_cow(false);
            e.set_writable(true);
        }
        PagingMode::Pae => {
            let e = get_entry64(page_idx);
            e.set_cow(false);
            e.set_writable(true);
        }
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
/// In legacy mode: clears PD[0]
/// In PAE mode: clears PDPT[0]
pub fn remove_identity_mapping() {
    match mode() {
        PagingMode::Legacy => {
            crate::println!("Paging: Legacy (32-bit)");
            // PD[0] is at recursive address: PAGE_TABLE_BASE + 0*4
            let pd = PAGE_TABLE_BASE as *mut Entry32;
            unsafe { *pd = Entry32::default(); }
        }
        PagingMode::Pae => {
            crate::println!("Paging: PAE (64-bit entries)");
            // PDPT[0] is at double-recursive address: PAGE_TABLE_BASE + 3*2MB + 0*8
            let pdpt = (PAGE_TABLE_BASE + 3 * 0x200000) as *mut Entry64;
            unsafe { *pdpt = Entry64::default(); }
        }
    }
    flush_tlb();
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

/// Enable legacy paging (32-bit, 2-level)
///
/// PD[0] = identity map first 4MB (uses scratch page, temporary)
/// PD[768] = recursive (PAGE_TABLE_BASE >> 22 = 768)
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
pub fn enable_pae(kpages: &mut PaePages, scratch: &mut PageTable64, kernel_phys: usize, kernel_pages: usize) {
    // Identity map using scratch as both PD and PT (self-referential)
    // scratch[0] = scratch itself, so scratch acts as PD with scratch as PT for first 2MB
    // This skips first 4KB but that's fine
    scratch[0] = Entry64::new(scratch.phys_page(), true, false);
    for i in 1..512 {
        scratch[i] = Entry64::new(i, true, false);
    }

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
    // PDPT[0] = scratch (acts as both PD and PT for identity mapping)
    kpages.pdpt[0] = Entry64::new(scratch.phys_page(), true, false);

    // PDPT[3] = PDPT itself (recursive - makes PDPT act as "virtual PD")
    kpages.pdpt[3] = Entry64::new(kpages.pdpt.phys_page(), true, false);

    // PDPT[4] = pt_pml4 (for PML4 region, leave empty for now)
    kpages.pdpt[4] = Entry64::new(kpages.pt_pml4.phys_page(), true, false);

    // PDPT[5] = pt_kernel (low mem + kernel)
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

/// Get child page index in recursive hierarchy
fn child_page_idx(parent_idx: usize, entry_idx: usize) -> usize {
    let entries = entries_per_page(mode());
    (parent_idx - (PAGE_TABLE_BASE / PAGE_SIZE)) * entries + entry_idx
}

/// Recursively copy page tables for fork, marking user pages as COW
fn recursively_copy_page_table(page_idx: usize) -> usize {
    use crate::phys_mm;

    let cur_page_tab_idx = PAGE_TABLE_BASE / PAGE_SIZE;
    let fork_page_tab_idx = FORK_PAGE_TAB / PAGE_SIZE;
    let entries = entries_per_page(mode());

    if page_idx >= cur_page_tab_idx {
        // This is a page table/directory - copy it
        let dst_offset = page_idx - cur_page_tab_idx;

        for i in 0..entries {
            let present = is_present(page_idx * entries + i);
            let user = is_user(page_idx * entries + i);

            if present && user {
                let child_page = recursively_copy_page_table(child_page_idx(page_idx, i));
                let writable = is_writable(page_idx * entries + i);
                let cow = is_cow(page_idx * entries + i);

                // Write to fork area
                let dst_idx = (fork_page_tab_idx + dst_offset) * entries + i;
                set_entry(dst_idx, child_page, writable, user, cow);
            } else {
                // Copy entry as-is to fork area
                let dst_idx = (fork_page_tab_idx + dst_offset) * entries + i;
                let src_idx = page_idx * entries + i;
                if is_present(src_idx) {
                    let phys = get_phys_page(src_idx);
                    let writable = is_writable(src_idx);
                    let user = is_user(src_idx);
                    let cow = is_cow(src_idx);
                    set_entry(dst_idx, phys, writable, user, cow);
                }
            }
        }

        // Return physical page of destination
        physical_page((fork_page_tab_idx + dst_offset) * PAGE_SIZE)
    } else {
        // User space page - increment ref count and mark COW
        let phys_page = get_phys_page(page_idx);
        phys_mm::inc_shared_count(phys_page);

        // Mark original as COW if it was writable
        if is_writable(page_idx) {
            mark_cow(page_idx);
        }

        phys_page
    }
}

/// Fork the current address space
/// Returns physical address of new page directory, or None on failure
pub fn fork_current() -> Option<u32> {
    use crate::phys_mm;

    // Allocate a page directory from pool
    let new_pd = alloc_page_dir()?;

    // Allocate a physical page for the new page directory content
    let pd_phys_page = phys_mm::alloc_phys_page()?;

    let entries = entries_per_page(mode());
    let fork_pdir_idx = FORK_PAGE_TAB / PAGE_SIZE / entries;

    // Map the new page directory at FORK_PAGE_TAB temporarily
    set_entry(page_idx(new_pd), pd_phys_page, true, false, false);
    flush_tlb();

    // Recursively copy the page tables
    let _root_page = recursively_copy_page_table(NUM_PAGES - 1);

    // Set up the new page directory - copy kernel mappings
    let kernel_start_idx = KERNEL_BASE / PAGE_SIZE / entries;
    for i in kernel_start_idx..(entries - 1) {
        let src_idx = (NUM_PAGES - entries) + i;  // Current page directory entries
        if is_present(src_idx) {
            let phys = get_phys_page(src_idx);
            let writable = is_writable(src_idx);
            let dst_idx = page_idx(new_pd) * entries + i;
            set_entry(dst_idx, phys, writable, false, false);
        }
    }

    // Set up recursive mapping for the new address space
    let last_entry_idx = page_idx(new_pd) * entries + (entries - 1);
    set_entry(last_entry_idx, pd_phys_page, true, false, false);

    // Clear FORK_PAGE_TAB entry in new page directory
    let fork_entry_idx = page_idx(new_pd) * entries + (entries - 2);
    clear_entry(fork_entry_idx);

    // Clear our temporary mapping
    clear_entry(page_idx(new_pd));
    flush_tlb();

    Some((pd_phys_page * PAGE_SIZE) as u32)
}

/// Recursively free all pages in current address space
fn recurse_free_pages(page_idx: usize) {
    use crate::phys_mm;

    if !is_present(page_idx) {
        return;
    }

    let cur_page_tab_idx = PAGE_TABLE_BASE / PAGE_SIZE;
    let entries = entries_per_page(mode());

    if page_idx >= cur_page_tab_idx {
        // Page table - recurse into it
        for i in 0..entries {
            let child_idx = child_page_idx(page_idx, i);
            if is_present(page_idx * entries + i) && is_user(page_idx * entries + i) {
                recurse_free_pages(child_idx);
            }
        }
    }

    phys_mm::free_phys_page(get_phys_page(page_idx));
}

/// Free all user pages in current address space
pub fn free_user_pages() {
    recurse_free_pages(NUM_PAGES - 1);
}
