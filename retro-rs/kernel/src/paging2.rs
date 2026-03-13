//! Unified paging with recursive scheme
//!
//! Supports both legacy 32-bit paging and PAE paging with a common interface.
//!
//! # Recursive mapping
//!
//! `entries[i]` is the page table entry for virtual page `i`. One self-referential
//! entry (the "recursive entry") makes the entire page table hierarchy visible as
//! a region within this flat array. `parent_index(i) = PAGE_TABLE_BASE_IDX + i / epp`
//! gives the entry that maps the page containing `entries[i]`.
//!
//! The recursive entry is a fixed point: `parent_index(recursive) == recursive`.
//! It divides the array into user and kernel:
//!
//! - `entries[0..recursive]` — user (U/S=1). Leaf PTEs and their page table ancestors.
//! - `entries[recursive..]` — kernel (U/S=0). Recursive entry, kernel page tables, kernel leaves.
//!
//! COW sharing applies only below the recursive entry. The recursive entry itself
//! is always present and hw_writable.
//!
//! # Memory layout
//!
//! ```text
//! 0x00000000 - 0xBFFFFFFF  User space (3 GB)
//! 0xC0000000 - 0xC07FFFFF  Recursive page tables (8 MB)
//! 0xC0800000 - 0xC09FFFFF  PML4 region (2 MB, for future long mode)
//! 0xC0A00000 - 0xC0AFFFFF  Low memory (1 MB, VGA/BIOS)
//! 0xC0B00000 - ...         Kernel code/data
//! ```
//!
//! Legacy mode: PD[768] → PD (recursive entry at entries[0xC0300])
//! PAE mode:    PDPT[3] → PDPT (recursive entry at entries[0xC0603])
//!
//! # PAE recursive mapping
//!
//! It is commonly claimed (e.g. on OSDev) that PAE cannot use recursive paging
//! because the PDPT is only 4 entries and a self-referential entry "wastes 1GB."
//! This is wrong on both counts:
//!
//! 1. The PDPT is 4 entries (32 bytes), but it lives in a 4KB page. The CPU only
//!    reads the first 4 entries during its page walk. The remaining 508 entries
//!    on that page are ignored by hardware — but through the recursive mapping,
//!    they appear in `entries[]` and work as regular kernel page table entries.
//!
//! 2. The 1GB virtual range claimed by the recursive PDPT slot is mostly
//!    not-present entries that cost nothing (demand paged). The actual page table
//!    pages within that range are at most 4 page directories + 2048 page tables
//!    = 8MB. This is far cheaper than Linux's approach on 32-bit, which reserves
//!    up to 896MB of kernel virtual space for a direct physical memory map (and
//!    still can't address all RAM above that, requiring HIGHMEM).
//!
//! # Mode-generic code
//!
//! All paging operations are generic over `Entry` (32-bit or 64-bit) and compute
//! structure from `epp()` (entries per page) and `levels()` at runtime. The
//! recursive mapping normalizes all modes into the same flat array — the formula
//! `parent_index(i) = PAGE_TABLE_BASE_IDX + i / epp` is identical for legacy,
//! PAE, and (future) 4-level paging. Only the number of hops to the fixed point
//! changes.

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

/// Per-process root page table. A union because the representation differs:
/// - Legacy/PML4: just the physical address of the root page table (= CR3 value)
/// - PAE: 4 sanitized PDPT entries, 32-byte aligned. CR3 = physical address of this.
#[repr(C, align(32))]
#[derive(Clone, Copy)]
pub union RootPageTable {
    phys: u32,
    pdpt: [u64; 4],
}

impl RootPageTable {
    pub const fn empty() -> Self {
        RootPageTable { pdpt: [0; 4] }
    }

    /// Initialize from the current (active) address space.
    pub fn init_current(&mut self) {
        if cpu_mode() == CpuMode::Pae {
            populate_pdpt(unsafe { &mut self.pdpt });
        } else {
            self.phys = current_root_phys() as u32;
        }
    }

    /// Initialize from a forked virtual root (accessed via temp_map).
    pub fn init_fork(&mut self, root_phys: u64) {
        if cpu_mode() == CpuMode::Pae {
            populate_pdpt_from(root_phys, unsafe { &mut self.pdpt });
        } else {
            self.phys = root_phys as u32;
        }
    }

    /// CR3 value for this root page table.
    pub fn cr3(&self) -> u32 {
        if cpu_mode() == CpuMode::Pae {
            let vaddr = unsafe { &self.pdpt } as *const _ as usize;
            let page = physical_page(vaddr);
            (page * PAGE_SIZE as u64 + (vaddr % PAGE_SIZE) as u64) as u32
        } else {
            unsafe { self.phys }
        }
    }

    /// Mutable pdpt slice for PAE COW updates. None for legacy/PML4.
    pub fn pdpt_mut(&mut self) -> Option<&mut [u64; 4]> {
        if cpu_mode() == CpuMode::Pae {
            Some(unsafe { &mut self.pdpt })
        } else {
            None
        }
    }

    /// Load this root page table into CR3.
    /// The pdpt entries are already correct — set at fork time and kept
    /// in sync by the page fault handler after COW resolution.
    pub fn activate(&self) {
        unsafe { crate::x86::write_cr3(self.cr3()); }
    }
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

/// Page table entry trait — defines entry format only.
/// Mode-specific constants (ROOT_IDX, USER_ENTRY_LIMIT) are runtime values.
pub trait Entry: Copy + Sized + Default + 'static {
    const ADDR_MASK: u64;

    fn raw(&self) -> u64;
    fn set_raw(&mut self, val: u64);

    fn addr(&self) -> u64 { self.raw() & Self::ADDR_MASK }
    fn page(&self) -> u64 { self.addr() >> 12 }

    fn present(&self) -> bool { self.raw() & flags::PRESENT != 0 }
    /// Hardware R/W bit — does the CPU currently allow writes?
    fn hw_writable(&self) -> bool { self.raw() & flags::READ_WRITE != 0 }
    fn user(&self) -> bool { self.raw() & flags::USER != 0 }
    /// Semantically writable — can become hw_writable via COW
    fn writable(&self) -> bool { self.raw() & flags::SOFT_RO == 0 }

    fn set_flag(&mut self, flag: u64, v: bool) {
        if v { self.set_raw(self.raw() | flag); }
        else { self.set_raw(self.raw() & !flag); }
    }

    fn set_present(&mut self, v: bool) { self.set_flag(flags::PRESENT, v); }
    fn set_hw_writable(&mut self, v: bool) { self.set_flag(flags::READ_WRITE, v); }
    fn set_user(&mut self, v: bool) { self.set_flag(flags::USER, v); }
    fn set_writable(&mut self, v: bool) { self.set_flag(flags::SOFT_RO, !v); }
    fn set_no_execute(&mut self, v: bool) { if nx_enabled() { self.set_flag(flags::NO_EXECUTE, v); } }

    fn new(page: u64, hw_writable: bool, user: bool) -> Self {
        let mut e = Self::default();
        e.set_raw((page << 12) | flags::PRESENT);
        e.set_hw_writable(hw_writable);
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
    pub fn phys_addr(&self) -> u64 {
        self as *const _ as u64
    }

    pub fn phys_page(&self) -> u64 {
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
    pub fn phys_addr(&self) -> u64 {
        self as *const _ as u64
    }

    pub fn phys_page(&self) -> u64 {
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

/// Fixed hardware-facing PDPT for PAE mode.
/// Set up long mode page tables (call after enable_pae)
/// Links PML4[0] = PDPT and PDPT[4] = PML4
pub fn setup_long_mode_tables() {
    let pdpt_phys = crate::x86::read_cr3() as u64;
    let pml4_phys = physical_page(unsafe { (&raw const PML4) as usize });

    // PML4[0] = PDPT (so long mode uses same mappings)
    unsafe { PML4[0] = Entry64::new(pdpt_phys >> 12, true, false); }

    // PDPT[4] = PML4 (so we can access PML4 via PML4_BASE)
    // PDPT is at entries[0xC0600] (address 0xC0603000)
    // Note: this is only called in PAE mode
    if let Entries::E64(e) = entries() {
        e[0xC0600 + 4] = Entry64::new(pml4_phys >> 12, true, false);
    }
}

/// Populate a RootPageTable's pdpt entries from the current virtual root.
/// Sanitizes entries (R/W=0, U/S=0 for hardware) and sets the recursive
/// entry to point to the virtual root (not itself).
pub fn populate_pdpt(pdpt: &mut [u64; 4]) {
    if let Entries::E64(e) = entries() {
        let root = root_base();
        for i in 0..4 {
            let mut entry = e[root + i];
            entry.set_hw_writable(false);
            entry.set_user(false);
            pdpt[i] = entry.0;
        }
        // Recursive slot points to virtual root (NOT itself)
        let virtual_root_page = e[recursive_idx()].page();
        let recursive_slot = recursive_idx() - root;
        pdpt[recursive_slot] = Entry64::new(virtual_root_page, false, false).0;
    }
}

/// Populate pdpt entries from a virtual root accessed via temp_map.
/// Used during fork when the new root isn't the current address space.
pub fn populate_pdpt_from(root_phys: u64, pdpt: &mut [u64; 4]) {
    let root_page = root_phys / PAGE_SIZE as u64;
    temp_map(root_page);
    let src = TEMP_MAP_VADDR as *const Entry64;
    unsafe {
        for i in 0..4 {
            let mut entry = *src.add(i);
            entry.set_hw_writable(false);
            entry.set_user(false);
            pdpt[i] = entry.0;
        }
        // Recursive slot points to virtual root
        let recursive_slot = recursive_idx() - root_base();
        pdpt[recursive_slot] = Entry64::new(root_page, false, false).0;
    }
    temp_unmap();
}

/// Update a single pdpt entry after COW resolution at root level.
pub fn update_pdpt_entry(pdpt: &mut [u64; 4], slot: usize, raw: u64) {
    let mut e = Entry64(raw);
    e.set_hw_writable(false);
    e.set_user(false);
    pdpt[slot] = e.0;
}

/// Check if an entry index is a root-level entry (PDPT level in PAE).
/// Returns the slot index (0-3) if so.
pub fn root_slot(idx: usize) -> Option<usize> {
    let root = root_base();
    if idx >= root && idx < root + 4 {
        Some(idx - root)
    } else {
        None
    }
}

// =============================================================================
// Paging mode and entries access
// =============================================================================

/// Total number of pages in address space
pub const NUM_PAGES: usize = 1 << 20;  // 1M pages = 4GB

/// CPU paging mode, derived from hardware state
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum CpuMode {
    Legacy,  // 32-bit paging, 4B entries
    Pae,     // PAE paging, 8B entries
    Compat,  // Long mode compat, 8B entries
}

/// Read current paging mode from CPU registers (CR4.PAE, EFER.LME)
#[inline]
pub fn cpu_mode() -> CpuMode {
    if crate::x86::read_cr4() & crate::x86::cr4::PAE == 0 {
        CpuMode::Legacy
    } else if !cpu_supports_long_mode() || unsafe { crate::x86::rdmsr(crate::x86::EFER_MSR) } & crate::x86::efer::LME == 0 {
        CpuMode::Pae
    } else {
        CpuMode::Compat
    }
}

/// Number of page table levels for current mode
#[inline]
fn levels() -> usize {
    match cpu_mode() {
        CpuMode::Legacy => 2,  // PD → PT
        CpuMode::Pae => 3,     // PDPT → PD → PT
        CpuMode::Compat => 4,  // PML4 → PDPT → PD → PT
    }
}

/// Entries per page for current mode
#[inline]
fn epp() -> usize {
    match cpu_mode() {
        CpuMode::Legacy => 1024,
        CpuMode::Pae | CpuMode::Compat => 512,
    }
}

/// Index of the recursive entry — the fixed point of parent_index.
/// Divides entries[] into user (below) and kernel (at/above).
#[inline]
pub fn recursive_idx() -> usize {
    let epp = epp();
    let mut idx = PAGE_TABLE_BASE_IDX;
    let mut i = 1;
    while i < levels() {
        idx = PAGE_TABLE_BASE_IDX + idx / epp;
        i += 1;
    }
    idx
}

/// First child of the recursive entry — start of the root page table entries.
#[inline]
fn root_base() -> usize {
    (recursive_idx() - PAGE_TABLE_BASE_IDX) * epp()
}

/// Page table entries — either 32-bit or 64-bit
pub enum Entries {
    E32(&'static mut [Entry32; NUM_PAGES]),
    E64(&'static mut [Entry64; NUM_PAGES]),
}

/// Get page table entries for current paging mode
#[inline]
pub fn entries() -> Entries {
    unsafe {
        if is_pae() {
            Entries::E64(&mut *(PAGE_TABLE_BASE as *mut [Entry64; NUM_PAGES]))
        } else {
            Entries::E32(&mut *(PAGE_TABLE_BASE as *mut [Entry32; NUM_PAGES]))
        }
    }
}

/// Check if using 64-bit entries (PAE or compat)
#[inline]
pub fn is_pae() -> bool {
    cpu_mode() != CpuMode::Legacy
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
pub fn physical_page(vaddr: usize) -> u64 {
    let idx = page_idx(vaddr);
    match entries() {
        Entries::E32(e) => e[idx].page(),
        Entries::E64(e) => e[idx].page(),
    }
}


/// Get current CR3 value (page directory physical address)
pub fn current_cr3() -> u64 {
    (crate::x86::read_cr3() & !(PAGE_SIZE as u32 - 1)) as u64
}

/// Get current process's virtual root physical address.
/// For legacy/compat: same as CR3.
/// For PAE: read from recursive entry (CR3 points to thread's pdpt, not virtual root).
pub fn current_root_phys() -> u64 {
    if cpu_mode() != CpuMode::Pae {
        return crate::x86::read_cr3() as u64;
    }
    // The virtual root's recursive entry points to itself
    let recursive_slot = recursive_idx() - root_base();
    match entries() {
        Entries::E64(e) => e[root_base() + recursive_slot].page() * PAGE_SIZE as u64,
        Entries::E32(_) => unreachable!(),
    }
}

/// Flush TLB
pub fn flush_tlb() {
    crate::x86::flush_tlb();
}

/// Remove identity mapping (call after switching to virtual addresses)
///
/// Clears the first root entry (PD[0] for legacy, PDPT[0] for PAE)
fn remove_identity_mapping<E: Entry>(entries: &mut [E]) {
    entries[root_base()] = E::default();
    flush_tlb();
}

/// Finish paging setup after stack switch
/// - Removes identity mapping
/// - Enables NX if available
/// - Sets up long mode tables if supported
/// - Hardens kernel memory
pub fn finish_setup_paging() {
    match entries() {
        Entries::E32(e) => {
            crate::println!("Paging: Legacy (32-bit)");
            remove_identity_mapping(e);
            harden_kernel(e);
        }
        Entries::E64(e) => {
            crate::println!("Paging: PAE (64-bit entries)");
            if cpu_supports_long_mode() {
                crate::println!("CPU supports Long Mode (64-bit)");

                // Before removing id map copy the compat <-> legacy protmode
                // to identity mapped page
                copy_trampoline();

                // Set up long mode page tables
                setup_long_mode_tables();
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
        scratch[i] = Entry32::new(i as u64, true, false);
    }

    // Map low memory (first 1MB) at LOW_MEM_BASE (0xC0A00000)
    // PT index for 0xC0A00000: (0xC0A00000 >> 12) & 0x3FF = 512
    for i in 0..256 {
        kpages.pt_kernel[512 + i] = Entry32::new(i as u64, true, false);
    }

    // Map kernel at KERNEL_BASE (0xC0B00000)
    // PT index for 0xC0B00000: (0xC0B00000 >> 12) & 0x3FF = 768
    for i in 0..kernel_pages.min(256) {
        kpages.pt_kernel[768 + i] = Entry32::new((kernel_phys / PAGE_SIZE + i) as u64, true, false);
    }

    // Setup page directory
    // PD[0] = identity (first 4MB) using scratch
    kpages.pd[0] = Entry32::new(scratch.phys_page(), true, false);

    // PD[768] = recursive (0xC0000000 >> 22 = 768)
    kpages.pd[768] = Entry32::new(kpages.pd.phys_page(), true, false);

    // PD[770] = kernel region (0xC0800000 >> 22 = 770)
    kpages.pd[770] = Entry32::new(kpages.pt_kernel.phys_page(), true, false);

    unsafe {
        // Load CR3 and enable paging (phys_addr fits in 32 bits during boot)
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
        scratch[i] = Entry64::new(i as u64, true, false);
    }
    // Note: page 0xF is preserved in remove_identity_mapping() for mode switching trampoline

    // Map low memory (first 1MB) at LOW_MEM_BASE (0xC0A00000)
    // PT index 0-255 maps physical 0x00000000-0x000FFFFF
    for i in 0..256 {
        kpages.pt_kernel[i] = Entry64::new(i as u64, true, false);
    }

    // Map kernel at KERNEL_BASE (0xC0B00000)
    // PT index 256-511 maps kernel (up to 1MB)
    for i in 0..kernel_pages.min(256) {
        kpages.pt_kernel[256 + i] = Entry64::new((kernel_phys / PAGE_SIZE + i) as u64, true, false);
    }

    // Setup PDPT (virtual root — has R/W bits for COW tracking)
    kpages.pdpt[0] = Entry64::new(scratch.phys_page(), true, false);
    kpages.pdpt[3] = Entry64::new(kpages.pdpt.phys_page(), true, false);
    kpages.pdpt[4] = Entry64::new(kpages.pt_pml4.phys_page(), true, false);
    kpages.pdpt[5] = Entry64::new(kpages.pt_kernel.phys_page(), true, false);

    // Boot with virtual root in CR3 directly (R/W bits in PDPT[0..3] are
    // technically reserved, but OK for boot — we switch to the thread's
    // thread's RootPageTable once threading is initialized)
    let cr4 = crate::x86::read_cr4();
    unsafe {
        crate::x86::write_cr4(cr4 | crate::x86::cr4::PAE);
        crate::x86::write_cr3(kpages.pdpt.phys_addr() as u32);
        let cr0 = crate::x86::read_cr0();
        crate::x86::write_cr0(cr0 | crate::x86::cr0::PG | crate::x86::cr0::WP);
    }
}

/// Enable paging with auto-detected mode
/// scratch is used for identity mapping (temporary, can be reused after remove_identity_mapping)
pub fn enable_paging(kpages: *mut KernelPages, scratch: *mut RawPage, kernel_phys: usize, kernel_pages: usize) {
    // Note: physical_page() not available until page tables are set up
    if !cpu_supports_pae() {
        let scratch32 = unsafe { &mut *(scratch as *mut PageTable32) };
        enable_legacy(unsafe { (*kpages).legacy() }, scratch32, kernel_phys, kernel_pages);
    } else {
        let scratch64 = unsafe { &mut *(scratch as *mut PageTable64) };
        enable_pae(unsafe { (*kpages).pae() }, scratch64, kernel_phys, kernel_pages);
    }
}

// =============================================================================
// Temporary mapping for fork operations
// =============================================================================

/// Temporary mapping address (first entry of PML4 region, unused)
/// In legacy: pt_kernel[0] maps this. In PAE: pt_pml4[0] maps this.
/// Both are KERNEL_PAGES.pages[1], entry 0.
const TEMP_MAP_VADDR: usize = PML4_BASE;  // 0xC0800000

/// Pointer to the page table that controls TEMP_MAP_VADDR
/// This is KERNEL_PAGES.pages[1] (pt_kernel for legacy, pt_pml4 for PAE)
static mut TEMP_MAP_PT: *mut RawPage = core::ptr::null_mut();

/// Initialize temp mapping (call after paging enabled, before fork)
pub fn init_temp_map() {
    unsafe {
        TEMP_MAP_PT = &raw mut crate::KERNEL_PAGES.pages[1];
    }
}

/// Map a physical page at TEMP_MAP_VADDR
fn temp_map(phys_page: u64) {
    unsafe {
        if is_pae() {
            let pt = TEMP_MAP_PT as *mut Entry64;
            *pt = Entry64::new(phys_page, true, false);
        } else {
            let pt = TEMP_MAP_PT as *mut Entry32;
            *pt = Entry32::new(phys_page, true, false);
        }
    }
    flush_tlb();
}

/// Unmap the temp mapping
fn temp_unmap() {
    unsafe {
        if is_pae() {
            let pt = TEMP_MAP_PT as *mut Entry64;
            *pt = Entry64::default();
        } else {
            let pt = TEMP_MAP_PT as *mut Entry32;
            *pt = Entry32::default();
        }
    }
    flush_tlb();
}

/// Get entries per page for an Entry type
pub const fn entries_per_page<E: Entry>() -> usize {
    PAGE_SIZE / core::mem::size_of::<E>()
}

/// Parent index in entries[] for a given entry index.
/// For a leaf page, this gives the PDE. For a PDE, the PDPTE. Etc.
/// This is the fundamental recursive mapping navigation:
///   parent(idx) = PAGE_TABLE_BASE_IDX + idx / entries_per_page
#[inline]
pub fn parent_index<E: Entry>(idx: usize) -> usize {
    PAGE_TABLE_BASE_IDX + idx / entries_per_page::<E>()
}

/// Alias: PDE index for a leaf page
#[inline]
pub fn pde_index<E: Entry>(page: usize) -> usize {
    parent_index::<E>(page)
}

// =============================================================================
// Lazy COW fork
// =============================================================================

/// Fork the current address space using lazy copy-on-write.
///
/// Copies only the root page table. All child page tables are shared
/// read-only. The page fault handler resolves sharing lazily at every
/// level via the recursive mapping — same algorithm for all paging modes.
pub fn fork_current() -> Option<u64> {
    match entries() {
        Entries::E32(e) => fork_generic(e),
        Entries::E64(e) => fork_generic(e),
    }
}

/// Generic fork: COW the root page table for a new address space.
fn fork_generic<E: Entry>(entries: &mut [E]) -> Option<u64> {
    let rec_idx = recursive_idx();
    let new_root = share_and_copy(entries, rec_idx)?;

    // Patch recursive entry in new copy to point to itself
    temp_map(new_root);
    unsafe {
        let dst = TEMP_MAP_VADDR as *mut E;
        let user_count = rec_idx - root_base();
        *dst.add(user_count) = E::new(new_root, true, false);
    }
    temp_unmap();

    flush_tlb();
    Some(new_root * PAGE_SIZE as u64)
}

// =============================================================================
// COW fault handling
// =============================================================================

/// Mark children of a page table entry as shared R/O and copy the page.
/// Returns the new page's physical page number.
fn share_and_copy<E: Entry>(entries: &mut [E], idx: usize) -> Option<u64> {
    use crate::phys_mm;

    debug_assert!(idx >= PAGE_TABLE_BASE_IDX,
        "share_and_copy: idx {} is a leaf page, not a page table entry", idx);

    let epp = entries_per_page::<E>();
    let child_base = (idx - PAGE_TABLE_BASE_IDX) * epp;

    for i in 0..epp {
        if entries[child_base + i].present() {
            entries[child_base + i].set_hw_writable(false);
            phys_mm::inc_shared_count(entries[child_base + i].page());
        }
    }

    let new_phys = phys_mm::alloc_phys_page()?;

    temp_map(new_phys);
    let dst = TEMP_MAP_VADDR as *mut E;
    unsafe {
        for i in 0..epp {
            *dst.add(i) = entries[child_base + i];
        }
    }
    temp_unmap();

    Some(new_phys)
}

/// COW a single entry (leaf data page or page table).
///
/// If sole owner, just sets hw_writable. Otherwise allocates a new page,
/// copies the old contents, and updates the entry. For page table entries,
/// also marks children R/O and increments their ref counts.
pub fn cow_entry<E: Entry>(entries: &mut [E], idx: usize) {
    use crate::phys_mm;

    debug_assert!(idx < recursive_idx(),
        "cow_entry: idx {} is at or above recursive entry, only user entries can be shared", idx);

    let old_phys = entries[idx].page();

    if phys_mm::get_ref_count(old_phys) == 1 {
        entries[idx].set_hw_writable(true);
        flush_tlb();
        return;
    }

    let new_phys = if idx >= PAGE_TABLE_BASE_IDX {
        share_and_copy(entries, idx).expect("Out of memory during COW")
    } else {
        // Leaf: copy from user VA (still maps old page during copy)
        let p = phys_mm::alloc_phys_page().expect("Out of memory during COW");
        temp_map(p);
        unsafe {
            let src = (idx * PAGE_SIZE) as *const u8;
            let dst = TEMP_MAP_VADDR as *mut u8;
            core::ptr::copy_nonoverlapping(src, dst, PAGE_SIZE);
        }
        temp_unmap();
        p
    };

    let user = entries[idx].user();
    entries[idx] = E::new(new_phys, true, user);
    phys_mm::free_phys_page(old_phys);
    flush_tlb();
}

// =============================================================================
// Free user pages
// =============================================================================

/// Free all user pages in current address space.
///
/// Recursively walks from root user entries down to leaf pages.
/// Shared subtrees (ref count > 1) are freed with a single dec-ref.
/// Sole-owned subtrees are walked and freed page by page.
pub fn free_user_pages() {
    match entries() {
        Entries::E32(e) => free_generic(e),
        Entries::E64(e) => free_generic(e),
    }
}

/// Generic free: walk user root entries, recursively free subtrees.
fn free_generic<E: Entry>(entries: &mut [E]) {
    let root = root_base();
    let user_count = recursive_idx() - root;

    for i in 0..user_count {
        if entries[root + i].present() {
            free_subtree(entries, root + i);
        }
    }
    flush_tlb();
}

/// Recursively free a page table subtree rooted at `parent_idx`.
///
/// If the page at parent_idx is shared (ref > 1), just dec-ref.
/// If sole-owned, walk children: recurse for intermediate levels,
/// free directly for leaf pages.
fn free_subtree<E: Entry>(entries: &mut [E], parent_idx: usize) {
    use crate::phys_mm;

    if !entries[parent_idx].present() {
        return;
    }

    let epp = entries_per_page::<E>();
    let phys = entries[parent_idx].page();

    if phys_mm::get_ref_count(phys) == 1 {
        // Sole owner — walk children
        let child_base = (parent_idx - PAGE_TABLE_BASE_IDX) * epp;
        for j in 0..epp {
            let child = child_base + j;
            if child >= PAGE_TABLE_BASE_IDX {
                // Intermediate level — recurse
                free_subtree(entries, child);
            } else if entries[child].present() {
                // Leaf page — free directly
                phys_mm::free_phys_page(entries[child].page());
                entries[child] = E::default();
            }
        }
        phys_mm::free_phys_page(phys);
    } else {
        // Shared — just decrement ref count
        phys_mm::free_phys_page(phys);
    }

    entries[parent_idx] = E::default();
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
        entries[i].set_hw_writable(false);
    }

    // .rodata: read-only, non-executable
    for i in text_end_page..rodata_end_page {
        entries[i].set_hw_writable(false);
        entries[i].set_no_execute(true);
    }

    // .data/.bss: read-write, non-executable
    for i in data_start_page..data_end_page {
        entries[i].set_no_execute(true);
    }

    flush_tlb();
    crate::println!("Kernel hardening complete");
}
