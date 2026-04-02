//! # Paging design
//!
//! ## Address space layout
//!
//! ```text
//! 0x00000000 - 0xBFFFFFFF  User space (3 GB, 3 root entries)
//! 0xC0000000 - 0xC07FFFFF  Recursive page tables (8 MB)
//! 0xC0800000 - 0xC09FFFFF  PML4 region (2 MB, compat mode only)
//! 0xC0A00000 - 0xC0AFFFFF  Low memory (1 MB, VGA/BIOS identity map)
//! 0xC0B00000 - ...         Kernel code/data
//! ```
//!
//! ## Recursive mapping
//!
//! One entry in the root page table points back to itself. This makes
//! the entire page table hierarchy appear as a flat array at 0xC0000000:
//!
//!   `entries[i]` = page table entry for virtual page `i`
//!   `parent_index(i) = PAGE_TABLE_BASE_IDX + i / epp`
//!
//! The recursive entry is the fixed point of parent_index. It divides
//! entries[] into user (below) and kernel (at and above). COW sharing
//! applies only to user entries.
//!
//! All operations — fork, COW, free, fault handling — are generic over
//! entry size and work identically for any paging depth. The formula
//! above is the same for 2-level, 3-level, and 4-level paging. Only
//! epp (entries per page: 1024 for 32-bit, 512 for 64-bit) differs.
//!
//! ## Constant root page
//!
//! The root page table (PD or PDPT) is a constant static page in the
//! kernel. Kernel entries (recursive, PML4 back-pointer, kernel PTs)
//! live in this constant page and are automatically shared by all
//! processes. Only user entries differ per-process.
//!
//! Per-thread storage (`RootPageTable`):
//! - Legacy: 768 saved PD entries (user PD[0..768])
//! - PAE/Compat: 3 saved PDPT entries (user PDPT[0..3]) + CR3
//!
//! Context switch: load thread's user entries into the constant root,
//! then reload CR3 (flushes TLB, re-reads hardware PDPT in PAE).
//!
//! ## Legacy mode (i386, 2-level)
//!
//! ```text
//! PD (constant static page, 1024 entries, 4B each)
//! ├── PD[0..767]   → user PTs (per-process, swapped at ctx switch)
//! ├── PD[768]      → PD (recursive, constant)
//! └── PD[770]      → kernel PT (constant)
//! ```
//!
//! - CR3 = PD phys (constant)
//! - Fork: share_and_copy(PD). Auto-patches PD[768]→self. Done.
//!
//! ## Compat mode (x86-64, 4-level, 32-bit kernel in compatibility mode)
//!
//! ```text
//! PML4 (constant static page, CR3 points here)
//! └── PML4[0]      → PDPT (constant)
//!
//! PDPT (constant static page)
//! ├── PDPT[0..2]   → user PDs (per-process, swapped at ctx switch)
//! ├── PDPT[3]      → PDPT (recursive, constant)
//! ├── PDPT[4]      → PML4 (back-pointer, constant)
//! └── PDPT[5]      → kernel PT (constant)
//! ```
//!
//! - CR3 = PML4 phys (constant, unless 64-bit process deshares PML4)
//! - Fork: share_and_copy(PDPT). Auto-patches PDPT[3]→self.
//!   Shares PDPT[0..2] (user PDs) and PDPT[4] (PML4). Done.
//!
//! ## PAE mode (pre-x86-64, 3-level)
//!
//! Same as compat (constant PDPT, fork share_and_copy), plus one
//! workaround: PAE hardware ignores R/W on PDPT entries, so COW
//! can't be enforced at that level. After fork, deshare PDPT[0..2]
//! immediately (cow_entry each shared PD). This pushes COW enforcement
//! to the PD level where hardware respects R/W.
//!
//! PAE CR3 points to a 32-byte hardware PDPT (separate static mut),
//! updated from the constant PDPT at context switch.
//!
//! ## Fork (all modes)
//!
//! share_and_copy the root (PD for legacy, PDPT for PAE/compat).
//! Self-referential entries are auto-patched. PAE deshares [0..2].

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

/// Low memory (first 1MB) mapped here for VGA, BIOS, etc. (PDPT[5] first half)
pub const LOW_MEM_BASE: usize = 0xC0A0_0000;

/// Kernel space starts here (PDPT[5+], after low memory)
pub const KERNEL_BASE: usize = 0xC0B0_0000;

/// Per-thread saved root page table entries.
///
/// The root page (PD or PDPT) is a constant static page. This struct
/// holds the per-process user entries that get swapped into the constant
/// root at context switch.
///
/// - Legacy: 768 PD entries (user PD[0..768])
/// - PAE/Compat: 3 PDPT entries (user PDPT[0..3]) + CR3 value
#[repr(C)]
#[derive(Clone, Copy)]
pub union RootPageTable {
    pub e32: [Entry32; 768],    // Legacy: user PD entries
    pub e64: [Entry64; 4],      // PAE/Compat: PDPT[0..3] + CR3
}

/// Hardware PDPT for PAE mode (32 bytes, loaded by CPU on CR3 reload).
/// Separate from the constant virtual PDPT page.
#[repr(C, align(32))]
struct HwPdpt([u64; 4]);
static mut HW_PDPT: HwPdpt = HwPdpt([0; 4]);

impl RootPageTable {
    pub const fn empty() -> Self {
        RootPageTable { e32: [Entry32(0); 768] }
    }

    /// Initialize from the current (active) address space.
    /// Saves current user entries from the constant root.
    /// Save user entries from the constant root into this struct.
    pub fn save(&mut self) {
        match cpu_mode() {
            CpuMode::Legacy => {
                if let Entries::E32(e) = entries() {
                    let root = root_base();
                    let user_count = recursive_idx() - root;
                    for i in 0..user_count {
                        unsafe { self.e32[i] = e[root + i]; }
                    }
                }
            }
            CpuMode::Pae | CpuMode::Compat => {
                if let Entries::E64(e) = entries() {
                    let root = root_base();
                    let user_count = recursive_idx() - root;
                    for i in 0..user_count {
                        unsafe { self.e64[i] = e[root + i]; }
                    }
                    // Always save PML4 phys (from PDPT[4] back-pointer),
                    // so cr3() works regardless of which mode we restore in.
                    let pml4_page = e[root + 4].page();
                    unsafe { self.e64[3] = Entry64(pml4_page * PAGE_SIZE as u64); }
                }
            }
        }
    }

    /// Load user entries from this struct into the constant root.
    /// Does NOT reload CR3 — call activate() for that, or use with
    /// toggle_cr3() when a mode switch follows.
    pub fn load_entries(&self) {
        match cpu_mode() {
            CpuMode::Legacy => {
                if let Entries::E32(e) = entries() {
                    let root = root_base();
                    let user_count = recursive_idx() - root;
                    for i in 0..user_count {
                        e[root + i] = unsafe { self.e32[i] };
                    }
                }
            }
            CpuMode::Pae | CpuMode::Compat => {
                if let Entries::E64(e) = entries() {
                    let root = root_base();
                    let user_count = recursive_idx() - root;
                    for i in 0..user_count {
                        e[root + i] = unsafe { self.e64[i] };
                    }
                    // Debug removed
                }
            }
        }
    }

    /// Load user entries into constant root and reload CR3.
    /// Use when no mode toggle is needed.
    pub fn activate(&self) {
        self.load_entries();
        if cpu_mode() == CpuMode::Pae {
            sync_hw_pdpt();
        }
        unsafe { crate::arch::x86::write_cr3(self.cr3() as u32); }
    }

    /// CR3 value for this address space.
    /// - Legacy: constant PD phys
    /// - PAE: constant hardware PDPT phys
    /// - Compat: PML4 phys from e64[3] (saved from PDPT[4] back-pointer)
    pub fn cr3(&self) -> u64 {
        match cpu_mode() {
            CpuMode::Legacy => current_root_phys(),
            CpuMode::Pae => unsafe {
                let vaddr = (&raw const HW_PDPT) as usize;
                let page = physical_page(vaddr);
                page * PAGE_SIZE as u64 + (vaddr % PAGE_SIZE) as u64
            },
            CpuMode::Compat => unsafe { self.e64[3].0 & !(PAGE_SIZE as u64 - 1) },
        }
    }

    /// Initialize for a forked child.
    /// Copies user entries from the forked root page (via temp_map)
    /// and sets CR3.
    pub fn init_fork(&mut self, new_root_phys: u64) {
        match cpu_mode() {
            CpuMode::Legacy => {
                let user_count = recursive_idx() - root_base();
                temp_map(new_root_phys);
                unsafe {
                    let src = temp_map_vaddr() as *const Entry32;
                    for i in 0..user_count {
                        self.e32[i] = *src.add(i);
                    }
                }
                temp_unmap();
            }
            CpuMode::Pae | CpuMode::Compat => {
                let user_count = recursive_idx() - root_base();
                temp_map(new_root_phys);
                unsafe {
                    let src = temp_map_vaddr() as *const Entry64;
                    for i in 0..user_count {
                        self.e64[i] = *src.add(i);
                    }
                    // (init_fork debug removed)
                }
                temp_unmap();
                // Read PML4 phys from live constant root (not parent's saved root which may be empty)
                if let Entries::E64(e) = entries() {
                    let pml4_page = e[root_base() + 4].page();
                    unsafe { self.e64[3] = Entry64(pml4_page * PAGE_SIZE as u64); }
                }
            }
        }
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

/// Set up long mode page tables (call after enable_pae)
/// Sets PML4[0] = PDPT so long mode uses same address space.
/// Note: vroot[4] (pt_pml4) is NOT overwritten — the PML4 page must not
/// double as a page table, otherwise demand paging writes PTEs into it
/// and corrupts PML4 entries.
pub fn setup_long_mode_tables() {
    let pdpt_phys = crate::arch::x86::read_cr3() as u64;
    let pml4_phys = physical_page(unsafe { (&raw const PML4) as usize });

    // PML4[0] = PDPT (so long mode uses same mappings)
    unsafe { PML4[0] = Entry64::new(pdpt_phys >> 12, true, true); }

    // PDPT[4] = PML4 (back-pointer so PML4 is visible in recursive mapping)
    if let Entries::E64(e) = entries() {
        e[root_base() + 4] = Entry64::new(pml4_phys, true, false);
    }
}

/// Get the root CR3 value (constant PD/PML4 phys).
/// For legacy: PD phys. For PAE: HW_PDPT phys. For compat: PML4 phys.
pub fn root_cr3() -> u64 {
    match cpu_mode() {
        CpuMode::Legacy => current_root_phys(),
        CpuMode::Pae => unsafe {
            let vaddr = (&raw const HW_PDPT) as usize;
            let page = physical_page(vaddr);
            page * PAGE_SIZE as u64 + (vaddr % PAGE_SIZE) as u64
        },
        CpuMode::Compat => {
            let pml4_phys = physical_page(unsafe { (&raw const PML4) as usize });
            pml4_phys * PAGE_SIZE as u64
        },
    }
}

/// CR3 for the TARGET mode after a toggle.
/// PAE→compat (want_64=true): PML4 phys
/// compat→PAE (want_64=false): HW_PDPT phys
/// Call load_entries() + sync_hw_pdpt() before this when going to PAE.
pub fn toggle_cr3(want_64: bool) -> u32 {
    if want_64 {
        // Target is long/compat mode → CR3 = PML4 phys
        let pml4_phys = physical_page(unsafe { (&raw const PML4) as usize });
        (pml4_phys * PAGE_SIZE as u64) as u32
    } else {
        // Target is PAE → CR3 = HW_PDPT phys
        unsafe {
            let vaddr = (&raw const HW_PDPT) as usize;
            let page = physical_page(vaddr);
            (page * PAGE_SIZE as u64 + (vaddr % PAGE_SIZE) as u64) as u32
        }
    }
}

/// Copy constant PDPT[0..4] to the hardware PDPT (PAE only).
/// Sanitizes entries: R/W=0, U/S=0 (hardware ignores these, but
/// keep them clean).
pub fn sync_hw_pdpt() {
    if cpu_mode() == CpuMode::Legacy { return; }

    if let Entries::E64(e) = entries() {
        let root = root_base();
        for i in 0..4 {
            let mut entry = e[root + i];
            entry.set_hw_writable(false);
            entry.set_user(false);
            unsafe { HW_PDPT.0[i] = entry.0; }
        }
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
    if crate::arch::x86::read_cr4() & crate::arch::x86::cr4::PAE == 0 {
        CpuMode::Legacy
    } else if !cpu_supports_long_mode() || unsafe { crate::arch::x86::rdmsr(crate::arch::x86::EFER_MSR) } & crate::arch::x86::efer::LME == 0 {
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
pub fn root_base() -> usize {
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

/// Hash the user address space structure.
/// Walks the page table tree, hashing canonical physical page indices
/// (assigned sequentially as encountered) and stable permission bits
/// (SOFT_RO, WRITE_THROUGH, USER, NO_EXECUTE — but not READ_WRITE/ACCESSED/DIRTY
/// which are COW-flippable or hardware-updated).
pub fn hash_address_space() -> u64 {
    match entries() {
        Entries::E32(e) => {
            let mut ctx = HashCtx::new();
            hash_walk(e, &mut ctx);
            ctx.h
        }
        Entries::E64(e) => {
            let mut ctx = HashCtx::new();
            hash_walk(e, &mut ctx);
            ctx.h
        }
    }
}

struct HashCtx {
    h: u64,
    phys_map: alloc::collections::BTreeMap<u64, u64>,
    next_id: u64,
}

impl HashCtx {
    fn new() -> Self {
        Self { h: 0xcbf29ce484222325, phys_map: alloc::collections::BTreeMap::new(), next_id: 0 }
    }

    fn feed(&mut self, val: u64) {
        self.h ^= val;
        self.h = self.h.wrapping_mul(0x100000001b3);
    }

    fn canon_id(&mut self, phys: u64) -> u64 {
        if let Some(&id) = self.phys_map.get(&phys) {
            id
        } else {
            let id = self.next_id;
            self.next_id += 1;
            self.phys_map.insert(phys, id);
            id
        }
    }
}

/// Stable bits to include in hash (not COW-flippable, not hw-updated)
const HASH_MASK: u64 = flags::PRESENT | flags::SOFT_RO | flags::WRITE_THROUGH
    | flags::USER | flags::NO_EXECUTE;

fn hash_walk<E: Entry>(entries: &[E], ctx: &mut HashCtx) {
    let root = root_base();
    let user_count = recursive_idx() - root;
    for i in 0..user_count {
        hash_node(entries, root + i, ctx);
    }
}

fn hash_node<E: Entry>(entries: &[E], idx: usize, ctx: &mut HashCtx) {
    let e = entries[idx];
    if !e.present() {
        ctx.feed(0);
        return;
    }
    let phys = e.page();
    let id = if e.raw() & flags::WRITE_THROUGH != 0 { phys } else { ctx.canon_id(phys) };
    ctx.feed(id | ((e.raw() & HASH_MASK) << 48));

    if idx < PAGE_TABLE_BASE_IDX {
        // Leaf — hash the 4K page data (skip volatile MMIO/WT pages)
        if e.raw() & flags::WRITE_THROUGH == 0 {
            let base = (idx * PAGE_SIZE) as *const u64;
            for i in 0..(PAGE_SIZE / 8) {
                ctx.feed(unsafe { *base.add(i) });
            }
        }
    } else {
        // Interior — recurse into children
        let epp = entries_per_page::<E>();
        let child_base = (idx - PAGE_TABLE_BASE_IDX) * epp;
        for j in 0..epp {
            hash_node(entries, child_base + j, ctx);
        }
    }
}

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
    (crate::arch::x86::read_cr3() & !(PAGE_SIZE as u32 - 1)) as u64
}

/// Get current process's virtual root physical address.
/// For legacy/compat: same as CR3.
/// For PAE: read from recursive entry (CR3 points to thread's pdpt, not virtual root).
pub fn current_root_phys() -> u64 {
    if cpu_mode() != CpuMode::Pae {
        return crate::arch::x86::read_cr3() as u64;
    }
    // The virtual root's recursive entry points to itself
    let recursive_slot = recursive_idx() - root_base();
    match entries() {
        Entries::E64(e) => e[root_base() + recursive_slot].page() * PAGE_SIZE as u64,
        Entries::E32(_) => unreachable!(),
    }
}

/// Raw TLB invalidation (CR3 reload). Used internally by paging operations
/// that don't need the PAE PDPT sync.
fn invalidate_tlb() {
    crate::arch::x86::flush_tlb();
}

/// Flush TLB. In PAE mode, also syncs the hardware PDPT
/// before reloading CR3.
pub fn flush_tlb() {
    sync_hw_pdpt();
    crate::arch::x86::flush_tlb();
}

/// Remove identity mapping (call after switching to virtual addresses)
///
/// Clears the first root entry (PD[0] for legacy, PDPT[0] for PAE)
fn remove_identity_mapping<E: Entry>(entries: &mut [E]) {
    entries[root_base()] = E::default();
    invalidate_tlb();
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
            let lm = cpu_supports_long_mode();
            if lm {
                crate::println!("CPU supports Long Mode (64-bit)");

                // Before removing id map copy the compat <-> legacy protmode
                // to identity mapped page
                copy_trampoline();

                // Set up long mode page tables
                setup_long_mode_tables();
                crate::println!("Long mode tables set up");
            }

            remove_identity_mapping(e);
            crate::println!("Identity mapping removed");

            enable_nx();
            if nx_enabled() {
                crate::println!("NX (No-Execute) protection enabled");
            }

            harden_kernel(e);
            invalidate_tlb();
        }
    }
}

/// Check if CPU supports PAE (CPUID.1:EDX bit 6)
pub fn cpu_supports_pae() -> bool {
    let (_, _, _, edx) = crate::arch::x86::cpuid(1);
    edx & (1 << 6) != 0
}

/// Check if CPU supports long mode (CPUID.80000001:EDX bit 29)
pub fn cpu_supports_long_mode() -> bool {
    let (max_ext, _, _, _) = crate::arch::x86::cpuid(0x80000000);
    if max_ext < 0x80000001 { return false; }
    let (_, _, _, edx) = crate::arch::x86::cpuid(0x80000001);
    edx & (1 << 29) != 0
}

/// Check if CPU supports NX/XD bit (CPUID.80000001:EDX bit 20)
pub fn cpu_supports_nx() -> bool {
    let (max_ext, _, _, _) = crate::arch::x86::cpuid(0x80000000);
    if max_ext < 0x80000001 { return false; }
    let (_, _, _, edx) = crate::arch::x86::cpuid(0x80000001);
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
        let efer = crate::arch::x86::rdmsr(crate::arch::x86::EFER_MSR);
        crate::arch::x86::wrmsr(crate::arch::x86::EFER_MSR, efer | crate::arch::x86::efer::NXE);
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
        let mut e = Entry32::new(i as u64, true, false);
        // VGA framebuffer (0xA0-0xBF) must be uncacheable
        if i >= 0xA0 && i < 0xC0 {
            e.set_raw(e.raw() | flags::CACHE_DISABLE);
        }
        kpages.pt_kernel[512 + i] = e;
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
        crate::arch::x86::write_cr3(kpages.pd.phys_addr() as u32);
        let cr0 = crate::arch::x86::read_cr0();
        crate::arch::x86::write_cr0(cr0 | crate::arch::x86::cr0::PG | crate::arch::x86::cr0::WP);
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
    // Identity map using scratch as PD: scratch[0] = scratch (self-ref PT for 0-2MB),
    // scratch[1] = pt_pml4 (PT for 2-4MB, temporarily borrowed)
    scratch[0] = Entry64::new(scratch.phys_page(), true, false);
    scratch[1] = Entry64::new(kpages.pt_pml4.phys_page(), true, false);
    for i in 2..512 {
        scratch[i] = Entry64::new(i as u64, true, false);
    }
    // pt_pml4 temporarily serves as identity PT for 2-4MB
    for i in 0..512 {
        kpages.pt_pml4[i] = Entry64::new((512 + i) as u64, true, false);
    }
    // Note: page 0xF is preserved in remove_identity_mapping() for mode switching trampoline

    // Map low memory (first 1MB) at LOW_MEM_BASE (0xC0A00000)
    // PT index 0-255 maps physical 0x00000000-0x000FFFFF
    for i in 0..256 {
        let mut e = Entry64::new(i as u64, true, false);
        if i >= 0xA0 && i < 0xC0 {
            e.set_raw(e.raw() | flags::CACHE_DISABLE);
        }
        kpages.pt_kernel[i] = e;
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
    let cr4 = crate::arch::x86::read_cr4();
    unsafe {
        crate::arch::x86::write_cr4(cr4 | crate::arch::x86::cr4::PAE);
        crate::arch::x86::write_cr3(kpages.pdpt.phys_addr() as u32);
        let cr0 = crate::arch::x86::read_cr0();
        crate::arch::x86::write_cr0(cr0 | crate::arch::x86::cr0::PG | crate::arch::x86::cr0::WP);
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

/// Pointer to the page table page that controls the temp mapping
static mut TEMP_MAP_PT: *mut RawPage = core::ptr::null_mut();

/// Entry index within TEMP_MAP_PT
static mut TEMP_MAP_ENTRY: usize = 0;

/// Temp mapping virtual address (set by init_temp_map)
static mut TEMP_MAP_VADDR_MUT: usize = 0;

pub fn temp_map_vaddr() -> usize {
    unsafe { TEMP_MAP_VADDR_MUT }
}

/// Initialize temp mapping (call after paging enabled, before fork)
///
/// Uses the last entry of pt_kernel in both modes.
/// Legacy: pt_kernel = pages[1], 1024 entries, last entry VA = 0xC0BFF000
/// PAE:    pt_kernel = pages[2],  512 entries, last entry VA = 0xC0BFF000
pub fn init_temp_map() {
    unsafe {
        if is_pae() {
            TEMP_MAP_PT = &raw mut crate::KERNEL_PAGES.pages[2];
            TEMP_MAP_ENTRY = entries_per_page::<Entry64>() - 1;
        } else {
            TEMP_MAP_PT = &raw mut crate::KERNEL_PAGES.pages[1];
            TEMP_MAP_ENTRY = entries_per_page::<Entry32>() - 1;
        }
        TEMP_MAP_VADDR_MUT = 0xC0BFF000;
    }
}

/// Map a physical page at the temp mapping address
pub fn temp_map(phys_page: u64) {
    unsafe {
        let idx = TEMP_MAP_ENTRY;
        if is_pae() {
            let pt = TEMP_MAP_PT as *mut Entry64;
            *pt.add(idx) = Entry64::new(phys_page, true, false);
        } else {
            let pt = TEMP_MAP_PT as *mut Entry32;
            *pt.add(idx) = Entry32::new(phys_page, true, false);
        }
    }
    invalidate_tlb();
}

/// Unmap the temp mapping
pub fn temp_unmap() {
    unsafe {
        let idx = TEMP_MAP_ENTRY;
        if is_pae() {
            let pt = TEMP_MAP_PT as *mut Entry64;
            *pt.add(idx) = Entry64::default();
        } else {
            let pt = TEMP_MAP_PT as *mut Entry32;
            *pt.add(idx) = Entry32::default();
        }
    }
    invalidate_tlb();
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
/// share_and_copy's the root page table. All child page tables are shared
/// read-only. Returns the new root's physical page number.
pub fn fork_current() -> Option<u64> {
    match entries() {
        Entries::E32(e) => fork_generic(e),
        Entries::E64(e) => fork_generic(e),
    }
}

/// Fork the current address space (COW).
///
/// All modes: share_and_copy the root (PD for legacy, PDPT for PAE/compat).
/// Self-referential entries are auto-patched by share_and_copy.
/// PAE only: deshare user entries [0..recursive) because PAE hardware
/// ignores R/W on PDPT entries.
///
/// Returns the new root's physical page number.
fn fork_generic<E: Entry>(entries: &mut [E]) -> Option<u64> {
    let new_root = share_and_copy(entries, recursive_idx())?;

    // Deshare user root entries in PAE mode (PDPT[0..2]).
    // PAE hardware ignores R/W on PDPT entries, so COW can't be enforced
    // at that level — eagerly COW to push enforcement to PD level.
    // Compat mode doesn't need this: PDPT entries are ordinary page table
    // entries with full R/W enforcement, so cascading COW works naturally.
    if cpu_mode() == CpuMode::Pae {
        let root = root_base();
        let user_count = recursive_idx() - root;
        for i in 0..user_count {
            if entries[root + i].present() && !entries[root + i].hw_writable() {
                cow_entry(entries, root + i);
            }
        }
    }

    flush_tlb();
    Some(new_root)
}

// =============================================================================
// COW fault handling
// =============================================================================

/// Copy a page table page and mark children as shared R/O in both copies.
/// All writes go through temp_map to avoid faulting on the self-mapped entries.
/// Returns the new page's physical page number.
fn share_and_copy<E: Entry>(entries: &mut [E], idx: usize) -> Option<u64> {
    use crate::arch::phys_mm;

    debug_assert!(idx >= PAGE_TABLE_BASE_IDX,
        "share_and_copy: idx {} is a leaf page, not a page table entry", idx);

    let epp = entries_per_page::<E>();
    let child_base = (idx - PAGE_TABLE_BASE_IDX) * epp;

    debug_assert!(child_base + epp <= NUM_PAGES,
        "share_and_copy: idx {:#x} children {:#x}..{:#x} > NUM_PAGES {:#x}",
        idx, child_base, child_base + epp, NUM_PAGES);

    // Get physical page of the parent page table (the one that entries[child_base..] maps)
    let parent_phys = entries[idx].page();

    // Allocate new page for child copy
    let new_phys = phys_mm::alloc_phys_page()?;

    // For the root page table, only mark user entries R/O (below recursive entry).
    // Kernel entries stay writable — shared between all processes.
    // For non-root page tables, all entries are user.
    let user_count = if idx == recursive_idx() {
        recursive_idx() - child_base
    } else {
        epp
    };

    // Copy parent -> child via temp_map, marking user entries R/O.
    // Self-referential entries (e.g. PDPT[3] recursive) are patched
    // to point to the new copy.
    temp_map(new_phys);
    unsafe {
        let dst = temp_map_vaddr() as *mut E;
        for i in 0..epp {
            let mut e = entries[child_base + i];
            if e.present() {
                if i < user_count {
                    e.set_hw_writable(false);
                }
                if e.page() == parent_phys {
                    // Self-referential → point to new copy
                    e = E::new(new_phys, true, false);
                }
            }
            *dst.add(i) = e;
        }
    }
    temp_unmap();

    // Mark parent user entries R/O and inc ref counts via temp_map
    temp_map(parent_phys);
    unsafe {
        let src = temp_map_vaddr() as *mut E;
        for i in 0..user_count {
            let e = &mut *src.add(i);
            if e.present() {
                e.set_hw_writable(false);
                phys_mm::inc_shared_count(e.page());
            }
        }
    }
    temp_unmap();

    invalidate_tlb();
    Some(new_phys)
}

/// COW a single entry (leaf data page or page table).
///
/// If sole owner, just sets hw_writable. Otherwise allocates a new page,
/// copies the old contents, and updates the entry. For page table entries,
/// also marks children R/O and increments their ref counts.
pub fn cow_entry<E: Entry>(entries: &mut [E], idx: usize) {
    use crate::arch::phys_mm;

    debug_assert!(idx != recursive_idx(),
        "cow_entry: idx {} is the recursive entry, must never be COW'd", idx);

    let old_phys = entries[idx].page();
    let ref_count = phys_mm::get_ref_count(old_phys);

    if ref_count == 1 {
        // Sole owner — just make writable
        entries[idx].set_hw_writable(true);
        invalidate_tlb();
        return;
    }

    let epp = entries_per_page::<E>();
    let new_phys = if idx >= PAGE_TABLE_BASE_IDX {
        let child_base = (idx - PAGE_TABLE_BASE_IDX) * epp;
        debug_assert!(child_base + epp <= NUM_PAGES,
            "cow_entry: idx {:#x} is not a non-leaf recursive entry", idx);
        share_and_copy(entries, idx).expect("Out of memory during COW")
    } else {
        // Leaf: copy old page content into a new physical page.
        let p = phys_mm::alloc_phys_page().expect("Out of memory during COW");
        if idx == 0 {
            // Page 0: can't read from VA 0 (null ptr). Copy via temp_map.
            let mut buf = alloc::vec![0u8; PAGE_SIZE];
            temp_map(old_phys);
            unsafe { core::ptr::copy_nonoverlapping(
                temp_map_vaddr() as *const u8, buf.as_mut_ptr(), PAGE_SIZE); }
            temp_map(p);
            unsafe { core::ptr::copy_nonoverlapping(
                buf.as_ptr(), temp_map_vaddr() as *mut u8, PAGE_SIZE); }
            temp_unmap();
        } else {
            // Other pages: read directly from user VA
            temp_map(p);
            unsafe {
                let src = (idx * PAGE_SIZE) as *const u8;
                core::ptr::copy_nonoverlapping(src, temp_map_vaddr() as *mut u8, PAGE_SIZE);
            }
            temp_unmap();
        }
        p
    };

    let user = entries[idx].user();
    entries[idx] = E::new(new_phys, true, user);
    phys_mm::free_phys_page(old_phys);
    invalidate_tlb();
}

// =============================================================================
// Free user pages
// =============================================================================

/// Generic free: walk user root entries, recursively free subtrees.
fn free_generic<E: Entry>(entries: &mut [E]) {
    let root = root_base();
    let user_count = recursive_idx() - root;

    for i in 0..user_count {
        if entries[root + i].present() {
            free_subtree(entries, root + i);
        }
    }
    invalidate_tlb();
}

/// Free all user pages in current address space.
///
/// Recursively walks from root user entries down to leaf pages.
/// Shared subtrees (ref count > 1) are freed with a single dec-ref.
/// Sole-owned subtrees are walked and freed page by page.
/// Free all user-space pages and page tables.
pub fn free_user_pages() {
    match entries() {
        Entries::E32(e) => free_generic(e),
        Entries::E64(e) => free_generic(e),
    }
}

/// Recursively free a page table subtree rooted at `parent_idx`.
///
/// If the page at parent_idx is shared (ref > 1), just dec-ref.
/// If sole-owned, walk children: recurse for intermediate levels,
/// free directly for leaf pages.
fn free_subtree<E: Entry>(entries: &mut [E], parent_idx: usize) {
    use crate::arch::phys_mm;

    if !entries[parent_idx].present() {
        return;
    }

    let epp = entries_per_page::<E>();
    let phys = entries[parent_idx].page();
    let ref_count = phys_mm::get_ref_count(phys);

    if ref_count == 1 {
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

/// Map the trampoline page (VA 0xF000) identity-mapped for a mode toggle.
/// Returns the saved PTE to pass to `clear_trampoline()`.
pub fn ensure_trampoline_mapped() -> u64 {
    if let Entries::E64(e) = entries() {
        let saved = e[TRAMPOLINE_PAGE].0;
        e[TRAMPOLINE_PAGE] = Entry64::new(TRAMPOLINE_PAGE as u64, true, false);
        crate::arch::x86::invlpg(TRAMPOLINE_ADDR);
        saved
    } else {
        0
    }
}

/// Restore the trampoline page's PTE after a mode toggle.
pub fn clear_trampoline(saved: u64) {
    match entries() {
        Entries::E32(e) => {
            e[TRAMPOLINE_PAGE] = Entry32(saved as u32);
        }
        Entries::E64(e) => {
            e[TRAMPOLINE_PAGE] = Entry64(saved);
        }
    }
    crate::arch::x86::invlpg(TRAMPOLINE_ADDR);
}

/// Map the first 1MB of physical memory as user-accessible (for VM86 mode).
/// Page 0 gets a private COW copy; pages 1-0x9F are demand-paged zero;
/// 0xA0-0xBF VGA framebuffer; 0xC0-0xFF ROM (read-only).
pub fn map_low_mem_user() {
    match entries() {
        Entries::E32(e) => map_low_mem_user_generic(e),
        Entries::E64(e) => map_low_mem_user_generic(e),
    }
}

fn map_low_mem_user_generic<E: Entry>(entries: &mut [E]) {
    // Page 0 (BIOS IVT + BDA): allocate a private copy so each VM86 process
    // has its own IVT. Copy via temp mapping to avoid null pointer issues.
    let page0_copy = crate::arch::phys_mm::alloc_phys_page().expect("alloc page 0 copy");
    temp_map(0); // map physical page 0 at temp VA
    let mut buf = [0u8; PAGE_SIZE];
    unsafe {
        core::ptr::copy_nonoverlapping(
            temp_map_vaddr() as *const u8,
            buf.as_mut_ptr(),
            PAGE_SIZE,
        );
    }
    temp_map(page0_copy); // map fresh page at temp VA
    unsafe {
        core::ptr::copy_nonoverlapping(
            buf.as_ptr(),
            temp_map_vaddr() as *mut u8,
            PAGE_SIZE,
        );
    }
    temp_unmap();
    entries[0] = E::new(page0_copy, true, true);

    // Pages 1-0x9F: conventional memory — left unmapped (demand-paged zero)
    // Each process gets private zeroed pages on first access.

    // Pages 0xA0-0xBF: VGA framebuffer — identity mapped RW, cache disabled
    // PCD (bit 4) must be set so the CPU doesn't cache/combine writes.
    // VGA Odd/Even addressing relies on seeing individual byte accesses.
    for i in 0xA0..0xC0usize {
        let mut e = E::new(i as u64, true, true);
        e.set_raw(e.raw() | flags::CACHE_DISABLE);
        entries[i] = e;
    }

    // Pages 0xC0-0xFF: ROM/BIOS area — identity mapped RO by default.
    // UMB and EMS pages are cleared to not-present later by scan_uma().
    for i in 0xC0..0x100usize {
        entries[i] = E::new(i as u64, false, true);
    }

    // A20 disabled by default: map pages 0x100-0x10F → physical 0x000-0x00F
    // (wrap-around aliasing of first 64KB at the 1MB boundary)
    for i in 0..16usize {
        let e = E::new(i as u64, true, true);
        entries[0x100 + i] = e;
    }

    flush_tlb();
}

/// Map a physical page into the user address space.
pub fn map_user_page_phys(vpage: usize, ppage: u64, extra_flags: u64) {
    match entries() {
        Entries::E32(e) => {
            let mut entry = Entry32::new(ppage, true, true);
            entry.set_raw(entry.raw() | extra_flags);
            e[vpage] = entry;
        }
        Entries::E64(e) => {
            let mut entry = Entry64::new(ppage, true, true);
            entry.set_raw(entry.raw() | extra_flags);
            e[vpage] = entry;
        }
    }
    flush_tlb();
}

/// Allocate a physical page, fill it with `data` (zero-padded to PAGE_SIZE),
/// and map it at user virtual page `page_idx` (writable, user-accessible).
pub fn map_user_page(page_idx: usize, data: &[u8]) {
    assert!(data.len() <= PAGE_SIZE);
    let phys = crate::arch::phys_mm::alloc_phys_page().expect("alloc user page");
    temp_map(phys);
    unsafe {
        let dst = temp_map_vaddr() as *mut u8;
        core::ptr::write_bytes(dst, 0, PAGE_SIZE);
        core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
    }
    temp_unmap();
    match entries() {
        Entries::E32(e) => { e[page_idx] = Entry32::new(phys, true, true); }
        Entries::E64(e) => { e[page_idx] = Entry64::new(phys, true, true); }
    }
    flush_tlb();
}

/// Set A20 gate state for VM86 mode.
/// When disabled (default): virtual 0x100000-0x10FFFF → physical 0x00000-0x0FFFF (wrap)
/// When enabled: virtual 0x100000-0x10FFFF → the thread's saved HMA mappings.
pub fn set_a20(enabled: bool, hma: &mut [Entry64; crate::vm86::HMA_PAGE_COUNT]) {
    match entries() {
        Entries::E32(e) => set_a20_generic_32(e, enabled, hma),
        Entries::E64(e) => set_a20_generic_64(e, enabled, hma),
    }
}

fn set_a20_generic_64(entries: &mut [Entry64], enabled: bool, hma: &mut [Entry64; crate::vm86::HMA_PAGE_COUNT]) {
    for i in 0..16usize {
        let idx = 0x100 + i;
        if enabled {
            entries[idx] = hma[i];
        } else {
            hma[i] = entries[idx];
            entries[idx] = Entry64::new(i as u64, true, true);
        }
    }
    flush_tlb();
}

fn set_a20_generic_32(entries: &mut [Entry32], enabled: bool, hma: &mut [Entry64; crate::vm86::HMA_PAGE_COUNT]) {
    for i in 0..16usize {
        let idx = 0x100 + i;
        if enabled {
            let saved = hma[i];
            let mut e = Entry32::new(saved.page(), saved.hw_writable(), saved.user());
            e.set_writable(saved.writable());
            entries[idx] = e;
        } else {
            let mut saved = Entry64::new(entries[idx].page(), entries[idx].hw_writable(), entries[idx].user());
            saved.set_writable(entries[idx].writable());
            hma[i] = saved;
            entries[idx] = Entry32::new(i as u64, true, true);
        }
    }
    flush_tlb();
}

/// Map an EMS page frame window (0-3) to the given 4 physical pages.
/// `base_page` is the EMS page frame start (from scan_uma).
/// Window N maps to virtual pages base_page + N*4 .. base_page + N*4 + 3.
/// Pass phys_pages = None to unmap the window.
pub fn map_ems_window(base_page: usize, window: usize, phys_pages: Option<&[u64; 4]>) {
    assert!(window < 4);
    let base = base_page + window * 4;
    match entries() {
        Entries::E32(e) => map_ems_window_generic(e, base, phys_pages),
        Entries::E64(e) => map_ems_window_generic(e, base, phys_pages),
    }
    flush_tlb();
}

fn map_ems_window_generic<E: Entry>(entries: &mut [E], base: usize, phys_pages: Option<&[u64; 4]>) {
    match phys_pages {
        Some(pages) => {
            for i in 0..4 {
                entries[base + i] = E::new(pages[i], true, true);
            }
        }
        None => {
            for i in 0..4 {
                entries[base + i] = E::default();
            }
        }
    }
}

/// Enable UMB region: clear RO identity mapping so demand paging provides RAM on first access.
pub fn map_umb(base_page: usize, num_pages: usize) {
    match entries() {
        Entries::E32(e) => { for i in 0..num_pages { e[base_page + i] = Entry32::default(); } }
        Entries::E64(e) => { for i in 0..num_pages { e[base_page + i] = Entry64::default(); } }
    }
    flush_tlb();
}

/// Disable UMB region: free physical pages and restore RO identity mapping.
pub fn unmap_umb(base_page: usize, num_pages: usize) {
    match entries() {
        Entries::E32(e) => {
            for i in 0..num_pages {
                if e[base_page + i].present() {
                    crate::arch::phys_mm::free_phys_page(e[base_page + i].addr() >> 12);
                }
                e[base_page + i] = Entry32::new((base_page + i) as u64, false, true);
            }
        }
        Entries::E64(e) => {
            for i in 0..num_pages {
                if e[base_page + i].present() {
                    crate::arch::phys_mm::free_phys_page(e[base_page + i].addr() >> 12);
                }
                e[base_page + i] = Entry64::new((base_page + i) as u64, false, true);
            }
        }
    }
    flush_tlb();
}

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
        entries[i].set_writable(false);
    }

    // .rodata: read-only, non-executable
    for i in text_end_page..rodata_end_page {
        entries[i].set_hw_writable(false);
        entries[i].set_writable(false);
        entries[i].set_no_execute(true);
    }

    // .data/.bss: read-write, non-executable
    for i in data_start_page..data_end_page {
        entries[i].set_no_execute(true);
    }

    invalidate_tlb();
    crate::println!("Kernel hardening complete");
}
