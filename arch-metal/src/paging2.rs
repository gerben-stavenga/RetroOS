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
//! - Fork: share_and_copy(PD). Done.
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
//! - Fork: share_and_copy(PDPT). Shares PDPT[0..2] (user PDs). Done.
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
//! PAE deshares [0..2].

use core::ops::{Index, IndexMut};

// PAGE_SIZE, LOW_MEM_BASE, and the RawPage blob are part of the
// backend-agnostic contract (`arch-abi`); re-exported so `crate::{
// PAGE_SIZE, LOW_MEM_BASE, RawPage}` keep resolving.
pub use arch_abi::{PAGE_SIZE, RawPage};

/// Recursive mapping base - page tables accessible here (PDPT[0-3], 8MB)
pub const PAGE_TABLE_BASE: usize = 0xC000_0000;

/// Page index where page tables start (PAGE_TABLE_BASE / PAGE_SIZE)
pub const PAGE_TABLE_BASE_IDX: usize = PAGE_TABLE_BASE / PAGE_SIZE;

/// Low memory (first 1MB) mapped here for VGA, BIOS, etc. (PDPT[5] first half)
pub use arch_abi::LOW_MEM_BASE;

/// Kernel space starts here (PDPT[5+], after low memory)
pub const KERNEL_BASE: usize = 0xC0B0_0000;

/// Kernel physical load address (must match KERNEL_PHYS in `kernel.ld`).
pub const KERNEL_PHYS: usize = 0x0010_0000;

/// The kernel heap occupies `[heap_base() .. HEAP_END)` in kernel space. The
/// demand-paging `#PF` handler grows it on access and the heap allocator carves
/// within it — but the window itself is a memory-layout fact (the ceiling, and
/// the base = first page past the kernel image's linker `_end`), owned here, not
/// allocator policy.
pub const HEAP_END: usize = FB_WINDOW_BASE;

/// VA window for the boot-handoff linear framebuffer on UEFI-class machines
/// (GOP — no VGA text mode). The kernel framebuffer console maps the
/// multiboot-reported framebuffer here, cache-disabled. 63 MB covers any
/// plausible mode (4K×32bpp ≈ 33 MB). Carved off the top of the heap window.
pub const FB_WINDOW_BASE: usize = 0xFC00_0000;
pub const FB_WINDOW_END: usize = 0xFFF0_0000;

/// First page after the kernel image (`_end`), aligned up — the heap base.
pub fn heap_base() -> usize {
    unsafe extern "C" {
        static _end: u8;
    }
    let end = (&raw const _end) as usize;
    (end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

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

impl Default for RootPageTable {
    fn default() -> Self { RootPageTable::empty() }
}

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

    /// Swap user entries between self and the constant root page, then reload CR3.
    /// On return, self holds the old root entries and the constant root has self's former entries.
    pub fn swap_and_activate(&mut self) {
        match cpu_mode() {
            CpuMode::Legacy => {
                if let Entries::E32(e) = entries() {
                    let root = root_base();
                    let user_count = recursive_idx() - root;
                    for i in 0..user_count {
                        unsafe { core::mem::swap(&mut self.e32[i], &mut e[root + i]); }
                    }
                }
            }
            CpuMode::Pae | CpuMode::Compat => {
                if let Entries::E64(e) = entries() {
                    let root = root_base();
                    let user_count = recursive_idx() - root;
                    // Save PML4 phys from live root before swapping
                    let pml4_page = e[root + 4].page();
                    for i in 0..user_count {
                        unsafe { core::mem::swap(&mut self.e64[i], &mut e[root + i]); }
                    }
                    // self.e64[3] now has PML4 phys from before swap; update to live root's
                    unsafe { self.e64[3] = Entry64(pml4_page * PAGE_SIZE as u64); }
                }
            }
        }
        if cpu_mode() == CpuMode::Pae {
            sync_hw_pdpt();
        }
        unsafe { crate::x86::write_cr3(self.cr3() as u32); }
    }

    /// Load user entries into constant root and reload CR3.
    /// Use when no mode toggle is needed.
    pub fn activate(&self) {
        self.load_entries();
        if cpu_mode() == CpuMode::Pae {
            sync_hw_pdpt();
        }
        unsafe { crate::x86::write_cr3(self.cr3() as u32); }
    }

    /// CR3 value for this address space.
    /// - Legacy: constant PD phys
    /// - PAE: constant hardware PDPT phys
    /// - Compat: PML4 phys from e64[3] (saved from PDPT[4] back-pointer)
    pub fn cr3(&self) -> u64 {
        match cpu_mode() {
            CpuMode::Legacy => current_root_phys(),
            CpuMode::Pae => {
                let vaddr = (&raw const HW_PDPT) as usize;
                let page = physical_page(vaddr);
                page * PAGE_SIZE as u64 + (vaddr % PAGE_SIZE) as u64
            },
            CpuMode::Compat => unsafe { self.e64[3].0 & !(PAGE_SIZE as u64 - 1) },
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
    #[allow(dead_code)] pub const ACCESSED: u64 = 1 << 5;
    #[allow(dead_code)] pub const DIRTY: u64 = 1 << 6;
    #[allow(dead_code)] pub const PAGE_SIZE_BIT: u64 = 1 << 7;
    /// Leaf-PTE PAT bit (bit 7 in a 4 KB PTE — same bit as PAGE_SIZE_BIT, which
    /// only means "large page" in a PDE/PDPTE). With PWT/PCD clear it selects
    /// PAT entry 4, which `enable_wc_pat` programs to Write-Combining. Set on the
    /// framebuffer so linear blits burst instead of going out as per-pixel UC
    /// transactions. Only valid on a 4 KB leaf entry.
    pub const WRITE_COMBINE: u64 = 1 << 7;
    /// Software flag: this frame is NOT owned by the address space mapping it —
    /// never free it on unmap/teardown, never copy-on-write it on fork.
    ///
    /// That ownership question used to be answered by `CACHE_DISABLE`, on the
    /// reasoning that externally-owned frames are MMIO. They mostly are, but not
    /// always: the shared VGA text aperture is ordinary RAM shared by the kernel
    /// console and every DOS process, and marking it uncached purely to protect
    /// it cost a full memory transaction per byte (and disabled fast-string, so
    /// a 4 KB scanout read measured ~2M cycles on real hardware). Splitting the
    /// two lets a frame be cacheable AND externally owned.
    /// Bit 11, not 10: `arch_abi::MAP_MMIO` is `1 << 10` and is passed through
    /// the same `extra_flags` argument, so a FOREIGN mapping on bit 10 took the
    /// MMIO branch and mapped the page NOT PRESENT — the console's first write
    /// then faulted.
    pub const FOREIGN: u64 = 1 << 11;
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

    #[allow(dead_code)]
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

impl Index<usize> for PageTable32 {
    type Output = Entry32;
    fn index(&self, idx: usize) -> &Entry32 { 
        unsafe { &core::mem::transmute::<&PageTable32, &[Entry32; 1024]>(self)[idx] }
    }
}

impl IndexMut<usize> for PageTable32 {
    fn index_mut(&mut self, idx: usize) -> &mut Entry32 { 
        unsafe { &mut core::mem::transmute::<&mut PageTable32, &mut [Entry32; 1024]>(self)[idx] }
    }
}

/// PAE mode page table: 512 x 64-bit entries = 4KB
#[derive(Clone)]
#[repr(transparent)]
pub struct PageTable64(pub RawPage);

impl Index<usize> for PageTable64 {
    type Output = Entry64;
    fn index(&self, idx: usize) -> &Entry64 { 
        unsafe { &core::mem::transmute::<&PageTable64, &[Entry64; 512]>(self)[idx] }
    }
}

impl IndexMut<usize> for PageTable64 {
    fn index_mut(&mut self, idx: usize) -> &mut Entry64 { 
        unsafe { &mut core::mem::transmute::<&mut PageTable64, &mut [Entry64; 512]>(self)[idx] }
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
    /// Kernel overflow page table (PD[771], 0xC0C00000-0xC0FFFFFF): the
    /// kernel image past its first 1 MB (the embedded bootfs makes it ~2 MB).
    pub pt_kernel2: PageTable32,
}

/// PAE mode kernel page tables (5 pages = 20KB)
///
/// With PDPT[3] = PDPT (recursive), the PDPT acts as a 512-entry "virtual PD"
/// for addresses 0xC0000000-0xFFFFFFFF. PDPT[4-511] become kernel PD entries.
/// Identity mapping uses SCRATCH page as both PD and PT (temporary, removed after boot)
/// Assumes kernel < 5MB (same as legacy mode)
#[derive(Clone)]
#[repr(C)]
pub struct PaePages {
    /// PDPT - also acts as "virtual PD" via PDPT[3] recursion
    /// PDPT[0] = scratch (identity), PDPT[3] = PDPT, PDPT[4] = pt_pml4,
    /// PDPT[5] = pt_kernel, PDPT[6] = pt_kernel2, PDPT[7] = pt_kernel3
    pub pdpt: PageTable64,
    /// Page table for PML4 region (PDPT[4], covers 0xC0800000-0xC09FFFFF)
    pub pt_pml4: PageTable64,
    /// Page table for low mem + kernel (PDPT[5], 0xC0A00000-0xC0BFFFFF)
    pub pt_kernel: PageTable64,
    /// Kernel overflow page tables (PDPT[6]/[7], 0xC0C00000-0xC0FFFFFF): the
    /// kernel image past its first 1 MB (the embedded bootfs makes it ~2 MB).
    pub pt_kernel2: PageTable64,
    pub pt_kernel3: PageTable64,
}

/// Kernel page tables (5 pages for PAE, 3 for legacy)
#[allow(dead_code)]
pub struct KernelPages([RawPage; 5]);

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

/// Kernel pages - statically allocated page tables
static mut KERNEL_PAGES: KernelPages = KernelPages([const { RawPage([0; PAGE_SIZE]) }; 5]);

/// PML4 for long mode - shared with PAE via PML4[0] = PDPT
static mut PML4: PageTable64 = PageTable64(RawPage([0; PAGE_SIZE]));

/// Set up long mode page tables (call after enable_pae)
/// Sets PML4[0] = PDPT so long mode uses same address space.
/// Note: vroot[4] (pt_pml4) is NOT overwritten — the PML4 page must not
/// double as a page table, otherwise demand paging writes PTEs into it
/// and corrupts PML4 entries.
pub fn setup_long_mode_tables() {
    // PAE CR3 points at the compact 32-byte hardware PDPT, while long mode
    // needs the full page-sized virtual root (including recursive entries).
    let pdpt_phys = current_root_phys();
    let pml4_phys = physical_page((&raw const PML4) as usize);

    // PML4[0] = PDPT (so long mode uses same mappings)
    unsafe { PML4[0] = Entry64::new(pdpt_phys >> 12, true, true); }

    // PDPT[4] = PML4 (back-pointer so PML4 is visible in recursive mapping)
    if let Entries::E64(e) = entries() {
        e[root_base() + 4] = Entry64::new(pml4_phys, true, false);
    }
}

/// Get the root CR3 value (constant PD/PML4 phys).
/// For legacy: PD phys. For PAE: HW_PDPT phys. For compat: PML4 phys.
#[allow(dead_code)]
pub fn root_cr3() -> u64 {
    match cpu_mode() {
        CpuMode::Legacy => current_root_phys(),
        CpuMode::Pae => {
            let vaddr = (&raw const HW_PDPT) as usize;
            let page = physical_page(vaddr);
            page * PAGE_SIZE as u64 + (vaddr % PAGE_SIZE) as u64
        },
        CpuMode::Compat => {
            let pml4_phys = physical_page((&raw const PML4) as usize);
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
        let pml4_phys = physical_page((&raw const PML4) as usize);
        (pml4_phys * PAGE_SIZE as u64) as u32
    } else {
        // Target is PAE → CR3 = HW_PDPT phys
        let vaddr = (&raw const HW_PDPT) as usize;
        let page = physical_page(vaddr);
        (page * PAGE_SIZE as u64 + (vaddr % PAGE_SIZE) as u64) as u32
    }
}

/// Copy constant PDPT[0..4] to the hardware PDPT (PAE only).
/// Sanitizes every bit that is reserved in a 32-bit PAE PDPTE. The virtual
/// root entries are also traversed as PDEs through the recursive mapping, so
/// hardware may set Accessed there; copying the raw entry makes a subsequent
/// MOV CR3 fail its PDPTR check on strict implementations.
fn hardware_pdpte(entry: Entry64) -> u64 {
    let mut mask = Entry64::ADDR_MASK
        | flags::PRESENT
        | flags::WRITE_THROUGH
        | flags::CACHE_DISABLE;
    if nx_enabled() {
        mask |= flags::NO_EXECUTE;
    }
    entry.0 & mask
}

pub fn sync_hw_pdpt() {
    if cpu_mode() == CpuMode::Legacy { return; }

    if let Entries::E64(e) = entries() {
        let root = root_base();
        for i in 0..4 {
            unsafe { HW_PDPT.0[i] = hardware_pdpte(e[root + i]); }
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
    if crate::x86::read_cr4() & crate::x86::cr4::PAE == 0 {
        CpuMode::Legacy
    } else if !cpu_supports_long_mode() || crate::x86::rdmsr(crate::x86::EFER_MSR) & crate::x86::efer::LME == 0 {
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

/// Cached `is_pae()` result. `cpu_mode()` reads CR4 + EFER (ring-0-only),
/// so any caller outside the arch syscall handlers (e.g. ring-1 kernel
/// code calling `entries()`) would #GP. The mode is fixed once
/// `enable_paging` returns; cache it there and read from this static.
static IS_PAE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Check if using 64-bit entries (PAE or compat). Reads the cache set by
/// `enable_pae` — safe from any ring.
#[inline]
pub fn is_pae() -> bool {
    IS_PAE.load(core::sync::atomic::Ordering::Relaxed)
}

// =============================================================================
// Address space tree snapshot (for corruption detection)
// =============================================================================

/// Stable entry bits: canonical page ID in low 48 bits, stable flags in upper bits.
/// Excludes READ_WRITE (COW-flippable) and ACCESSED/DIRTY (hw-updated).
const STABLE_MASK: u64 = flags::PRESENT | flags::SOFT_RO | flags::WRITE_THROUGH
    | flags::CACHE_DISABLE | flags::USER | flags::NO_EXECUTE;

/// Recursive page table tree node.
/// `bits` = canonical page ID | (stable flags << 48).
#[derive(Clone, Hash, PartialEq, Eq)]
pub enum Node {
    Leaf { bits: u64, data_hash: u64 },
    Internal { bits: u64, children: alloc::vec::Vec<(u16, Node)> },
}

/// Full user address space snapshot.
#[derive(Clone, Hash, PartialEq, Eq)]
pub struct PageTree(pub alloc::vec::Vec<(u16, Node)>);

struct CollectCtx {
    phys_map: alloc::collections::BTreeMap<u64, u64>,
    next_id: u64,
}

impl CollectCtx {
    fn new() -> Self { Self { phys_map: alloc::collections::BTreeMap::new(), next_id: 0 } }

    fn canon_bits(&mut self, raw: u64) -> u64 {
        let phys = (raw >> 12) & 0xF_FFFF_FFFF;
        let id = if raw & (flags::WRITE_THROUGH | flags::CACHE_DISABLE) != 0 {
            phys  // MMIO: use real phys, not canonical
        } else {
            *self.phys_map.entry(phys).or_insert_with(|| {
                let id = self.next_id;
                self.next_id += 1;
                id
            })
        };
        id | ((raw & STABLE_MASK) << 48)
    }
}

impl PageTree {
    pub fn collect() -> Self {
        match entries() {
            Entries::E32(e) => Self::collect_walk(e),
            Entries::E64(e) => Self::collect_walk(e),
        }
    }

    fn collect_walk<E: Entry>(ents: &[E]) -> Self {
        let root = root_base();
        let user_count = recursive_idx() - root;
        let mut ctx = CollectCtx::new();
        let mut nodes = alloc::vec::Vec::new();
        for i in 0..user_count {
            if ents[root + i].present() {
                nodes.push((i as u16, Self::collect_node(ents, root + i, &mut ctx)));
            }
        }
        PageTree(nodes)
    }

    fn collect_node<E: Entry>(ents: &[E], idx: usize, ctx: &mut CollectCtx) -> Node {
        let raw = ents[idx].raw();
        let bits = ctx.canon_bits(raw);
        if idx < PAGE_TABLE_BASE_IDX {
            let dh = if raw & (flags::WRITE_THROUGH | flags::CACHE_DISABLE) == 0 {
                hash_page_data(idx * PAGE_SIZE)
            } else { 0 };
            Node::Leaf { bits, data_hash: dh }
        } else {
            let epp = entries_per_page::<E>();
            let child_base = (idx - PAGE_TABLE_BASE_IDX) * epp;
            let mut children = alloc::vec::Vec::new();
            for j in 0..epp {
                if ents[child_base + j].present() {
                    children.push((j as u16, Self::collect_node(ents, child_base + j, ctx)));
                }
            }
            Node::Internal { bits, children }
        }
    }

    /// Print diff between expected (self) and actual (other).
    pub fn diff(&self, other: &PageTree) {
        diff_children(&self.0, &other.0, 0);
    }
}

fn node_bits(n: &Node) -> u64 {
    match n { Node::Leaf { bits, .. } | Node::Internal { bits, .. } => *bits }
}

fn diff_children(a: &[(u16, Node)], b: &[(u16, Node)], depth: usize) {
    let mut ai = 0usize;
    let mut bi = 0usize;
    while ai < a.len() || bi < b.len() {
        match (a.get(ai), b.get(bi)) {
            (Some((aidx, an)), Some((bidx, bn))) if aidx == bidx => {
                if an != bn { diff_node(*aidx, an, bn, depth); }
                ai += 1; bi += 1;
            }
            (Some((aidx, an)), Some((bidx, _))) if aidx < bidx => {
                lib::println!("{:w$}- [{}] bits={:#x}", "", aidx, node_bits(an), w = depth * 2);
                ai += 1;
            }
            (_, Some((bidx, bn))) => {
                lib::println!("{:w$}+ [{}] bits={:#x}", "", bidx, node_bits(bn), w = depth * 2);
                bi += 1;
            }
            (Some((aidx, an)), None) => {
                lib::println!("{:w$}- [{}] bits={:#x}", "", aidx, node_bits(an), w = depth * 2);
                ai += 1;
            }
            (None, None) => break,
        }
    }
}

fn diff_node(idx: u16, a: &Node, b: &Node, depth: usize) {
    match (a, b) {
        (Node::Internal { bits: ab, children: ac }, Node::Internal { bits: bb, children: bc }) => {
            if ab != bb {
                lib::println!("{:w$}~ [{}] bits={:#x} -> {:#x}", "", idx, ab, bb, w = depth * 2);
            } else {
                lib::println!("{:w$}~ [{}] bits={:#x} (children changed)", "", idx, ab, w = depth * 2);
            }
            diff_children(ac, bc, depth + 1);
        }
        (Node::Leaf { bits: ab, data_hash: ah }, Node::Leaf { bits: bb, data_hash: bh }) => {
            lib::println!("{:w$}~ [{}] bits={:#x}dh={:#x} -> bits={:#x}dh={:#x}",
                "", idx, ab, ah, bb, bh, w = depth * 2);
        }
        _ => {
            lib::println!("{:w$}~ [{}] node type changed!", "", idx, w = depth * 2);
        }
    }
}

fn hash_page_data(va: usize) -> u64 {
    use core::hash::Hasher;
    let mut h = FnvHasher(0xcbf29ce484222325);
    let base = va as *const u64;
    for i in 0..(PAGE_SIZE / 8) {
        h.write_u64(unsafe { *base.add(i) });
    }
    h.finish()
}

/// FNV-1a hasher
struct FnvHasher(u64);

impl core::hash::Hasher for FnvHasher {
    fn finish(&self) -> u64 { self.0 }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }
}

fn fnv_hash(tree: &PageTree) -> u64 {
    use core::hash::{Hash, Hasher};
    let mut h = FnvHasher(0xcbf29ce484222325);
    tree.hash(&mut h);
    h.finish()
}

static mut RECORDED_TREES: Option<alloc::collections::BTreeMap<u64, PageTree>> = None;

fn recorded_trees() -> &'static mut alloc::collections::BTreeMap<u64, PageTree> {
    unsafe {
        let ptr = core::ptr::addr_of_mut!(RECORDED_TREES);
        if (*ptr).is_none() {
            *ptr = Some(alloc::collections::BTreeMap::new());
        }
        (*ptr).as_mut().unwrap()
    }
}

/// Collect tree, hash it, store snapshot. Returns the hash.
pub fn hash_and_record() -> u64 {
    let tree = PageTree::collect();
    let h = fnv_hash(&tree);
    recorded_trees().insert(h, tree);
    h
}

/// Print diff between two recorded trees.
pub fn print_recorded_diff(expected: u64, actual: u64) {
    let map = recorded_trees();
    let exp = map.get(&expected);
    let act = map.get(&actual);
    match (exp, act) {
        (Some(e), Some(a)) => e.diff(a),
        _ => lib::println!("  (trees not available for diff)"),
    }
}

/// Get page index from virtual address
#[inline]
pub const fn page_idx(vaddr: usize) -> usize {
    vaddr / PAGE_SIZE
}

/// Mark a kernel virtual page as not-present and flush its TLB entry.
/// Used to install a guard page below the kernel stack so overflow
/// page-faults instead of silently corrupting adjacent .data.
pub fn unmap_kernel_page(vaddr: usize) {
    let idx = page_idx(vaddr);
    match entries() {
        Entries::E32(e) => { e[idx] = Entry32(0); }
        Entries::E64(e) => { e[idx] = Entry64(0); }
    }
    crate::x86::invlpg(vaddr);
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
#[allow(dead_code)]
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

/// Raw TLB invalidation (CR3 reload). Used internally by paging operations
/// that don't need the PAE PDPT sync.
fn invalidate_tlb() {
    crate::x86::flush_tlb();
}

/// Flush TLB. In PAE mode, also syncs the hardware PDPT
/// before reloading CR3.
pub fn flush_tlb() {
    sync_hw_pdpt();
    crate::x86::flush_tlb();
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
            lib::println!("Paging: Legacy (32-bit)");
            remove_identity_mapping(e);
            harden_kernel(e);
        }
        Entries::E64(e) => {
            lib::println!("Paging: PAE (64-bit entries)");
            let lm = cpu_supports_long_mode();
            if lm {
                lib::println!("CPU supports Long Mode (64-bit)");

                // Set up long mode page tables
                setup_long_mode_tables();
                lib::println!("Long mode tables set up");
            }

            remove_identity_mapping(e);
            lib::println!("Identity mapping removed");

            enable_nx();
            if nx_enabled() {
                lib::println!("NX (No-Execute) protection enabled");
            }

            enable_wc_pat();
            if wc_pat_enabled() {
                lib::println!("PAT: Write-Combining slot enabled (framebuffer)");
            }

            harden_kernel(e);
            invalidate_tlb();
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

/// Check if CPU supports the Page Attribute Table (CPUID.1:EDX bit 16).
pub fn cpu_supports_pat() -> bool {
    let (_, _, _, edx) = crate::x86::cpuid(1);
    edx & (1 << 16) != 0
}

/// Set when `enable_wc_pat` programmed the WC PAT slot. `fbcon` checks this to
/// decide whether the framebuffer can be mapped Write-Combining (else UC).
static mut WC_PAT_ENABLED: bool = false;

/// Whether a Write-Combining PAT slot is available (see `flags::WRITE_COMBINE`).
pub fn wc_pat_enabled() -> bool {
    unsafe { WC_PAT_ENABLED }
}

/// Reprogram PAT entry 4 (PAT=1, PCD=0, PWT=0) from its default WB to
/// Write-Combining, so a 4 KB leaf PTE carrying `flags::WRITE_COMBINE` maps WC.
///
/// Entries 0–3 — the PCD/PWT combinations the rest of the kernel relies on for
/// WB / WT / UC- / UC — are left at their reset values, so nothing already
/// mapped changes type. Only pages that explicitly set the PAT bit (the
/// framebuffer) pick up WC. Must run after paging is up and before the
/// framebuffer is mapped (`fbcon::init`).
pub fn enable_wc_pat() {
    if !cpu_supports_pat() {
        return;
    }
    // Reset IA32_PAT = 0x0007_0406_0007_0406 (PA0=WB PA1=WT PA2=UC- PA3=UC,
    // PA4=WB PA5=WT PA6=UC- PA7=UC). Rewrite PA4 (byte 4 = bits 32..39) WB→WC(0x01).
    const PAT_RESET: u64 = 0x0007_0406_0007_0406;
    const PAT_WC: u64 = (PAT_RESET & !(0xFFu64 << 32)) | (0x01u64 << 32);
    unsafe {
        // SDM 11.12.4 cautions to flush around a memory-type change; the FB isn't
        // mapped yet and we only touch an otherwise-unused slot, but flush anyway.
        crate::x86::wbinvd();
        crate::x86::wrmsr(crate::x86::IA32_PAT_MSR, PAT_WC);
        crate::x86::wbinvd();
        crate::x86::flush_tlb();
        WC_PAT_ENABLED = true;
    }
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

fn boot_phys_page(page: &RawPage) -> u64 {
    let va = page as *const _ as usize;
    ((va - KERNEL_BASE + KERNEL_PHYS) >> 12) as u64
}

fn boot_phys_addr(page: &RawPage) -> u64 {
    boot_phys_page(page) << 12
}

/// Enable legacy paging (32-bit, 2-level)
///
/// PD[0] = identity map first 4MB (uses scratch page, temporary)
/// PD[768] = recursive (0xC0000000 >> 22 = 768)
/// PD[770] = kernel region (0xC0800000 >> 22 = 770)
///   PT[0-511]: PML4 region (0xC0800000-0xC09FFFFF)
///   PT[512-767]: low mem (0xC0A00000-0xC0AFFFFF)
///   PT[768-1023]: kernel (0xC0B00000-0xC0BFFFFF)
pub fn enable_legacy(scratch: &mut PageTable32, kernel_phys: usize, kernel_pages: usize) {
    #[allow(static_mut_refs)]
    let kpages = unsafe { KERNEL_PAGES.legacy() };
    // Identity map first 4MB (1024 pages) using scratch page
    for i in 0..1024 {
        scratch[i] = Entry32::new(i as u64, true, false);
    }

    // Map low memory (first 1MB) at LOW_MEM_BASE (0xC0A00000)
    // PT index for 0xC0A00000: (0xC0A00000 >> 12) & 0x3FF = 512
    for i in 0..256 {
        let mut e = Entry32::new(i as u64, true, false);
        // VGA framebuffer (0xA0-0xBF) must be uncacheable
        if (0xA0..0xC0).contains(&i) {
            e.set_raw(e.raw() | flags::CACHE_DISABLE);
        }
        kpages.pt_kernel[512 + i] = e;
    }

    // Map kernel at KERNEL_BASE (0xC0B00000)
    // PT index for 0xC0B00000: (0xC0B00000 >> 12) & 0x3FF = 768
    // Pages past the first 1 MB (PT end) continue in pt_kernel2 (PD[771],
    // 0xC0C00000+) — the embedded bootfs pushes the kernel past 1 MB.
    for i in 0..kernel_pages.min(256 + 1024) {
        let e = Entry32::new((kernel_phys / PAGE_SIZE + i) as u64, true, false);
        if i < 256 {
            kpages.pt_kernel[768 + i] = e;
        } else {
            kpages.pt_kernel2[i - 256] = e;
        }
    }

    // Setup page directory
    // PD[0] = identity (first 4MB) using scratch
    kpages.pd[0] = Entry32::new(boot_phys_page(&scratch.0), true, false);

    // PD[768] = recursive (0xC0000000 >> 22 = 768)
    kpages.pd[768] = Entry32::new(boot_phys_page(&kpages.pd.0), true, false);

    // PD[770] = kernel region (0xC0800000 >> 22 = 770)
    kpages.pd[770] = Entry32::new(boot_phys_page(&kpages.pt_kernel.0), true, false);

    // PD[771] = kernel overflow (0xC0C00000-0xC0FFFFFF)
    kpages.pd[771] = Entry32::new(boot_phys_page(&kpages.pt_kernel2.0), true, false);

    unsafe {
        crate::x86::write_cr3(boot_phys_addr(&kpages.pd.0) as u32);
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
pub fn enable_pae(scratch: &mut PageTable64, kernel_phys: usize, kernel_pages: usize) {
    #[allow(static_mut_refs)]
    let kpages = unsafe { KERNEL_PAGES.pae() };
    // Identity map using scratch as PD: scratch[0] = scratch (self-ref PT for 0-2MB),
    // scratch[1] = pt_pml4 (PT for 2-4MB, temporarily borrowed)
    scratch[0] = Entry64::new(boot_phys_page(&scratch.0), true, false);
    scratch[1] = Entry64::new(boot_phys_page(&kpages.pt_pml4.0), true, false);
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
        if (0xA0..0xC0).contains(&i) {
            e.set_raw(e.raw() | flags::CACHE_DISABLE);
        }
        kpages.pt_kernel[i] = e;
    }

    // Map kernel at KERNEL_BASE (0xC0B00000)
    // PT index 256-511 maps kernel (up to 1MB); pages past that continue in
    // pt_kernel2/pt_kernel3 (PDPT[6]/[7], 0xC0C00000+, 2MB per table) — the
    // embedded bootfs pushes the kernel past 1 MB.
    for i in 0..kernel_pages.min(256 + 1024) {
        let e = Entry64::new((kernel_phys / PAGE_SIZE + i) as u64, true, false);
        if i < 256 {
            kpages.pt_kernel[256 + i] = e;
        } else if i < 256 + 512 {
            kpages.pt_kernel2[i - 256] = e;
        } else {
            kpages.pt_kernel3[i - 256 - 512] = e;
        }
    }

    // Setup PDPT (virtual root — has R/W bits for COW tracking)
    kpages.pdpt[0] = Entry64::new(boot_phys_page(&scratch.0), true, false);
    kpages.pdpt[3] = Entry64::new(boot_phys_page(&kpages.pdpt.0), true, false);
    kpages.pdpt[4] = Entry64::new(boot_phys_page(&kpages.pt_pml4.0), true, false);
    kpages.pdpt[5] = Entry64::new(boot_phys_page(&kpages.pt_kernel.0), true, false);
    kpages.pdpt[6] = Entry64::new(boot_phys_page(&kpages.pt_kernel2.0), true, false);
    kpages.pdpt[7] = Entry64::new(boot_phys_page(&kpages.pt_kernel3.0), true, false);

    // The hardware PAE PDPT has a stricter format than the virtual root:
    // bits 1 (R/W) and 2 (U/S) are reserved in PDPTEs. Keep the full entries
    // in the recursively mapped virtual root for software/COW bookkeeping,
    // but load CR3 with the dedicated 32-byte hardware PDPT from the start.
    // QEMU accepts those reserved bits in a CR3-loaded PDPT; real CPUs need
    // them clear and can fault before the first post-paging instruction.
    for i in 0..4 {
        unsafe { HW_PDPT.0[i] = hardware_pdpte(kpages.pdpt[i]); }
    }
    let hw_pdpt_va = (&raw const HW_PDPT) as usize;
    let hw_pdpt_phys = hw_pdpt_va - KERNEL_BASE + KERNEL_PHYS;
    let cr4 = crate::x86::read_cr4();
    unsafe {
        crate::x86::write_cr4(cr4 | crate::x86::cr4::PAE);
        crate::x86::write_cr3(hw_pdpt_phys as u32);
        let cr0 = crate::x86::read_cr0();
        crate::x86::write_cr0(cr0 | crate::x86::cr0::PG | crate::x86::cr0::WP);
    }
    IS_PAE.store(true, core::sync::atomic::Ordering::Relaxed);
}

/// Boot-time early framebuffer window: a static PD of 2MB pages installed at
/// PDPT[2] (VA 0x80000000), usable the instant `enable_pae` returns — no
/// allocator, no #PF handler, works for ANY physical address (PAE PDEs carry
/// 52-bit phys; the Blade 14's GOP framebuffer sits at 0x7C_0000_0000, which
/// pre-paging 32-bit code cannot address at all). The boot life-sign strip is
/// painted through this and the window is torn down again immediately.
static mut EARLY_FB_PD: PageTable64 = PageTable64(RawPage([0; PAGE_SIZE]));

/// Map 64MB around `fb_phys` and return its VA. PAE/long boot path only
/// (legacy returns None — pre-PAE machines have a real VGA anyway).
pub fn map_early_fb(fb_phys: u64) -> Option<usize> {
    if !cpu_supports_pae() {
        return None;
    }
    const TWO_MB: u64 = 2 * 1024 * 1024;
    let base = fb_phys & !(TWO_MB - 1);
    #[allow(static_mut_refs)]
    let (pd, kpages) = unsafe { (&mut EARLY_FB_PD, KERNEL_PAGES.pae()) };
    for i in 0..32u64 {
        // PS (2MB page) + present + write + cache-disable (MMIO).
        pd[i as usize] = Entry64(
            (base + i * TWO_MB) | flags::PRESENT | flags::READ_WRITE
                | flags::PAGE_SIZE_BIT | flags::CACHE_DISABLE,
        );
    }
    kpages.pdpt[2] = Entry64::new(boot_phys_page(&pd.0), true, false);
    flush_tlb();
    Some(0x8000_0000usize + (fb_phys - base) as usize)
}

/// Tear the early framebuffer window down (PDPT[2] belongs to user space).
pub fn unmap_early_fb() {
    if !cpu_supports_pae() {
        return;
    }
    #[allow(static_mut_refs)]
    let kpages = unsafe { KERNEL_PAGES.pae() };
    kpages.pdpt[2] = Entry64::default();
    flush_tlb();
}

/// Enable paging with auto-detected mode
/// scratch is used for identity mapping (temporary, can be reused after remove_identity_mapping)
pub fn enable_paging(scratch: *mut RawPage, kernel_phys: usize, kernel_pages: usize) {
    // The kernel mapping covers 0xC0B00000-0xC0FFFFFF (PDE[770]'s last 1 MB
    // + the pt_kernel2/3 overflow tables = 5 MB, 1280 pages). Anything beyond
    // gets silently truncated by the `.min()` in enable_legacy/enable_pae and
    // page-faults at runtime. Trip a clear assert before that happens.
    assert!(kernel_pages <= 256 + 1024,
        "kernel too large: {} pages (>{} pages = 5 MB). Either shrink the \
         kernel or extend the mapping in enable_legacy/enable_pae with more \
         overflow page tables (PDE[772]+).",
        kernel_pages, 256 + 1024);
    // Note: physical_page() not available until page tables are set up
    if !cpu_supports_pae() {
        let scratch32 = unsafe { &mut *(scratch as *mut PageTable32) };
        enable_legacy(scratch32, kernel_phys, kernel_pages);
    } else {
        let scratch64 = unsafe { &mut *(scratch as *mut PageTable64) };
        enable_pae(scratch64, kernel_phys, kernel_pages);
    }
}

// =============================================================================
// Temporary mapping for fork operations
// =============================================================================

/// Page-aligned BSS page whose PTE is repurposed to map arbitrary physical
/// pages. Callers access it via `&mut TEMP_PAGE` after temp_swap.
static mut TEMP_PAGE: RawPage = RawPage([0; PAGE_SIZE]);

/// Map a physical page at the temp mapping address. Returns the page
/// that was previously mapped (pass back to restore).
#[must_use]
pub fn temp_swap(page: u64) -> u64 {
    let vpage = (&raw const TEMP_PAGE as usize) / PAGE_SIZE;
    let old_page = unsafe {
        if is_pae() {
            let entries = PAGE_TABLE_BASE as *mut Entry64;
            let old = (*entries.add(vpage)).page();
            *entries.add(vpage) = Entry64::new(page, true, false);
            old
        } else {
            let entries = PAGE_TABLE_BASE as *mut Entry32;
            let old = (*entries.add(vpage)).page();
            *entries.add(vpage) = Entry32::new(page, true, false);
            old
        }
    };
    invalidate_tlb();
    old_page
}

/// Allocate a fresh physical page and map it at the temp VA.
/// Returns the saved page (pass to temp_swap to restore and get the new page back).
#[must_use]
fn fresh_temp_page() -> u64 {
    temp_swap(crate::phys_mm::alloc_phys_page().expect("out of memory"))
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
#[allow(dead_code)]
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
/// Fork the current address space (COW).
/// Marks parent user entries R/O, increments ref counts, and fills
/// `child_root` with the child's user root entries.
pub fn fork_current(child_root: &mut RootPageTable) {
    let user_count = recursive_idx() - root_base();
    // Use a stack buffer for the full root page copy.
    // share_and_copy writes all entries (including kernel), but we only
    // need user entries for child_root.
    match entries() {
        Entries::E32(e) => {
            let mut buf = [Entry32::default(); PAGE_SIZE / core::mem::size_of::<Entry32>()];
            fork_generic(e, &mut buf);
            for (i, item) in buf.iter().enumerate().take(user_count) {
                unsafe { child_root.e32[i] = *item; }
            }
        }
        Entries::E64(e) => {
            let mut buf = [Entry64::default(); PAGE_SIZE / core::mem::size_of::<Entry64>()];
            fork_generic(e, &mut buf);
            for (i, item) in buf.iter().enumerate().take(user_count) {
                unsafe { child_root.e64[i] = *item; }
            }
        }
    }
}

/// Fork the current address space (COW).
///
/// All modes: share_and_copy the root (PD for legacy, PDPT for PAE/compat).
/// PAE only: deshare user entries [0..recursive) because PAE hardware
/// ignores R/W on PDPT entries.
fn fork_generic<E: Entry>(entries: &mut [E], dst: &mut [E]) {
    let root = root_base();
    let user_count = recursive_idx() - root;
    share_and_copy(&mut entries[root..root + user_count], &mut dst[..user_count]);

    // Eagerly deshare all user PD/PDPT entries so that COW enforcement
    // is pushed down to leaf PTEs.  This avoids cascading COW (where a
    // PD-level fault must share_and_copy before the leaf fault can fire)
    // which is fragile and hard to keep refcount-correct.
    //
    // PAE MUST do this (hardware ignores R/W on PDPT entries).
    // Legacy benefits from the same simplification.
    // Compat doesn't need it (PDPT entries have full R/W enforcement).
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
}

// =============================================================================
// COW fault handling
// =============================================================================

/// COW-share a page table page: mark each present non-MMIO entry R/O
/// in `src`, increment its ref count, and write the R/O copy to `dst`.
fn share_and_copy<E: Entry>(src: &mut [E], dst: &mut [E]) {
    use crate::phys_mm;

    debug_assert_eq!(src.len(), dst.len());

    for i in 0..src.len() {
        let mut e = src[i];
        if e.present() && e.raw() & (flags::CACHE_DISABLE | flags::FOREIGN) == 0 {
            e.set_hw_writable(false);
            src[i].set_hw_writable(false);
            phys_mm::inc_shared_count(src[i].page());
        }
        dst[i] = e;
    }

    invalidate_tlb();
}

/// COW a single entry (leaf data page or page table).
///
/// If sole owner, just sets hw_writable. Otherwise allocates a new page,
/// copies the old contents, and updates the entry. For page table entries,
/// also marks children R/O and increments their ref counts.
pub fn cow_entry<E: Entry>(entries: &mut [E], idx: usize) {
    use crate::phys_mm;

    debug_assert!(idx < recursive_idx(),
        "cow_entry: idx {} is at or above recursive entry, must be a user entry", idx);

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
        // Point entries[idx] at a fresh page first, so the recursive view
        // of child entries is writable (no R/O ancestor). Then temp_map
        // the old page as src and share_and_copy into the recursive view.
        let user = entries[idx].user();
        let p = phys_mm::alloc_phys_page().expect("Out of memory during COW");
        entries[idx] = E::new(p, true, user);
        invalidate_tlb();
        let saved = temp_swap(old_phys);
        let src = unsafe { let tp = &raw mut TEMP_PAGE; core::slice::from_raw_parts_mut((*tp).0.as_mut_ptr() as *mut E, epp) };
        share_and_copy(src, &mut entries[child_base..child_base + epp]);
        phys_mm::free_phys_page(temp_swap(saved));
        return;
    } else {
        // Leaf: copy old page content into a new physical page.
        if idx == 0 {
            // Page 0: can't read from VA 0 (null ptr). Copy via temp_map.
            let scratch = &raw mut crate::SCRATCH;
            let saved = temp_swap(old_phys);
            unsafe { let tp = &raw const TEMP_PAGE; core::ptr::copy_nonoverlapping(
                (*tp).0.as_ptr(), (*scratch).0.as_mut_ptr(), PAGE_SIZE); }
            let _ = fresh_temp_page();
            unsafe { let tp = &raw mut TEMP_PAGE; core::ptr::copy_nonoverlapping(
                (*scratch).0.as_ptr(), (*tp).0.as_mut_ptr(), PAGE_SIZE); }
            temp_swap(saved)
        } else {
            // Other pages: read directly from user VA
            let saved = fresh_temp_page();
            unsafe {
                let src = (idx * PAGE_SIZE) as *const u8;
                let tp = &raw mut TEMP_PAGE;
                core::ptr::copy_nonoverlapping(src, (*tp).0.as_mut_ptr(), PAGE_SIZE);
            }
            temp_swap(saved)
        }
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
    use crate::phys_mm;

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
                // Leaf page — free unless MMIO (cache-disabled)
                if entries[child].raw() & (flags::CACHE_DISABLE | flags::FOREIGN) == 0 {
                    phys_mm::free_phys_page(entries[child].page());
                }
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

/// Dedicated low identity hierarchy used only while toggling PAE/compat mode.
/// The boot SCRATCH page cannot be reused here: page-zero COW operations use
/// it after startup, and a leaf PTE alone is ineffective once PDPT[0] has been
/// removed by `finish_setup_paging`.
static mut TRAMPOLINE_PD: PageTable64 = PageTable64(RawPage([0; PAGE_SIZE]));
static mut TRAMPOLINE_PT: PageTable64 = PageTable64(RawPage([0; PAGE_SIZE]));

/// Identity-map the page holding `toggle_prot_compat` so the function can run
/// at its physical address while paging is briefly disabled during a mode
/// toggle. The page is COMPUTED from the symbol — an old version hardcoded
/// "first page of .text" (KERNEL_PHYS), but the linker long since stopped
/// placing the stub there, so the identity fetch landed on an unmapped page,
/// the arch demand-fault mapped it as NX data, and the retried fetch panicked
/// with a present+NX #PF (first 64-bit exec on metal was the reproducer).
/// Returns the previous PDPT[0] value to pass back to `clear_trampoline()`.
pub fn ensure_trampoline_mapped() -> u64 {
    unsafe extern "fastcall" {
        fn toggle_prot_compat(new_cr3: u32);
    }
    let stub_phys = toggle_prot_compat as *const () as usize - KERNEL_BASE + KERNEL_PHYS;
    let page = stub_phys / PAGE_SIZE;
    // One PT covers 2 MiB; the stub is a few dozen bytes but map its neighbor
    // too in case it straddles a page boundary.
    debug_assert!(page + 1 < PAGE_SIZE / 8, "toggle stub beyond the trampoline PT's 2 MiB reach");
    if let Entries::E64(e) = entries() {
        let root = root_base();
        let saved = e[root].0;
        #[allow(static_mut_refs)]
        unsafe {
            TRAMPOLINE_PT[page] = Entry64::new(page as u64, true, false);
            TRAMPOLINE_PT[page + 1] = Entry64::new(page as u64 + 1, true, false);
            TRAMPOLINE_PD[0] = Entry64::new(boot_phys_page(&TRAMPOLINE_PT.0), true, false);
            e[root] = Entry64::new(boot_phys_page(&TRAMPOLINE_PD.0), true, false);
        }
        // Needed when the target is PAE; harmless when the target is compat.
        sync_hw_pdpt();
        // PAE caches all four PDPTEs on MOV CR3. INVLPG cannot make a newly
        // installed PDPT[0] visible before the trampoline's physical jump.
        crate::x86::flush_tlb();
        saved
    } else {
        0
    }
}

/// Restore PDPT[0] after a mode toggle.
pub fn clear_trampoline(saved: u64) {
    if let Entries::E64(e) = entries() {
        e[root_base()] = Entry64(saved);
    }
    sync_hw_pdpt();
    crate::x86::flush_tlb();
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
    let saved = temp_swap(0); // map physical page 0 at temp VA
    let mut buf = [0u8; PAGE_SIZE];
    unsafe {
        let tp = &raw const TEMP_PAGE;
        core::ptr::copy_nonoverlapping(
            (*tp).0.as_ptr(),
            buf.as_mut_ptr(),
            PAGE_SIZE,
        );
    }
    let _ = fresh_temp_page();
    unsafe {
        let tp = &raw mut TEMP_PAGE;
        core::ptr::copy_nonoverlapping(
            buf.as_ptr(),
            (*tp).0.as_mut_ptr(),
            PAGE_SIZE,
        );
    }
    entries[0] = E::new(temp_swap(saved), true, true);

    // Pages 1..0x10 (low 64KB excluding page 0): eager-alloc as zero pages
    // so the A20-disabled HMA wrap (PcMachine::new copies entries[0..0x10]
    // into HMA_PAGE) reliably aliases across the process lifetime. If these
    // were left as demand-paged-zero, the first write to virt 0x1000 would
    // alloc phys X for entries[1] while entries[0x101] still held the
    // not-present copy from PcMachine::new — a subsequent read of virt
    // 0x101000 would alloc its OWN phys Y, breaking the alias. Pre-
    // allocating ensures both PTEs reference the same phys page from the
    // start.
    for slot in entries.iter_mut().take(0x10usize).skip(1) {
        let saved2 = fresh_temp_page();
        unsafe {
            let tp = &raw mut TEMP_PAGE;
            core::ptr::write_bytes(
                (*tp).0.as_mut_ptr(),
                0,
                PAGE_SIZE,
            );
        }
        let new_phys = temp_swap(saved2);
        *slot = E::new(new_phys, true, true);
    }

    // Pages 0x10-0x9F: conventional memory — left unmapped (demand-paged zero)
    // Each process gets private zeroed pages on first access.

    // Pages 0xA0-0xBF: VGA framebuffer — identity mapped RW, cache disabled
    // PCD (bit 4) must be set so the CPU doesn't cache/combine writes.
    // VGA Odd/Even addressing relies on seeing individual byte accesses.
    for (i, slot) in entries.iter_mut().enumerate().take(0xC0usize).skip(0xA0) {
        let mut e = E::new(i as u64, true, true);
        e.set_raw(e.raw() | flags::CACHE_DISABLE);
        *slot = e;
    }

    // Pages 0xC0-0xFF: ROM/BIOS area — identity mapped RO by default.
    // UMB and EMS pages are cleared to not-present later by scan_uma().
    for (i, slot) in entries.iter_mut().enumerate().take(0x100usize).skip(0xC0) {
        *slot = E::new(i as u64, false, true);
    }

    // HMA (virt 0x100000..0x10FFFF) is set up by `PcMachine::new` in the DOS
    // personality, which copies entries[0..16] (user's private low memory)
    // into HMA_PAGE for the A20-disabled wrap. Seeding HMA_PAGE here with
    // direct phys 0..15 was a bug: PcMachine::new's first arch_copy_page_entries
    // moved that mapping into HMA_SHADOW (virt 0x110000..0x11FFFF), where it
    // remained user-accessible for the process lifetime — every write into
    // HMA_SHADOW landed at real phys 0..15, corrupting the master BIOS IVT/BDA.
    // Leaving entries[0x100..] not-present here means HMA_SHADOW also ends up
    // not-present after PcMachine::new's copy, which is the correct A20-on
    // state when no extended memory has been allocated.

    flush_tlb();
}

/// Map a physical page into the user address space.
pub fn map_user_page_phys(vpage: usize, ppage: u64, extra_flags: u64) {
    // MAP_MMIO: an emulated device aperture — present=0 + Cache-Disable (PCD),
    // the not-present twin of the present+PCD passthrough device mappings. A #PF
    // here is a device trap the kernel decodes (planar VGA, future emulated
    // BARs), not demand-paged RAM; try_handle_page_fault recognises the PCD.
    if extra_flags & arch_abi::MAP_MMIO != 0 {
        match entries() {
            Entries::E32(e) => { let mut x = Entry32::default(); x.set_raw(flags::CACHE_DISABLE | flags::USER); e[vpage] = x; }
            Entries::E64(e) => { let mut x = Entry64::default(); x.set_raw(flags::CACHE_DISABLE | flags::USER); e[vpage] = x; }
        }
        flush_tlb();
        return;
    }
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

/// Physical page base of the shared VGA text aperture (0xB8000-0xBFFFF: 8 pages
/// of real RAM), allocated once on first call. On a UEFI/GOP machine the legacy
/// physical 0xB8000 region is unbacked (reads 0xFF), so it cannot serve as the
/// text screen; this is the dedicated RAM that does. The kernel low-mem window
/// and every DOS process's guest 0xB8000 are both mapped to these pages, giving
/// one shared text screen — the emulated equivalent of VGA hardware's video RAM.
pub fn vga_text_aperture_ppage() -> u64 {
    // Single-threaded kernel state, allocated once at boot — a plain static like
    // the other paging/phys_mm globals (no atomic needed).
    static mut APERTURE: u64 = 0;
    unsafe {
        let cur = *core::ptr::addr_of!(APERTURE);
        if cur != 0 {
            return cur;
        }
        let base = crate::phys_mm::alloc_contig(8).expect("VGA text aperture alloc");
        *core::ptr::addr_of_mut!(APERTURE) = base;
        base
    }
}

/// Map the current process's VGA color-text aperture (guest 0xB8000-0xBFFFF, 8
/// pages) onto the shared text aperture, so it writes the one screen the kernel
/// console + every DOS process share. Unlike the graphics/mono region (which is
/// per-process via `map_fresh_range`), this is shared and NOT zeroed — on-screen
/// text (the boot log, a prior program's output) persists, exactly as VGA-text
/// hardware leaves the shared video RAM intact across programs.
pub fn map_vga_text_aperture_user() {
    let ap = vga_text_aperture_ppage();
    for i in 0..8usize {
        // Cacheable — this is RAM we allocated, not a card's MMIO — but FOREIGN,
        // because the same frames are mapped into the kernel window and every
        // other DOS process: no space may free or copy-on-write them.
        map_user_page_phys(0xB8000 / PAGE_SIZE + i, ap + i as u64, flags::FOREIGN);
    }
}

/// Allocate a physical page, fill it with `data` (zero-padded to PAGE_SIZE),
/// and map it at user virtual page `page_idx` (writable, user-accessible).
#[allow(dead_code)]
pub fn map_user_page(page_idx: usize, data: &[u8]) {
    assert!(data.len() <= PAGE_SIZE);
    let saved = fresh_temp_page();
    unsafe {
        let tp = &raw mut TEMP_PAGE;
        let dst = (*tp).0.as_mut_ptr();
        core::ptr::write_bytes(dst, 0, PAGE_SIZE);
        core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
    }
    let phys = temp_swap(saved);
    match entries() {
        Entries::E32(e) => { e[page_idx] = Entry32::new(phys, true, true); }
        Entries::E64(e) => { e[page_idx] = Entry64::new(phys, true, true); }
    }
    flush_tlb();
}

/// Set A20 gate state for VM86 mode.
/// When disabled (default): virtual 0x100000-0x10FFFF → physical 0x00000-0x0FFFF (wrap)
/// When enabled: virtual 0x100000-0x10FFFF → the thread's saved HMA mappings.
/// Copy page table entries from src range to dst range.
pub fn copy_page_entries(src_vpage: usize, dst_vpage: usize, count: usize) {
    use crate::phys_mm;
    match entries() {
        Entries::E32(e) => { for i in 0..count {
            // A copy into a live mapping must drop the reference it held, or the
            // clobbered frame's refcount never reaches zero and it leaks (mirror
            // unmap_range). Skip MMIO / externally-owned frames.
            let old = e[dst_vpage + i];
            if old.present() && old.raw() & (flags::CACHE_DISABLE | flags::FOREIGN) == 0 {
                phys_mm::free_phys_page(old.addr() >> 12);
            }
            e[dst_vpage + i] = e[src_vpage + i];
            if e[src_vpage + i].present() { phys_mm::inc_shared_count(e[src_vpage + i].page()); }
        }}
        Entries::E64(e) => { for i in 0..count {
            // A copy into a live mapping must drop the reference it held, or the
            // clobbered frame's refcount never reaches zero and it leaks (mirror
            // unmap_range). Skip MMIO / externally-owned frames.
            let old = e[dst_vpage + i];
            if old.present() && old.raw() & (flags::CACHE_DISABLE | flags::FOREIGN) == 0 {
                phys_mm::free_phys_page(old.addr() >> 12);
            }
            e[dst_vpage + i] = e[src_vpage + i];
            if e[src_vpage + i].present() { phys_mm::inc_shared_count(e[src_vpage + i].page()); }
        }}
    }
    flush_tlb();
}

/// Swap page table entries between two ranges (no refcount changes).
pub fn swap_page_entries(a_vpage: usize, b_vpage: usize, count: usize) {
    match entries() {
        Entries::E32(e) => {
            for i in 0..count {
                e.swap(a_vpage + i, b_vpage + i);
            }
        }
        Entries::E64(e) => {
            for i in 0..count {
                e.swap(a_vpage + i, b_vpage + i);
            }
        }
    }
    flush_tlb();
}

/// Clear page entries to absent (enables demand paging on next access).
pub fn unmap_range(base_page: usize, num_pages: usize) {
    use crate::phys_mm;
    match entries() {
        Entries::E32(e) => {
            for i in 0..num_pages {
                let ent = e[base_page + i];
                // MMIO / externally-owned (cache-disabled) frames are not
                // ours to free — same rule as the address-space teardown.
                if ent.present() && ent.raw() & (flags::CACHE_DISABLE | flags::FOREIGN) == 0 {
                    phys_mm::free_phys_page(ent.addr() >> 12);
                }
                e[base_page + i] = Entry32::default();
            }
        }
        Entries::E64(e) => {
            for i in 0..num_pages {
                let ent = e[base_page + i];
                if ent.present() && ent.raw() & (flags::CACHE_DISABLE | flags::FOREIGN) == 0 {
                    phys_mm::free_phys_page(ent.addr() >> 12);
                }
                e[base_page + i] = Entry64::default();
            }
        }
    }
    flush_tlb();
}


/// Replace a range with fresh anonymous user-RW frames. Owned (non-MMIO)
/// frames currently mapped are freed first; cache-disabled / externally-
/// owned pages (an aliased DMA buffer) are left intact.
pub fn map_fresh_range(base_page: usize, num_pages: usize) {
    use crate::phys_mm;
    match entries() {
        Entries::E32(e) => {
            for i in 0..num_pages {
                let ent = e[base_page + i];
                if ent.present() && ent.raw() & (flags::CACHE_DISABLE | flags::FOREIGN) == 0 {
                    phys_mm::free_phys_page(ent.addr() >> 12);
                }
                let fresh = phys_mm::alloc_phys_page().unwrap_or(0);
                e[base_page + i] = Entry32::new(fresh, true, true);
            }
        }
        Entries::E64(e) => {
            for i in 0..num_pages {
                let ent = e[base_page + i];
                if ent.present() && ent.raw() & (flags::CACHE_DISABLE | flags::FOREIGN) == 0 {
                    phys_mm::free_phys_page(ent.addr() >> 12);
                }
                let fresh = phys_mm::alloc_phys_page().unwrap_or(0);
                e[base_page + i] = Entry64::new(fresh, true, true);
            }
        }
    }
    flush_tlb();
    // Zero the freshly-mapped pages. `alloc_phys_page` hands back uninitialised
    // frames; on real hardware that RAM reads as 0xFF, so a fresh VGA aperture
    // showed as a white screen wherever the guest hadn't drawn (qemu happens to
    // zero-fill, hiding it). The pages are now mapped + TLB-flushed, so write
    // through the mapped VA. (DOS callers also rely on a clean B8000/A0000.)
    for i in 0..num_pages {
        unsafe {
            core::ptr::write_bytes(((base_page + i) * PAGE_SIZE) as *mut u8, 0, PAGE_SIZE);
        }
    }
}

/// Harden kernel memory permissions
/// - .text: read-only, executable
/// - .rodata: read-only, non-executable (if NX available)
/// - .data/.bss: read-write, non-executable (if NX available)
fn harden_kernel<E: Entry>(entries: &mut [E]) {
    // Get linker symbols
    unsafe extern "C" {
        static _kernel_start: u8;
        static _etext: u8;
        static _erodata: u8;
        static _data: u8;
        static _end: u8;
    }

    let text_start = (&raw const _kernel_start) as usize;
    let text_end = (&raw const _etext) as usize;
    let rodata_end = (&raw const _erodata) as usize;
    let data_start = (&raw const _data) as usize;
    let data_end = (&raw const _end) as usize;

    let text_start_page = page_idx(text_start);
    let text_end_page = page_idx(text_end + PAGE_SIZE - 1);
    let rodata_end_page = page_idx(rodata_end + PAGE_SIZE - 1);
    let data_start_page = page_idx(data_start);
    let data_end_page = page_idx(data_end + PAGE_SIZE - 1);

    lib::println!("Hardening kernel:");
    lib::println!("  .text:   {:#x}-{:#x} (pages {}-{}): R-X",
        text_start, text_end, text_start_page, text_end_page);
    lib::println!("  .rodata: {:#x}-{:#x} (pages {}-{}): R-- NX",
        text_end, rodata_end, text_end_page, rodata_end_page);
    lib::println!("  .data:   {:#x}-{:#x} (pages {}-{}): RW- NX",
        data_start, data_end, data_start_page, data_end_page);

    // .text: read-only, executable (no NX)
    for slot in entries.iter_mut().take(text_end_page).skip(text_start_page) {
        slot.set_hw_writable(false);
        slot.set_writable(false);
    }

    // .rodata: read-only, non-executable
    for slot in entries.iter_mut().take(rodata_end_page).skip(text_end_page) {
        slot.set_hw_writable(false);
        slot.set_writable(false);
        slot.set_no_execute(true);
    }

    // .data/.bss: read-write, non-executable
    for slot in entries.iter_mut().take(data_end_page).skip(data_start_page) {
        slot.set_no_execute(true);
    }

    invalidate_tlb();
    lib::println!("Kernel hardening complete");
}
