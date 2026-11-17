//! x86 page tables over caller-supplied storage.
//!
//! Saved user roots belong to callers. One fixed live directory and long-mode
//! mirror belong to this CPU. Mapping operations consume PageInput; user faults
//! consume PageSupply. Neither path allocates or grows host containers.

#[cfg(test)]
use crate::test_memory;

use crate::phys;

// Serializes shared-table ownership transitions across hosted CPU threads.
// Nested resolvers on this thread do not acquire the mutex twice.
static PAGING_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
thread_local! {
    static PAGING_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
struct PagingGuard { _lock: Option<std::sync::MutexGuard<'static, ()>> }
impl PagingGuard {
    fn lock() -> Self {
        let lock = if PAGING_DEPTH.with(|depth| depth.get() == 0) {
            Some(PAGING_LOCK.lock().expect("paging operation panicked"))
        } else { None };
        PAGING_DEPTH.with(|depth| depth.set(depth.get() + 1));
        Self { _lock: lock }
    }
}
impl Drop for PagingGuard {
    fn drop(&mut self) { PAGING_DEPTH.with(|depth| depth.set(depth.get() - 1)); }
}

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
/// Physical-device alias temporarily redirected onto an owned shadow page.
/// The other PTE flags remain unchanged so the mapping can be restored.
/// Shared writable RAM: fork retains this mapping instead of making it COW.
const SHARED: u32 = 1 << 11;

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
    // Includes demand paging and host-side COW resolution, which can happen
    // through GuestBytes without passing through an arch mapping call.
    #[cfg(feature = "kvm")]
    crate::kvm::mark_tlb_dirty();
    unsafe {
        let p = phys::frame_ptr(ppage).add(i * 4) as *mut u32;
        p.write_unaligned(v);
    }
}

/// Consume and zero one caller-supplied table frame.
#[cfg(test)]
fn take_table() -> u64 {
    let ppage = phys::take_input().expect("page table needs supplied input");
    unsafe { core::ptr::write_bytes(phys::frame_ptr(ppage), 0, 4096) };
    ppage
}

/// Create a new (empty) address space: a zeroed page directory frame. Returns
/// its ppage — this is the value loaded into CR3.
#[cfg(test)]
pub fn new_page_dir() -> u64 {
    take_table()
}

/// Map virtual page `vaddr` (page-aligned) to physical frame `paddr_ppage` in
/// the address space rooted at page directory `pd`. Allocates the intermediate
/// page table on first use. `writable` clears the W bit when false (read-only).
#[cfg(test)]
pub fn map_page(pd: u64, vaddr: u32, paddr_ppage: u64, writable: bool) {
    let pde_i = pde_index(vaddr);
    let pde = read_entry(pd, pde_i);
    let pt = if pde & PRESENT != 0 {
        (pde >> 12) as u64
    } else {
        let pt = take_table();
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
#[cfg(test)]
fn unmap_page(pd: u64, vaddr: u32) {
    let pde = read_entry(pd, pde_index(vaddr));
    if pde & PRESENT != 0 {
        write_entry((pde >> 12) as u64, pte_index(vaddr), 0);
    }
}

/// Software walk: translate guest virtual `vaddr` to a guest physical address,
/// or `None` if unmapped. Used by the kernel's guest-memory accessors (the
/// kernel is host code; it can't lean on the CPU MMU like the metal kernel).
pub fn translate(pd: u64, vaddr: u32) -> Option<u32> {
    let _paging = PagingGuard::lock();
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
        crate::phys::init_test_ram();
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
        crate::phys::init_test_ram();
        let pd = new_page_dir();
        // Map a few non-identity pages, including two in the same 4 MiB region
        // (shared page table) and one far away (separate page table).
        let f1 = test_memory::alloc_backed_pages(1);
        let f2 = test_memory::alloc_backed_pages(1);
        let f3 = test_memory::alloc_backed_pages(1);
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
        crate::phys::init_test_ram();
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
        let gdt_frame = test_memory::alloc_backed_pages(1);
        let code_frame = test_memory::alloc_backed_pages(1);
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
                    let frame = test_memory::alloc_backed_pages(1);
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

// Saved roots and fixed live tables.

use std::cell::Cell;
use crate::space::RootPageTable;
thread_local! {
    static STORAGE: Cell<u64> = const { Cell::new(u64::MAX) };
}
/// Fixed supervisor storage: directory, SYS table, zero, SYS pages and long twin.
pub const PAGING_PAGES: usize = 28 + 2054;

/// Storage is caller-owned, contiguous, zeroed and resident for this CPU's life.
pub unsafe fn initialize(storage: u64) {
    assert!(storage + PAGING_PAGES as u64 <= (phys::PHYS_SIZE / 4096) as u64);
    STORAGE.with(|s| { assert_eq!(s.replace(storage), u64::MAX); });
    let pd = storage;
    write_entry(pd, 1023, (((storage + 1) as u32) << 12) | PRESENT | WRITABLE);
    for i in 0..crate::sysdesc::SYS_SIZE / 4096 {
        let address = crate::sysdesc::SYS_BASE as u32 + (i * 4096) as u32;
        write_entry(storage + 1, pte_index(address),
            (((storage + 3 + i as u64) as u32) << 12) | PRESENT | WRITABLE);
    }
    crate::sysdesc::initialize(storage + 3);
}
pub fn active_pd() -> u64 {
    STORAGE.with(|s| { assert_ne!(s.get(), u64::MAX, "paging not initialized"); s.get() })
}
fn with_active_pd<R>(f: impl FnOnce(u64) -> R) -> R { f(active_pd()) }

pub fn activate(mut incoming: RootPageTable) -> RootPageTable {
    let _paging = PagingGuard::lock();
    let pd = active_pd();
    for (i, entry) in incoming.0.iter_mut().enumerate() {
        let old = read_entry(pd, i);
        write_entry(pd, i, *entry);
        *entry = old;
    }
    incoming
}
pub fn space_translate(vaddr: u32) -> Option<u32> { translate(active_pd(), vaddr) }

/// Share table storage. Leaf references belong to the tables, so retaining a
/// table does not walk its leaves. Detachment establishes new leaf references.
pub fn space_fork(child: &mut RootPageTable) {
    let _paging = PagingGuard::lock();
    assert!(child.0.iter().all(|&e| e == 0));
    let pd = active_pd();
    for (i, entry) in child.0.iter_mut().enumerate() {
        let raw = read_entry(pd, i);
        if raw & PRESENT != 0 {
            phys::retain(u64::from(raw >> 12));
            *entry = (raw & !WRITABLE) | COW;
            write_entry(pd, i, *entry);
        }
    }
}

fn private_table(pd: u64, index: usize, fault: bool) -> Option<u64> {
    let pde = read_entry(pd, index);
    if pde & PRESENT != 0 && pde & COW == 0 { return Some(u64::from(pde >> 12)); }
    let old = u64::from(pde >> 12);
    let fresh = if fault { phys::take_fault() } else { phys::take_input() }?;
    if pde & PRESENT != 0 {
        for i in 0..1024 {
            let raw = read_entry(old, i);
            let borrowed = raw & TYPED != 0 && raw & SHARED != 0;
            let cow = raw & PRESENT != 0 && raw & WRITABLE != 0 && !borrowed;
            let entry = if cow { (raw & !WRITABLE) | COW } else { raw };
            if owns_mapping(entry) { phys::retain(u64::from(entry >> 12)); }
            write_entry(fresh, i, entry);
        }
        release_table(old);
    }
    write_entry(pd, index, ((fresh as u32) << 12) | ENTRY_FLAGS);
    Some(fresh)
}

fn release_table(table: u64) {
    if !phys::shared(table) {
        for i in 0..1024 { release_mapping(read_entry(table, i)); }
    }
    phys::release(table);
}
pub fn destroy(root: &mut RootPageTable) {
    let _paging = PagingGuard::lock();
    for entry in &mut root.0 {
        if *entry & PRESENT != 0 { release_table(u64::from(*entry >> 12)); }
        *entry = 0;
    }
}

/// Resolve a write #PF on a present COW page in the active space: privatise the
/// frame (copy if still shared with another space, else just re-enable write)
/// and clear the COW mark. Returns false if `vaddr` isn't a COW page — a
/// genuine read-only/illegal write the kernel must surface as a fault.
pub fn space_cow_fault(vaddr: u32) -> bool {
    let _paging = PagingGuard::lock();
    if !phys::can_fault() { return false; }
    let pd = active_pd();
    let pde = read_entry(pd, pde_index(vaddr));
    if pde & PRESENT == 0 { return false; }
    let old = pte_raw(pd, vaddr);
    if old & PRESENT == 0 || pde & COW == 0 && old & COW == 0 { return false; }
    // A shared table has hardware W=0; detach even when the leaf itself is RO.
    let pt = private_table(pd, pde_index(vaddr), true).unwrap();
    let pte = read_entry(pt, pte_index(vaddr));
    if pte & WRITABLE != 0 { return true; }
    if pte & COW == 0 { return false; }
    let frame = u64::from(pte >> 12);
    let borrowed = pte & TYPED != 0 && pte & SHARED != 0;
    if borrowed || phys::shared(frame) {
        let new = phys::take_fault().unwrap();
        unsafe { core::ptr::copy_nonoverlapping(phys::frame_ptr(frame), phys::frame_ptr(new), 4096); }
        write_entry(pt, pte_index(vaddr), ((new as u32) << 12) | ((pte & 0xfff & !COW & !SHARED) | WRITABLE));
        if !borrowed { phys::release(frame); }
    } else {
        write_entry(pt, pte_index(vaddr), (pte & !COW) | WRITABLE);
    }
    true
}

/// Resolve user bytes through the active directory, consuming only donated
/// fault pages when necessary. Callers bound transfers and replenish between them.
pub fn space_resolve(vaddr: u32) -> *mut u8 {
    resolve_in(active_pd(), vaddr)
}

/// Resolve bytes through the executing CPU's directory.
pub fn resolve_in(pd: u64, vaddr: u32) -> *mut u8 {
    let _paging = PagingGuard::lock();
    let raw = pte_raw(pd, vaddr);
    assert!(raw & PRESENT != 0 || raw & TYPED == 0 && raw != ABSENT,
        "guest access to an absent or inaccessible mapping");
    let pa = match translate(pd, vaddr) {
        Some(pa) => pa,
        None => {
            assert!(vaddr < 0xc0000000 && phys::can_fault(), "guest byte access needs supplied pages");
            let table = private_table(pd, pde_index(vaddr), true).unwrap();
            let frame = phys::take_fault().unwrap();
            write_entry(table, pte_index(vaddr), ((frame as u32) << 12) | ENTRY_FLAGS);
            (frame as u32) << 12 | (vaddr & 0xFFF)
        }
    };
    unsafe { phys::frame_ptr((pa >> 12) as u64).add((pa & 0xFFF) as usize) }
}

/// Kernel writes to typed mappings obey the same leaf permissions as guests.
pub(crate) fn space_resolve_write(vaddr: u32) -> *mut u8 {
    let _paging = PagingGuard::lock();
    let pd = active_pd();
    let raw = pte_raw(pd, vaddr);
    if raw & PRESENT != 0 {
        if raw & COW != 0 || read_entry(pd, pde_index(vaddr)) & COW != 0 {
            assert!(space_cow_fault(vaddr), "guest write to protected mapping");
        }
        assert!(pte_raw(pd, vaddr) & WRITABLE != 0, "guest write to protected mapping");
    }
    space_resolve(vaddr)
}

/// Guest-fault resolve from the software CPU (#PF, no EIP progress + CR2). Returns
/// `true` if the page was demand-committed (retry) and `false` for a genuinely
/// illegal access (null guard / out of range) that must bubble as `PageFault`.
const NULL_GUARD: u32 = 0x1_0000;
pub fn space_demand(vaddr: u32) -> bool {
    let _paging = PagingGuard::lock();
    let page = vaddr & !0xFFF;
    let pd = active_pd();
    if translate(pd, vaddr).is_some() {
        return true; // already present — spurious refault, just retry
    }
    // MMIO/device aperture (present=0 + PCD, e.g. the planar VGA window mapped
    // with MAP_MMIO): trap to the kernel, never demand-commit RAM.
    if pte_raw(pd, vaddr) & (CACHE_DISABLE | TYPED) != 0 {
        return false;
    }
    if vaddr < NULL_GUARD || (vaddr as usize) >= 0xC000_0000 {
        return false;
    }
    if !phys::can_fault() { return false; }
    let table = private_table(pd, pde_index(page), true).unwrap();
    let frame = phys::take_fault().unwrap();
    write_entry(table, pte_index(page), ((frame as u32) << 12) | ENTRY_FLAGS);
    true
}





/// Free every user page in the active space (arch CLEAN): drop the PTEs and
/// return the frames to the allocator. Kernel windows (high) are left intact.
pub fn space_clean() {
    let _paging = PagingGuard::lock();
    let mut old = activate(RootPageTable::empty());
    destroy(&mut old);
}

// Long-mode hardware tables are a bounded mirror of the legacy source tree.
// A generation change rebuilds the one caller-supplied workspace for this CPU.
const ENTRY_FLAGS64: u64 = ENTRY_FLAGS as u64;

thread_local! {
    static LONG_GEN: Cell<u64> = const { Cell::new(1) };
    static LONG_BUILT: Cell<u64> = const { Cell::new(0) };
}

#[allow(dead_code)]
fn read_entry64(ppage: u64, i: usize) -> u64 {
    unsafe { (phys::frame_ptr(ppage).add(i * 8) as *const u64).read_unaligned() }
}
#[allow(dead_code)]
fn write_entry64(ppage: u64, i: usize, v: u64) {
    unsafe { (phys::frame_ptr(ppage).add(i * 8) as *mut u64).write_unaligned(v) }
}

/// Build a fresh 4-level tree mirroring the 2-level tree at `pd`. User VAs are
/// all below 4 GiB, so the shape is PML4[0] → one PDPT → up to 4 PDs → PTs;
/// each 32-bit page table (4 MiB reach) feeds two 64-bit ones (2 MiB reach).
#[allow(dead_code)]
fn build_long_twin(pd: u64) -> u64 {
    let mut frames = 0usize;
    let fresh = |used: &mut usize| {
        assert!(*used < 2054);
        let frame = active_pd() + 28 + *used as u64;
        *used += 1;
        unsafe { core::ptr::write_bytes(phys::frame_ptr(frame), 0, 4096); }
        frame
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
            write_entry64(pt64, pt_i, (if pde & COW != 0 { pte & !WRITABLE } else { pte }) as u64);
        }
    }
    pml4
}

/// PML4 root (ppage — `frame_phys` of it is the CR3 value) for a long-mode
/// slice of the ACTIVE space: the lazily (re)built 4-level twin.
#[allow(dead_code)]
pub fn active_pml4() -> u64 {
    let _paging = PagingGuard::lock();
    let generation = LONG_GEN.with(Cell::get);
    LONG_BUILT.with(|built| {
        if built.get() != generation {
            build_long_twin(active_pd());
            built.set(generation);
        }
    });
    active_pd() + 28
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
    use arch_abi::{UserPage, page_entry::{Attributes, Backing, Mapping, PageEntry, PhysicalFrame}};

    #[test]
    fn exhausted_fault_reservoir_returns_before_the_store_and_resumes() {
        use arch_abi::{Arch as _, GuestBytes as _, KernelEvent, Regs};
        crate::phys::init_test_ram();
        let mut machine = crate::backend::Interp;
        let code = 0x10000;
        // mov eax,20000000; mov ecx,96; store; add eax,4096; dec ecx; jnz store; int 80
        let program = [
            0xb8,0,0,0,0x20, 0xb9,96,0,0,0,
            0xc7,0,0x78,0x56,0x34,0x12, 0x05,0,0x10,0,0,
            0x49,0x75,0xf2, 0xcd,0x80,
        ];
        machine.copy_to(code, &program);
        let mut regs = Regs::empty();
        regs.init_user_process(code as u32, 0x80000);
        let mut exhausted = false;
        let mut finished = false;
        for _ in 0..1000 {
            let event = machine.execute(&mut regs, &arch_abi::IoPolicy::default(), std::time::Duration::from_millis(10));
            match event {
                KernelEvent::Irq => {
                    if !phys::can_fault() {
                        exhausted = true;
                        assert_eq!(regs.frame.rip, code as u64 + 10);
                        assert!(space_translate(regs.rax as u32).is_none(), "uncompleted store must remain unmapped");
                        phys::refill_test_reserve();
                    }
                }
                KernelEvent::SoftInt(0x80) | KernelEvent::Syscall => { finished = true; break; }
                other => panic!("unexpected event: {other:?}"),
            }
        }
        assert!(exhausted && finished);
        assert_eq!(machine.read::<u32>(0x20000000 + 95 * 4096), 0x12345678);
    }

    #[test]
    fn typed_fault_states_do_not_demand_allocate() {
        crate::phys::init_test_ram();

        let page = UserPage::new(0x41000000).unwrap();
        for entry in [PageEntry::Absent, PageEntry::Intercepted] {
            replace_user_mapping(page, entry).unwrap();
            assert!(!space_demand(page.address() as u32));
            assert_eq!(read_mapping(page).unwrap(), entry);
        }
        let frame = test_memory::alloc_backed_pages(1);
        let mapping = Mapping { backing: Backing::Owned(PhysicalFrame::new(frame).unwrap()),
            attributes: Attributes::EXECUTABLE | Attributes::CACHE_DISABLE };
        replace_user_mapping(page, PageEntry::NoAccess(mapping)).unwrap();
        assert!(test_memory::is_shared(frame));
        assert!(!space_demand(page.address() as u32));
        space_clean();
        assert!(!test_memory::is_shared(frame));
        test_memory::free_phys_page(frame);
    }

    #[test]
    fn cached_frame_private_protection_and_cow_preserve_backing_owner() {
        crate::phys::init_test_ram();

        let frame = test_memory::alloc_backed_pages(1);
        unsafe { *phys::frame_ptr(frame) = 0x42; }
        replace_user_mapping(UserPage::new(0x41000000).unwrap(), PageEntry::ReadOnly(Mapping {
            backing: Backing::Owned(PhysicalFrame::new(frame).unwrap()), attributes: Attributes::EXECUTABLE,
        })).unwrap();
        assert_eq!(space_translate(0x41000000), Some((frame * 4096) as u32));
        assert!(!space_cow_fault(0x41000000), "read-only protection denies writes");
        let mut child = RootPageTable::empty(); space_fork(&mut child); let parent = activate(child);
        assert!(!space_cow_fault(0x41000000));
        test_protect(0x41000, 1, true);
        assert!(space_cow_fault(0x41000000));
        let copy = space_translate(0x41000000).unwrap();
        assert_ne!(u64::from(copy >> 12), frame);
        unsafe { *phys::frame_ptr(u64::from(copy >> 12)) = 0x77; }
        assert_eq!(unsafe { *phys::frame_ptr(frame) }, 0x42);
        space_clean(); activate(parent); space_clean();
        assert!(!test_memory::is_shared(frame)); test_memory::free_phys_page(frame);
    }

    #[test]
    fn shared_kernel_ram_aliases_survive_fork_and_guest_teardown() {
        crate::phys::init_test_ram();
        let backing = test_memory::alloc_backed_pages(64);
        for i in 0..64 {
            replace_user_mapping(UserPage::new(0x41000000 + i * 4096).unwrap(), PageEntry::Writable(Mapping {
                backing: Backing::Borrowed(PhysicalFrame::new(backing + i).unwrap()), attributes: Attributes::EXECUTABLE,
            })).unwrap();
        }
        test_alias(0x41000, 0xA0, 16);
        for i in 0..8 {
            replace_user_mapping(UserPage::new(0xB0000 + i * 4096).unwrap(), PageEntry::Intercepted).unwrap();
        }
        unsafe { *phys::frame_ptr(backing).add(23) = 0x31; }
        assert_eq!(space_translate(0xA0017), Some((backing as u32 * 4096) + 23));
        let mut child = RootPageTable::empty(); space_fork(&mut child); let parent = activate(child);
        assert_eq!(pte_raw(active_pd(), 0xB0000), CACHE_DISABLE);
        assert!(!space_demand(0xB0000), "fork must preserve the planar trap");
        for addr in [0xA0017, 0x4100_0017, 0x4103_F000] {
            assert_ne!(pte_raw(active_pd(), addr) & WRITABLE, 0);
            assert_ne!(pte_raw(active_pd(), addr) & SHARED, 0);
            let _ = space_cow_fault(addr); // detach the table; borrowed leaf stays writable
        }
        let guest = space_translate(0xA0017).unwrap();
        unsafe { *phys::frame_ptr(u64::from(guest >> 12)).add((guest & 4095) as usize) = 0x72; }
        assert_eq!(unsafe { *phys::frame_ptr(backing).add(23) }, 0x72);
        // Mode changes replace/unmap direct windows. They must drop their
        // alias references while retaining the permanent kernel allocation.
        test_ram(0xA0, 8);
        test_remove(0xA8, 8);
        space_clean();
        activate(parent);
        assert_eq!(space_translate(0xA0017), Some(guest));
        space_clean();
        for page in backing..backing + 64 {
            assert!(!test_memory::is_shared(page), "only the kernel reference remains");
        }
        assert_eq!(unsafe { *phys::frame_ptr(backing).add(23) }, 0x72);
        test_memory::free_phys_contig(backing, 64);
    }

    #[test]
    fn long_twin_mirrors_and_tracks_changes() {
        crate::phys::init_test_ram();
        test_ram(0x10, 2);
        let pml4 = active_pml4();
        assert_eq!(
            translate64(pml4, 0x10_000),
            space_translate(0x10_000).map(u64::from),
            "twin translates a mapped page to the same frame"
        );
        assert_eq!(translate64(pml4, 0x12_000), None, "unmapped stays unmapped");
        assert_eq!(active_pml4(), pml4, "no mutation → same twin, no rebuild");
        // Mutate the source tree → the twin refreshes on next request.
        test_ram(0x12, 1);
        let pml4b = active_pml4();
        assert_eq!(
            translate64(pml4b, 0x12_000),
            space_translate(0x12_000).map(u64::from),
            "rebuilt twin sees the new page"
        );
        // Read-only source PTE mirrors as read-only (W bit clear).
        test_protect(0x10, 1, false);
        let pml4c = active_pml4();
        let pa = translate64(pml4c, 0x10_000).expect("still mapped");
        assert_eq!(pa >> 12, space_translate(0x10_000).unwrap() as u64 >> 12);
    }


    #[test]
    fn map_fork_translate() {
        crate::phys::init_test_ram();
        test_ram(0x10, 2); // vpages 0x10,0x11
        let p = space_translate(0x10_000).expect("mapped");
        // Write a marker through the frame and confirm fork copies it.
        unsafe { *phys::frame_ptr((p >> 12) as u64) = 0x7E };
        let mut child = RootPageTable::empty(); space_fork(&mut child); let _parent = activate(child);
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

        test_protect(0x10, 1, false);
        let pde = read_entry(active_pd(), pde_index(0x10_000));
        let pte = read_entry((pde >> 12) as u64, pte_index(0x10_000));
        assert_eq!(pte & WRITABLE, 0);
        test_remove(0x10, 1);
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
        crate::phys::init_test_ram();
        let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).expect("uc");
        let base = phys::frame_ptr(0);
        unsafe { uc.mem_map_ptr(0, 16<<20, Prot::ALL, base as *mut core::ffi::c_void).unwrap(); }

        let pd = new_page_dir();
        // GDT identity-mapped low so the CPL0 trampoline can load flat selectors.
        let gdt = test_memory::alloc_backed_pages(1);
        map_page(pd, frame_phys(gdt) & !0xFFF, gdt, true); // identity
        wphys(frame_phys(gdt), &[0u8;8]);
        wphys(frame_phys(gdt)+8, &flat_desc(0x9A));   // sel 0x08: ring0 code
        wphys(frame_phys(gdt)+16, &flat_desc(0x92));  // sel 0x10: ring0 data

        // CPL0 trampoline page (identity): a single `iretd` (0xCF) that pops the
        // VM86 frame below and enters the v86 task. This mirrors configure_pm:
        // VM86 is entered by IRET into a frame whose EFLAGS image has VM=1 — the
        // only architecturally valid entry, and how a real kernel does it.
        let tramp = test_memory::alloc_backed_pages(1);
        let tramp_va = 0x2000u32;
        map_page(pd, tramp_va, tramp, true);
        wphys(frame_phys(tramp), &[0xCFu8]); // iretd

        // Trampoline stack page (identity): holds the 32-bit VM86 iret frame.
        let stk = test_memory::alloc_backed_pages(1);
        let stk_va = 0x3000u32;
        map_page(pd, stk_va, stk, true);

        // VM86 code lives at linear 0x10000 (CS=0x1000, IP=0) but is mapped to a
        // NON-identity physical frame — proving the translation, not a coincidence.
        let code_frame = test_memory::alloc_backed_pages(1);
        map_page(pd, 0x10000, code_frame, true);
        // mov ax, 0x1234 (real-mode/16-bit) ; jmp $   →  B8 34 12  EB FE
        wphys(frame_phys(code_frame), &[0xB8, 0x34, 0x12, 0xEB, 0xFE]);
        // A VM86 stack so the v86 task has somewhere to point SS:SP (linear 0x1FFF0).
        let v86stk = test_memory::alloc_backed_pages(1);
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
        crate::phys::init_test_ram();

        // Code page at virtual 0x40_0000, backed by whatever frame the space
        // allocator picked (non-identity by construction).
        test_ram(0x400, 1);
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

// Typed mappings coexist with historical entries during caller migration.
// Bit 10 tags new entries so borrowed lifetime is distinct from old SHARED
// mappings, which retained an allocator reference. It is software-only.
const TYPED: u32 = 1 << 10;
const ABSENT: u32 = CACHE_DISABLE | COW;
fn owns_mapping(entry: u32) -> bool {
    (entry & PRESENT != 0 || entry & TYPED != 0)
        && !(entry & TYPED != 0 && entry & SHARED != 0)
}
fn release_mapping(entry: u32) {
    if owns_mapping(entry) { phys::release(u64::from(entry >> 12)); }
}
fn zero_frame() -> u64 { active_pd() + 2 }

/// Keep validation and the whole completed prefix within one paging transition.
pub(crate) fn mapping_batch(start: arch_abi::UserPage, count: usize,
    mut apply: impl FnMut(arch_abi::UserPage, usize) -> Result<(), arch_abi::MappingError>,
) -> Result<(), arch_abi::MappingFailure> {
    let _paging = PagingGuard::lock();
    if count != 0 {
        start.offset(count - 1).map_err(|error| arch_abi::MappingFailure { completed: 0, error })?;
    }
    for completed in 0..count {
        apply(start.offset(completed).unwrap(), completed)
            .map_err(|error| arch_abi::MappingFailure { completed, error })?;
    }
    Ok(())
}

pub(crate) fn read_mapping_run(start: arch_abi::UserPage, maximum: usize) -> Result<(arch_abi::page_entry::PageEntry, usize), arch_abi::MappingError> {
    let _paging = PagingGuard::lock();
    if maximum == 0 { return Err(arch_abi::MappingError::InvalidAddress); }
    start.offset(maximum - 1)?;
    let entry = read_mapping(start)?;
    // Bound a scan to one table; a missing table is already uniformly zero.
    let limit = maximum.min(1024 - pte_index(start.address() as u32));
    if read_entry(active_pd(), pde_index(start.address() as u32)) & PRESENT == 0 {
        return Ok((entry, limit));
    }
    let mut count = 1;
    while count < limit && read_mapping(start.offset(count)?)? == entry { count += 1; }
    Ok((entry, count))
}

pub(crate) fn read_mapping(page: arch_abi::UserPage) -> Result<arch_abi::page_entry::PageEntry, arch_abi::MappingError> {
    let _paging = PagingGuard::lock();
    use arch_abi::{MappingError, page_entry::{Attributes, Backing, Mapping, PageEntry, PhysicalFrame, X86PteFormat}};
    if page.address() >= 0xc000_0000 { return Err(MappingError::Unsupported); }
    let address = page.address() as u32;
    let mut raw = pte_raw(active_pd(), address);
    if read_entry(active_pd(), pde_index(address)) & COW != 0
        && raw & PRESENT != 0 && raw & WRITABLE != 0
        && !(raw & TYPED != 0 && raw & SHARED != 0) {
        raw = (raw & !WRITABLE) | COW;
    }
    if raw & TYPED != 0 {
        let encoded = if raw & PRESENT != 0 { raw & !TYPED } else { raw };
        return Ok(PageEntry::decode(u64::from(encoded), X86PteFormat::Legacy32, page.address())?);
    }
    if raw == ABSENT { return Ok(PageEntry::Absent); }
    if raw == 0 {
        return Ok(PageEntry::CopyOnWrite(Mapping { backing: Backing::Borrowed(PhysicalFrame::new(zero_frame())?),
            attributes: Attributes::EXECUTABLE }));
    }
    if raw & PRESENT == 0 { return Ok(PageEntry::Intercepted); }
    let mut attributes = Attributes::EXECUTABLE;
    for (mask, flag) in [(8, Attributes::WRITE_THROUGH), (16, Attributes::CACHE_DISABLE), (128, Attributes::PAT)] {
        if raw & mask != 0 { attributes = attributes | flag; }
    }
    let m = Mapping { backing: Backing::Owned(PhysicalFrame::new(u64::from(raw >> 12))?), attributes };
    Ok(if raw & COW != 0 { PageEntry::CopyOnWrite(m) }
        else if raw & WRITABLE != 0 { PageEntry::Writable(m) }
        else { PageEntry::ReadOnly(m) })
}

pub(crate) fn replace_user_mapping(page: arch_abi::UserPage, entry: arch_abi::page_entry::PageEntry) -> Result<(), arch_abi::MappingError> {
    let _paging = PagingGuard::lock();
    use arch_abi::{MappingError, page_entry::{Backing, PageEntry, X86PteFormat}};
    if page.address() >= 0xc000_0000 { return Err(MappingError::Unsupported); }
    let mut raw = entry.encode(X86PteFormat::Legacy32, page.address())? as u32;
    let mapping = match entry {
        PageEntry::Absent => { raw = ABSENT; None }
        PageEntry::Intercepted => { raw = CACHE_DISABLE; None }
        PageEntry::NoAccess(m) | PageEntry::ReadOnly(m) | PageEntry::Writable(m) | PageEntry::CopyOnWrite(m) => {
            if m.backing.frame().number() >= (phys::PHYS_SIZE / 4096) as u64 { return Err(MappingError::InvalidFrame); }
            raw |= TYPED;
            Some(m)
        }
    };
    let address = page.address() as u32;
    with_active_pd(|pd| {
        let pt = private_table(pd, pde_index(address), false).ok_or(MappingError::NeedPages)?;
        if let Some(m) = mapping {
            if let Backing::Owned(frame) = m.backing { phys::retain(frame.number()); }
        }
        let old = read_entry(pt, pte_index(address));
        write_entry(pt, pte_index(address), raw);
        release_mapping(old);
        Ok::<(), MappingError>(())
    })?;
    crate::engine::invalidate_pages(address as usize / 4096, 1);
    Ok(())
}

#[cfg(test)]
fn test_ram(base: usize, count: usize) {
    use arch_abi::{UserPage, page_entry::{PageEntry, Mapping, Backing, PhysicalFrame, Attributes}};
    for i in 0..count {
        let frame = test_memory::alloc_backed_pages(1);
        unsafe { core::ptr::write_bytes(phys::frame_ptr(frame), 0, 4096); }
        replace_user_mapping(UserPage::new(((base + i) * 4096) as u64).unwrap(), PageEntry::Writable(Mapping {
            backing: Backing::Owned(PhysicalFrame::new(frame).unwrap()), attributes: Attributes::EXECUTABLE,
        })).unwrap();
        test_memory::free_phys_page(frame);
    }
}
#[cfg(test)]
fn test_protect(base: usize, count: usize, writable: bool) {
    use arch_abi::{UserPage, page_entry::PageEntry};
    for i in 0..count {
        let page = UserPage::new(((base + i) * 4096) as u64).unwrap();
        let m = match read_mapping(page).unwrap() {
            PageEntry::ReadOnly(m) | PageEntry::Writable(m) | PageEntry::CopyOnWrite(m) => m,
            _ => panic!("backing expected"),
        };
        replace_user_mapping(page, if writable { PageEntry::CopyOnWrite(m) } else { PageEntry::ReadOnly(m) }).unwrap();
    }
}
#[cfg(test)]
fn test_remove(base: usize, count: usize) {
    for i in 0..count {
        replace_user_mapping(arch_abi::UserPage::new(((base + i) * 4096) as u64).unwrap(), arch_abi::page_entry::PageEntry::Absent).unwrap();
    }
}
#[cfg(test)]
fn test_alias(source: usize, destination: usize, count: usize) {
    for i in 0..count {
        let entry = read_mapping(arch_abi::UserPage::new(((source + i) * 4096) as u64).unwrap()).unwrap();
        replace_user_mapping(arch_abi::UserPage::new(((destination + i) * 4096) as u64).unwrap(), entry).unwrap();
    }
}

use arch_abi::{UserPage, MappingError, page_entry::{PageEntry, Backing, PhysicalFrame}};

struct Rearrangement;
impl arch_abi::mapping::Rearrange for Rearrangement {
    fn read(&mut self, page: UserPage) -> Result<PageEntry, MappingError> { read_mapping(page) }
    fn prepare(&mut self, page: UserPage) -> Result<(), MappingError> {
        let entry = self.read(page)?;
        self.replace(page, entry)
    }
    #[inline(never)]
    fn private_alias(&mut self, page: UserPage) -> Result<(), MappingError> {
        let PageEntry::CopyOnWrite(mut mapping) = self.read(page)? else { return Ok(()); };
        let frame = PhysicalFrame::new(phys::take_input().ok_or(MappingError::NeedPages)?).unwrap();
        unsafe { core::ptr::copy_nonoverlapping(phys::frame_ptr(mapping.backing.frame().number()), phys::frame_ptr(frame.number()), 4096); }
        mapping.backing = Backing::Owned(frame);
        let entry = PageEntry::Writable(mapping);
        let result = self.replace(page, entry);
        // replace retained the mapping; release our temporary owned reference.
        self.release(entry);
        result
    }
    fn replace(&mut self, page: UserPage, entry: PageEntry) -> Result<(), MappingError> { replace_user_mapping(page, entry) }
    fn retain(&mut self, entry: PageEntry) {
        if let Some(frame) = owned_backing(entry) { phys::retain(frame.number()); }
    }
    fn release(&mut self, entry: PageEntry) {
        if let Some(frame) = owned_backing(entry) { phys::release(frame.number()); }
    }
}
fn owned_backing(entry: PageEntry) -> Option<PhysicalFrame> {
    match entry {
        PageEntry::NoAccess(m) | PageEntry::ReadOnly(m) | PageEntry::Writable(m) | PageEntry::CopyOnWrite(m) => {
            match m.backing { Backing::Owned(frame) => Some(frame), Backing::Borrowed(_) => None }
        }
        _ => None,
    }
}

pub(crate) fn rearrange_mappings(a: UserPage, b: UserPage, count: usize, swap: bool) -> Result<(), MappingError> {
    let _paging = PagingGuard::lock();
    // Reject unsupported high ranges before any preparation on the low range.
    if count != 0 && (a.address() >= 0xc0000000 || b.address() >= 0xc0000000) { return Err(MappingError::Unsupported); }
    arch_abi::mapping::rearrange(&mut Rearrangement, a, b, count, swap)
}
