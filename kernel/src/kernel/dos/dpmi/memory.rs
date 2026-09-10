//! DPMI 0.9 committed memory. There is no swap: every successful allocation
//! is backed now, not promised until a later page fault. Backend frame counts
//! therefore account for other clients too, without a second reservation ledger.

use super::state::{DpmiState, MemBlock};

const PAGE: u32 = 4096;
// Stop before the guest's fixed framebuffer aperture (and the other device
// mapping windows above it), including after repeated DPMI sessions.
const LIMIT: u32 = super::super::machine::vga::SVGA_LFB_BASE as u32;
// Keep room for kernel heap growth, DOS services, and subsequent page tables.
// This is a host-wide admission threshold, not a per-game memory limit.
const HOST_RESERVE: usize = 4 * 1024 * 1024 / PAGE as usize;
// DOS clients get a bounded memory pool, not all of the host's RAM. This
// limit is shared by all live 0501H blocks of a client; kernel/video backing
// is outside it. Actual physical availability may impose a smaller limit.
const CLIENT_PAGES: usize = 32 * 1024 * 1024 / PAGE as usize;
const NO_LINEAR: u16 = 0x8012;
const NO_PHYSICAL: u16 = 0x8013;
const NO_HANDLE: u16 = 0x8016;
const BAD_SIZE: u16 = 0x8021;
const BAD_HANDLE: u16 = 0x8023;

/// The backing operations used by the allocation service. Kept small so the
/// admission/rollback contract can be tested with a finite frame pool.
pub(super) trait Backing {
    fn free_page_count(&self) -> usize;
    fn total_page_count(&self) -> Option<usize>;
    fn map_fresh_range(&mut self, base: usize, count: usize);
    fn unmap_range(&mut self, base: usize, count: usize);
    fn swap_page_entries(&mut self, from: usize, to: usize, count: usize);
}

impl<A: crate::Arch> Backing for A {
    fn free_page_count(&self) -> usize { crate::Arch::free_page_count(self) }
    fn total_page_count(&self) -> Option<usize> { crate::Arch::total_page_count(self) }
    fn map_fresh_range(&mut self, base: usize, count: usize) { crate::Arch::map_fresh_range(self, base, count); }
    fn unmap_range(&mut self, base: usize, count: usize) { crate::Arch::unmap_range(self, base, count); }
    fn swap_page_entries(&mut self, from: usize, to: usize, count: usize) { crate::Arch::swap_page_entries(self, from, to, count); }
}

fn aligned_size(size: u32) -> Result<u32, u16> {
    if size == 0 { return Err(BAD_SIZE); }
    size.checked_add(PAGE - 1).map(|n| n & !(PAGE - 1)).ok_or(NO_LINEAR)
}

// Conservative bound for page tables on both legacy and PAE backends,
// including unaligned ends and COW of the upper levels.
fn table_pages(pages: usize) -> usize { pages.div_ceil(512) + 8 }

fn usable_pages(free: usize) -> usize {
    let available = free.saturating_sub(HOST_RESERVE);
    available.saturating_sub(table_pages(available))
}

fn remaining_pages(dpmi: &DpmiState) -> usize {
    let used: usize = dpmi.mem_blocks.iter().flatten()
        .map(|block| (block.size / PAGE) as usize).sum();
    CLIENT_PAGES.saturating_sub(used)
}

fn check_growth(dpmi: &DpmiState, bytes: u32) -> Result<(), u16> {
    if (bytes / PAGE) as usize > remaining_pages(dpmi) { return Err(NO_PHYSICAL); }
    Ok(())
}

/// First fitting hole, or the largest hole when size is None.
fn hole(blocks: &[Option<MemBlock>], start: u32, size: Option<u32>) -> Option<(u32, u32)> {
    let mut base = start;
    let mut largest = None;
    while base < LIMIT {
        let next = blocks.iter().flatten().filter(|b| b.base >= base).min_by_key(|b| b.base);
        let end = next.map_or(LIMIT, |b| b.base);
        let length = end - base;
        if size.is_some_and(|n| n <= length) { return Some((base, length)); }
        if length > largest.map_or(0, |(_, n)| n) { largest = Some((base, length)); }
        match next {
            Some(b) => base = b.base.checked_add(b.size)?,
            None => break,
        }
    }
    if size.is_none() { largest } else { None }
}

pub(super) fn info<A: Backing>(machine: &A, dpmi: &DpmiState) -> [u32; 12] {
    let free = machine.free_page_count();
    let linear = hole(&dpmi.mem_blocks, dpmi.mem_start, None).map_or(0, |(_, n)| n / PAGE);
    let max = if dpmi.mem_blocks.iter().any(Option::is_none) {
        usable_pages(free).min(remaining_pages(dpmi)).min(linear as usize) as u32
    } else { 0 };
    let mut info = [u32::MAX; 12];
    info[0] = max * PAGE;
    info[1] = max;
    info[2] = max;
    // Linear-space fields are optional in 0.9; leave unknown rather than
    // describing unrelated mappings outside this allocation arena.
    // With no swap, the available physical/pageable pool is the same pool
    // admitted by 0501H. Do not expose host-reserved or over-quota frames here:
    // clients can size allocations from these counts, not just info[0].
    info[4] = max;
    info[5] = max;
    info[6] = machine.total_page_count().map_or(u32::MAX, |n| n.min(u32::MAX as usize) as u32);
    info[8] = 0; // no paging file
    info
}

fn commit<A: Backing>(machine: &mut A, base: u32, size: u32, address_pages: usize) -> Result<(), u16> {
    let pages = (size / PAGE) as usize;
    let needed = pages + table_pages(address_pages) + HOST_RESERVE;
    if needed > machine.free_page_count() { return Err(NO_PHYSICAL); }
    // Kernel services run synchronously; no other client can allocate between
    // this preflight and the mapping. The table allowance covers paging work
    // performed by map_fresh_range and, on relocation, swap_page_entries.
    machine.map_fresh_range((base / PAGE) as usize, pages);
    Ok(())
}

pub(super) fn allocate<A: Backing>(machine: &mut A, dpmi: &mut DpmiState, size: u32) -> Result<u32, u16> {
    let size = aligned_size(size)?;
    let slot = dpmi.mem_blocks.iter().position(Option::is_none).ok_or(NO_HANDLE)?;
    check_growth(dpmi, size)?;
    let base = hole(&dpmi.mem_blocks, dpmi.mem_start, Some(size)).ok_or(NO_LINEAR)?.0;
    commit(machine, base, size, (size / PAGE) as usize)?;
    dpmi.mem_blocks[slot] = Some(MemBlock { base, size });
    dpmi.mem_next = dpmi.mem_next.max(base + size);
    Ok(base)
}

pub(super) fn free<A: Backing>(machine: &mut A, dpmi: &mut DpmiState, handle: u32) -> Result<(), u16> {
    let slot = dpmi.mem_blocks.iter().position(|b| b.is_some_and(|b| b.base == handle)).ok_or(BAD_HANDLE)?;
    let block = dpmi.mem_blocks[slot].unwrap();
    machine.unmap_range((block.base / PAGE) as usize, (block.size / PAGE) as usize);
    dpmi.mem_blocks[slot] = None;
    Ok(())
}

pub(super) fn resize<A: Backing>(machine: &mut A, dpmi: &mut DpmiState, handle: u32, size: u32) -> Result<u32, u16> {
    let size = aligned_size(size)?;
    let slot = dpmi.mem_blocks.iter().position(|b| b.is_some_and(|b| b.base == handle)).ok_or(BAD_HANDLE)?;
    let old = dpmi.mem_blocks[slot].unwrap();
    let base = if size <= old.size {
        if size < old.size {
            machine.unmap_range(((old.base + size) / PAGE) as usize, ((old.size - size) / PAGE) as usize);
        }
        old.base
    } else {
        check_growth(dpmi, size - old.size)?;
        let end = old.base.checked_add(size).filter(|&end| end <= LIMIT);
        let in_place = end.is_some_and(|end| !dpmi.mem_blocks.iter().flatten()
            .any(|b| b.base != old.base && b.base < end && b.base + b.size > old.base));
        let base = if in_place { old.base } else {
            hole(&dpmi.mem_blocks, dpmi.mem_start, Some(size)).ok_or(NO_LINEAR)?.0
        };
        commit(machine, base + old.size, size - old.size, (size / PAGE) as usize)?;
        if base != old.base {
            // Move the old backing, preserving its contents and attributes;
            // no temporary second copy of the old block consumes RAM.
            machine.swap_page_entries((old.base / PAGE) as usize, (base / PAGE) as usize, (old.size / PAGE) as usize);
        }
        base
    };
    dpmi.mem_blocks[slot] = Some(MemBlock { base, size });
    dpmi.mem_next = dpmi.mem_next.max(base + size);
    Ok(base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    struct Pool {
        free: usize,
        // One sentinel word per mapped page is sufficient to check that resize
        // preserves backing rather than replacing the old data with zeroes.
        pages: BTreeMap<usize, u32>,
    }
    impl Pool {
        fn new() -> Self { Self { free: 8192, pages: BTreeMap::new() } }
    }
    impl Backing for Pool {
        fn free_page_count(&self) -> usize { self.free }
        fn total_page_count(&self) -> Option<usize> { Some(8192) }
        fn map_fresh_range(&mut self, base: usize, count: usize) {
            assert!(self.free >= count);
            for page in base..base + count { assert!(self.pages.insert(page, 0).is_none()); }
            self.free -= count;
        }
        fn unmap_range(&mut self, base: usize, count: usize) {
            for page in base..base + count { assert!(self.pages.remove(&page).is_some()); }
            self.free += count;
        }
        fn swap_page_entries(&mut self, from: usize, to: usize, count: usize) {
            for i in 0..count {
                let word = self.pages.remove(&(from + i)).unwrap();
                assert!(self.pages.insert(to + i, word).is_none());
            }
        }
    }

    #[test]
    fn commits_reclaims_and_reuses_the_same_hole() {
        let mut pool = Pool::new();
        let mut dpmi = DpmiState::new();
        let report = info(&pool, &dpmi);
        assert_eq!(report[5], report[0] / PAGE);
        assert_eq!(report[6], 8192);
        assert_eq!(report[8], 0);
        let base = allocate(&mut pool, &mut dpmi, 3 * PAGE).unwrap();
        assert_eq!(pool.free, 8192 - 3);
        assert!(info(&pool, &dpmi)[0] < report[0]);
        resize(&mut pool, &mut dpmi, base, PAGE).unwrap();
        assert_eq!(pool.free, 8191);
        free(&mut pool, &mut dpmi, base).unwrap();
        assert_eq!(pool.free, 8192);
        assert_eq!(info(&pool, &dpmi), report);
        assert_eq!(allocate(&mut pool, &mut dpmi, 3 * PAGE), Ok(base));
    }

    #[test]
    fn grows_in_place_or_moves_without_overwriting_a_neighbor() {
        let mut pool = Pool::new();
        let mut dpmi = DpmiState::new();
        let base = allocate(&mut pool, &mut dpmi, PAGE).unwrap();
        pool.pages.insert((base / PAGE) as usize, 0x12345678);
        assert_eq!(resize(&mut pool, &mut dpmi, base, 2 * PAGE), Ok(base));
        let neighbor = allocate(&mut pool, &mut dpmi, PAGE).unwrap();
        pool.pages.insert((neighbor / PAGE) as usize, 0x87654321);
        let moved = resize(&mut pool, &mut dpmi, base, 4 * PAGE).unwrap();
        assert_ne!(moved, base);
        assert_eq!(pool.pages[&((moved / PAGE) as usize)], 0x12345678);
        assert_eq!(pool.pages[&((neighbor / PAGE) as usize)], 0x87654321);
        assert_eq!(pool.free, 8192 - 5);
        assert_eq!(free(&mut pool, &mut dpmi, base), Err(BAD_HANDLE));
    }

    #[test]
    fn exhaustion_and_invalid_requests_leave_the_old_block_unchanged() {
        let mut pool = Pool::new();
        let mut dpmi = DpmiState::new();
        let base = allocate(&mut pool, &mut dpmi, PAGE).unwrap();
        let next = dpmi.mem_next;
        pool.free = HOST_RESERVE + 8; // other users consumed the remaining frames
        let report = info(&pool, &dpmi);
        assert_eq!(report[0], 0);
        assert_eq!(allocate(&mut pool, &mut dpmi, PAGE), Err(NO_PHYSICAL));
        assert_eq!(resize(&mut pool, &mut dpmi, base, 2 * PAGE), Err(NO_PHYSICAL));
        assert_eq!(resize(&mut pool, &mut dpmi, base, 0), Err(BAD_SIZE));
        assert_eq!(allocate(&mut pool, &mut dpmi, u32::MAX), Err(NO_LINEAR));
        assert_eq!(dpmi.mem_next, next);
        assert_eq!(pool.pages.len(), 1);
        assert_eq!(dpmi.mem_blocks[0].unwrap().size, PAGE);
        assert_eq!(info(&pool, &dpmi), report);
    }

    #[test]
    fn rejects_zero_and_overflow() {
        assert_eq!(aligned_size(0), Err(BAD_SIZE));
        assert_eq!(aligned_size(u32::MAX), Err(NO_LINEAR));
        assert_eq!(aligned_size(1), Ok(PAGE));
        assert_eq!(aligned_size(PAGE + 1), Ok(2 * PAGE));
    }

    #[test]
    fn admission_preserves_host_and_table_budget() {
        for free in [0, HOST_RESERVE - 1, HOST_RESERVE, 8192, 65536] {
            let usable = usable_pages(free);
            if usable != 0 { assert!(usable + table_pages(usable) + HOST_RESERVE <= free); }
            else { assert!(free <= HOST_RESERVE + table_pages(free)); }
        }
    }

    #[test]
    fn client_budget_is_shared_by_blocks_and_reclaimed_on_shrink_and_free() {
        let mut pool = Pool::new();
        pool.free = 65536; // abundant host RAM must not enlarge the DOS pool
        let mut dpmi = DpmiState::new();
        let budget = CLIENT_PAGES as u32 * PAGE;
        assert_eq!(&info(&pool, &dpmi)[..3], &[budget, CLIENT_PAGES as u32, CLIENT_PAGES as u32]);
        let a = allocate(&mut pool, &mut dpmi, budget / 2).unwrap();
        assert_eq!(info(&pool, &dpmi)[0], budget / 2);
        let b = allocate(&mut pool, &mut dpmi, budget / 2).unwrap();
        let free_before = pool.free;
        let next_before = dpmi.mem_next;
        assert_eq!(info(&pool, &dpmi)[0], 0);
        assert_eq!(allocate(&mut pool, &mut dpmi, 1), Err(NO_PHYSICAL));
        assert_eq!(resize(&mut pool, &mut dpmi, b, budget / 2 + 1), Err(NO_PHYSICAL));
        assert_eq!(pool.free, free_before);
        assert_eq!(dpmi.mem_next, next_before);
        assert_eq!(dpmi.mem_blocks[1].unwrap().size, budget / 2);
        resize(&mut pool, &mut dpmi, a, budget / 2 - PAGE).unwrap();
        assert_eq!(info(&pool, &dpmi)[0], PAGE);
        resize(&mut pool, &mut dpmi, b, budget / 2 + PAGE).unwrap();
        assert_eq!(info(&pool, &dpmi)[0], 0);
        free(&mut pool, &mut dpmi, a).unwrap();
        assert_eq!(info(&pool, &dpmi)[0], budget / 2 - PAGE);
        free(&mut pool, &mut dpmi, b).unwrap();
        assert_eq!(info(&pool, &dpmi)[0], budget);
    }

    #[test]
    fn client_budget_cannot_be_bypassed_by_one_oversized_request() {
        let mut pool = Pool::new();
        pool.free = 65536;
        let mut dpmi = DpmiState::new();
        let budget = CLIENT_PAGES as u32 * PAGE;
        assert_eq!(allocate(&mut pool, &mut dpmi, budget + 1), Err(NO_PHYSICAL));
        assert!(pool.pages.is_empty());
        assert_eq!(pool.free, 65536);
        let base = allocate(&mut pool, &mut dpmi, budget).unwrap();
        assert_eq!(info(&pool, &dpmi)[0], 0);
        assert_eq!(resize(&mut pool, &mut dpmi, base, budget + 1), Err(NO_PHYSICAL));
        assert_eq!(resize(&mut pool, &mut dpmi, base, budget), Ok(base));
    }

    #[test]
    fn backing_availability_can_limit_a_client_below_32_mib() {
        let mut pool = Pool::new();
        pool.free = HOST_RESERVE + 128;
        let mut dpmi = DpmiState::new();
        let offered = info(&pool, &dpmi)[0];
        assert!(offered < CLIENT_PAGES as u32 * PAGE);
        allocate(&mut pool, &mut dpmi, offered).unwrap();
        assert_eq!(info(&pool, &dpmi)[0], 0);
        assert_eq!(allocate(&mut pool, &mut dpmi, PAGE), Err(NO_PHYSICAL));
    }

    #[test]
    fn reported_free_physical_pages_can_be_allocated() {
        for host_free in [HOST_RESERVE + 128, 8192, 65536] {
            let mut pool = Pool::new();
            pool.free = host_free;
            let mut dpmi = DpmiState::new();
            let initial = info(&pool, &dpmi);
            let a = allocate(&mut pool, &mut dpmi, initial[5] / 2 * PAGE).unwrap();
            let available = info(&pool, &dpmi);
            assert!(available[5] < initial[5]);
            assert_eq!(available[4], available[5]);
            assert_eq!(available[5] * PAGE, available[0]);
            // An extender may request the entire +14h free-page count.
            let b = allocate(&mut pool, &mut dpmi, available[5] * PAGE).unwrap();
            let exhausted = info(&pool, &dpmi);
            assert!(exhausted[5] < available[5]);
            for field in [1, 2, 4, 5] {
                assert_eq!(exhausted[field] * PAGE, exhausted[0]);
            }
            // Physical admission is conservative about future page tables;
            // the mock does not charge those frames. Quota exhaustion is exact.
            if host_free == 65536 { assert_eq!(exhausted[5], 0); }
            resize(&mut pool, &mut dpmi, b, PAGE).unwrap();
            let shrunk = info(&pool, &dpmi);
            assert!(shrunk[5] > 0);
            assert_eq!(shrunk[4], shrunk[5]);
            assert_eq!(shrunk[5] * PAGE, shrunk[0]);
            free(&mut pool, &mut dpmi, a).unwrap();
            free(&mut pool, &mut dpmi, b).unwrap();
            assert_eq!(info(&pool, &dpmi), initial);
            assert_eq!(initial[6], 8192); // physical total is not the free pool
        }
    }

    #[test]
    fn holes_reused_without_overlapping_live_blocks() {
        let base = super::super::state::MEM_BASE;
        let mut blocks = [Some(MemBlock { base: base + 3 * PAGE, size: PAGE }),
            Some(MemBlock { base, size: PAGE })];
        assert_eq!(hole(&blocks, base, Some(2 * PAGE)), Some((base + PAGE, 2 * PAGE)));
        assert_eq!(hole(&blocks, base, Some(3 * PAGE)).unwrap().0, base + 4 * PAGE);
        blocks[1] = None;
        assert_eq!(hole(&blocks, base, Some(3 * PAGE)), Some((base, 3 * PAGE)));
        assert!(hole(&blocks, LIMIT - PAGE, Some(2 * PAGE)).is_none());
    }
}
