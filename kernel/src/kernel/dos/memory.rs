//! Extended-memory ownership for one DOS personality/address space.
//!
//! XMS, EMS and DPMI are protocols, not independent supplies of RAM.  This
//! manager is their common committed page pool: it owns every extended linear
//! range, accounts one guest-wide quota, and returns frames immediately when a
//! block is released.  Protocol modules retain only handles and presentation.

const PAGE: u32 = 4096;
const GENERAL_BASE: u32 = 0x0050_0000;
const LIMIT: u32 = super::machine::vga::SVGA_LFB_BASE as u32;
const HOST_RESERVE: usize = 4 * 1024 * 1024 / PAGE as usize;
const CLIENT_PAGES: usize = 32 * 1024 * 1024 / PAGE as usize;
const MAX_BLOCKS: usize = 512;

pub const XMS_OWNER: Owner = Owner(1);
pub const EMS_OWNER: Owner = Owner(2);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Owner(u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Block {
    pub base: u32,
    /// Page-rounded committed size.
    pub size: u32,
    owner: Owner,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error { BadSize, NoLinear, NoPhysical, NoSlots, BadHandle }

/// Small backing seam so allocator policy is host-testable independently of
/// the metal/interpreter page-table implementations.
pub trait Backing {
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

pub struct DosMemory {
    blocks: alloc::vec::Vec<Block>,
    next_owner: u32,
    general_high_water: u32,
}

impl DosMemory {
    pub const fn new() -> Self {
        Self { blocks: alloc::vec::Vec::new(), next_owner: 3, general_high_water: GENERAL_BASE }
    }

    /// Give a new DPMI session an independent ownership domain. Its first
    /// allocation starts on a MiB boundary above all older general blocks,
    /// retaining the DOS/4GW/CWSDPMI slab-origin convention across nested EXEC.
    pub fn new_dpmi_owner(&mut self) -> (Owner, u32) {
        let owner = Owner(self.next_owner);
        self.next_owner = self.next_owner.wrapping_add(1).max(3);
        let start = align_up(self.general_high_water.max(GENERAL_BASE), 0x10_0000)
            .unwrap_or(LIMIT);
        self.general_high_water = start;
        (owner, start)
    }

    pub fn owner_blocks(&self, owner: Owner) -> usize {
        self.blocks.iter().filter(|b| b.owner == owner).count()
    }

    pub fn allocate<A: Backing>(
        &mut self,
        machine: &mut A,
        owner: Owner,
        bytes: u32,
        alignment: u32,
        lower: u32,
        upper: u32,
    ) -> Result<Block, Error> {
        let size = aligned_size(bytes)?;
        if self.blocks.len() >= MAX_BLOCKS { return Err(Error::NoSlots); }
        if size as usize / PAGE as usize > self.available_pages(machine) {
            return Err(Error::NoPhysical);
        }
        let base = self.hole(lower, upper, alignment.max(PAGE), Some(size))
            .map(|(base, _)| base).ok_or(Error::NoLinear)?;
        commit(machine, base, size)?;
        let block = Block { base, size, owner };
        self.blocks.push(block);
        if base >= GENERAL_BASE {
            self.general_high_water = self.general_high_water.max(base + size);
        }
        Ok(block)
    }

    pub fn free<A: Backing>(&mut self, machine: &mut A, owner: Owner, base: u32) -> Result<(), Error> {
        let index = self.blocks.iter().position(|b| b.owner == owner && b.base == base)
            .ok_or(Error::BadHandle)?;
        let block = self.blocks.swap_remove(index);
        machine.unmap_range((block.base / PAGE) as usize, (block.size / PAGE) as usize);
        Ok(())
    }

    pub fn release_owner<A: Backing>(&mut self, machine: &mut A, owner: Owner) {
        let mut index = 0;
        while index < self.blocks.len() {
            if self.blocks[index].owner == owner {
                let block = self.blocks.swap_remove(index);
                machine.unmap_range((block.base / PAGE) as usize, (block.size / PAGE) as usize);
            } else {
                index += 1;
            }
        }
    }

    pub fn resize<A: Backing>(
        &mut self,
        machine: &mut A,
        owner: Owner,
        base: u32,
        bytes: u32,
        alignment: u32,
        lower: u32,
        upper: u32,
    ) -> Result<Block, Error> {
        let size = aligned_size(bytes)?;
        let index = self.blocks.iter().position(|b| b.owner == owner && b.base == base)
            .ok_or(Error::BadHandle)?;
        let old = self.blocks[index];
        if size == old.size { return Ok(old); }
        if size < old.size {
            machine.unmap_range(((old.base + size) / PAGE) as usize, ((old.size - size) / PAGE) as usize);
            self.blocks[index].size = size;
            return Ok(self.blocks[index]);
        }
        let growth = size - old.size;
        if growth as usize / PAGE as usize > self.available_pages(machine) {
            return Err(Error::NoPhysical);
        }
        let end = old.base.checked_add(size).filter(|&end| end <= upper);
        let in_place = old.base >= lower && end.is_some_and(|end| !self.blocks.iter().enumerate()
            .any(|(i, b)| i != index && b.base < end && b.base + b.size > old.base));
        let new_base = if in_place {
            old.base
        } else {
            self.hole(lower, upper, alignment.max(PAGE), Some(size))
                .map(|(base, _)| base).ok_or(Error::NoLinear)?
        };
        commit(machine, new_base + old.size, growth)?;
        if new_base != old.base {
            machine.swap_page_entries(
                (old.base / PAGE) as usize,
                (new_base / PAGE) as usize,
                (old.size / PAGE) as usize,
            );
        }
        self.blocks[index].base = new_base;
        self.blocks[index].size = size;
        self.general_high_water = self.general_high_water.max(new_base + size);
        Ok(self.blocks[index])
    }

    pub fn available_pages<A: Backing>(&self, machine: &A) -> usize {
        let used: usize = self.blocks.iter().map(|b| (b.size / PAGE) as usize).sum();
        quota_remaining(used).min(usable_pages(machine.free_page_count()))
    }

    pub fn largest_bytes<A: Backing>(&self, machine: &A, lower: u32, upper: u32, alignment: u32) -> u32 {
        let linear = self.hole(lower, upper, alignment.max(PAGE), None).map_or(0, |(_, n)| n);
        linear.min((self.available_pages(machine).min(u32::MAX as usize / PAGE as usize) as u32) * PAGE)
    }

    pub fn total_page_count<A: Backing>(&self, machine: &A) -> Option<usize> {
        machine.total_page_count()
    }

    fn hole(&self, lower: u32, upper: u32, alignment: u32, wanted: Option<u32>) -> Option<(u32, u32)> {
        if lower >= upper || !alignment.is_power_of_two() { return None; }
        let mut ranges: alloc::vec::Vec<Block> = self.blocks.iter().copied()
            .filter(|b| b.base < upper && b.base + b.size > lower).collect();
        ranges.sort_unstable_by_key(|b| b.base);
        let mut cursor = align_up(lower, alignment)?;
        let mut largest = None;
        for block in ranges {
            let end = block.base.min(upper);
            let length = end.saturating_sub(cursor);
            if wanted.is_some_and(|size| size <= length) { return Some((cursor, length)); }
            if length > largest.map_or(0, |(_, n)| n) { largest = Some((cursor, length)); }
            cursor = align_up(cursor.max(block.base.saturating_add(block.size)), alignment)?;
            if cursor >= upper { break; }
        }
        let length = upper.saturating_sub(cursor);
        if wanted.is_some_and(|size| size <= length) { return Some((cursor, length)); }
        if length > largest.map_or(0, |(_, n)| n) { largest = Some((cursor, length)); }
        wanted.map_or(largest, |_| None)
    }
}

pub const fn general_limit() -> u32 { LIMIT }
pub const fn client_bytes() -> u32 { CLIENT_PAGES as u32 * PAGE }

fn aligned_size(bytes: u32) -> Result<u32, Error> {
    if bytes == 0 { return Err(Error::BadSize); }
    bytes.checked_add(PAGE - 1).map(|n| n & !(PAGE - 1)).ok_or(Error::NoLinear)
}

fn align_up(value: u32, alignment: u32) -> Option<u32> {
    value.checked_add(alignment - 1).map(|n| n & !(alignment - 1))
}

fn table_pages(pages: usize) -> usize { pages.div_ceil(512) + 8 }
fn usable_pages(free: usize) -> usize {
    let available = free.saturating_sub(HOST_RESERVE);
    available.saturating_sub(table_pages(available))
}
fn quota_remaining(used: usize) -> usize { CLIENT_PAGES.saturating_sub(used) }

fn commit<A: Backing>(machine: &mut A, base: u32, size: u32) -> Result<(), Error> {
    let pages = (size / PAGE) as usize;
    let needed = pages + table_pages(pages) + HOST_RESERVE;
    if needed > machine.free_page_count() { return Err(Error::NoPhysical); }
    machine.map_fresh_range((base / PAGE) as usize, pages);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    struct Pool {
        free: usize,
        pages: BTreeMap<usize, u32>,
    }

    impl Pool {
        fn new() -> Self { Self { free: 65536, pages: BTreeMap::new() } }
    }

    impl Backing for Pool {
        fn free_page_count(&self) -> usize { self.free }
        fn total_page_count(&self) -> Option<usize> { Some(65536) }
        fn map_fresh_range(&mut self, base: usize, count: usize) {
            for page in base..base + count {
                assert!(self.pages.insert(page, 0).is_none());
            }
            self.free -= count;
        }
        fn unmap_range(&mut self, base: usize, count: usize) {
            for page in base..base + count {
                assert!(self.pages.remove(&page).is_some());
            }
            self.free += count;
        }
        fn swap_page_entries(&mut self, from: usize, to: usize, count: usize) {
            for offset in 0..count {
                let value = self.pages.remove(&(from + offset)).unwrap();
                assert!(self.pages.insert(to + offset, value).is_none());
            }
        }
    }

    #[test]
    fn protocols_share_one_nonoverlapping_arena_and_quota() {
        let mut pool = Pool::new();
        let mut memory = DosMemory::new();
        let xms = memory.allocate(&mut pool, XMS_OWNER, PAGE, PAGE,
            0x120000, general_limit()).unwrap();
        let ems = memory.allocate(&mut pool, EMS_OWNER, 16 * 1024, 16 * 1024,
            GENERAL_BASE, general_limit()).unwrap();
        let (dpmi, start) = memory.new_dpmi_owner();
        let block = memory.allocate(&mut pool, dpmi, PAGE, PAGE,
            start, general_limit()).unwrap();

        assert_eq!(xms.base, 0x120000);
        assert_eq!(ems.base, GENERAL_BASE);
        assert_eq!(start & 0xFFFFF, 0);
        assert!(block.base >= ems.base + ems.size);
        assert_eq!(memory.available_pages(&pool), CLIENT_PAGES - 6);
    }

    #[test]
    fn free_and_resize_reclaim_pages_and_preserve_contents() {
        let mut pool = Pool::new();
        let mut memory = DosMemory::new();
        let (owner, start) = memory.new_dpmi_owner();
        let first = memory.allocate(&mut pool, owner, PAGE, PAGE, start, general_limit()).unwrap();
        pool.pages.insert((first.base / PAGE) as usize, 0x1234_5678);
        let neighbor = memory.allocate(&mut pool, owner, PAGE, PAGE, start, general_limit()).unwrap();
        let moved = memory.resize(&mut pool, owner, first.base, 3 * PAGE, PAGE,
            start, general_limit()).unwrap();
        assert_ne!(moved.base, first.base);
        assert_eq!(pool.pages[&((moved.base / PAGE) as usize)], 0x1234_5678);
        memory.free(&mut pool, owner, neighbor.base).unwrap();
        memory.release_owner(&mut pool, owner);
        assert!(pool.pages.is_empty());
        assert_eq!(pool.free, 65536);
    }
}
