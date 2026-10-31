//! Address reservations and page backing. NT flag/status translation lives in RETROOS.DLL.
use super::{Api, WindowsState};
use alloc::{vec, vec::Vec};

pub(super) struct Region {
    base: u32,
    pages: Vec<Option<u32>>,
    shared: bool,
    mapped: bool,
    image: bool,
}

// Kept below the DLL slots and the legacy Win16 heap. Explicit requests outside
// this arena are rejected, never silently mapped over images or process state.
const START: u32 = 0x0100_0000;
const END: u32 = 0x1000_0000;

pub(super) fn call<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    api: Api,
    base: u32,
    size: u32,
    flags: u32,
) -> u32 {
    if api == Api::MemoryReserve {
        if size == 0 || size & 4095 != 0 || base & 65535 != 0 {
            return 0;
        }
        // The NE image, its DLL segments and resource arena occupy 16–49 MiB.
        let start = if state.win16.is_some() {
            0x0400_0000
        } else {
            START
        };
        let mut candidate = if base == 0 { start } else { base };
        loop {
            let Some(end) = candidate.checked_add(size) else {
                return 0;
            };
            if candidate < start || end > END {
                return 0;
            }
            let regions = state
                .memory
                .iter()
                .map(|r| (r.base, r.base + r.pages.len() as u32 * 4096));
            let images = state.modules.iter().filter_map(|m| {
                let image = super::pe::Image::parse(&m.data).ok()?;
                Some((m.base, m.base.checked_add(image.header.size_image)?))
            });
            let overlap = regions
                .chain(images)
                .find(|&(lo, hi)| candidate < hi && end > lo);
            if let Some((_, hi)) = overlap {
                if base != 0 {
                    return 0;
                }
                let Some(next) = hi.checked_add(65535) else {
                    return 0;
                };
                candidate = next & !65535;
                continue;
            }
            state.memory.push(Region {
                base: candidate,
                shared: false,
                mapped: false,
                image: false,
                pages: vec![None; (size / 4096) as usize],
            });
            return candidate;
        }
    }
    if api == Api::MemoryRelease {
        let Some(index) = state.memory.iter().position(|r| r.base == base) else {
            return 0;
        };
        if (state.memory[index].shared || state.memory[index].mapped) && flags != 1 {
            return 0;
        }
        let region = state.memory.remove(index);
        let end = base + region.pages.len() as u32 * 4096;
        state
            .protections
            .retain(|&(page, _)| page < base || page >= end);
        for (i, backed) in region.pages.into_iter().enumerate() {
            if backed.is_some() {
                machine.unmap_range(base as usize / 4096 + i, 1);
            }
        }
        return 1;
    }
    if size == 0 || (base | size) & 4095 != 0 || flags & !3 != 0 {
        return 0;
    }
    let Some(end) = base.checked_add(size) else {
        return 0;
    };
    let Some(region) = state
        .memory
        .iter_mut()
        .find(|r| base >= r.base && end <= r.base + r.pages.len() as u32 * 4096)
    else {
        return 0;
    };
    if region.shared || region.mapped {
        return 0;
    }
    if api == Api::MemoryDecommit {
        state
            .protections
            .retain(|&(page, _)| page < base || page >= end);
    }
    let first = ((base - region.base) / 4096) as usize;
    for i in first..first + (size / 4096) as usize {
        let address = region.base as usize + i * 4096;
        if api == Api::MemoryCommit {
            // Recommitting a page must preserve its contents and protection.
            if region.pages[i].is_none() {
                machine.zero(address, 4096);
                machine.set_page_flags(address / 4096, 1, flags & 1 != 0, flags & 2 != 0);
                region.pages[i] = Some(flags);
            }
        } else if region.pages[i].is_some() {
            machine.unmap_range(address / 4096, 1);
            region.pages[i] = None;
        }
    }
    1
}

pub(super) fn permissions(state: &WindowsState, address: u32) -> Option<u32> {
    let region = state
        .memory
        .iter()
        .find(|r| address >= r.base && address < r.base + r.pages.len() as u32 * 4096)?;
    region.pages[((address - region.base) / 4096) as usize]
}

/// Record the protection of a reservation filled with kernel-owned aliases.
pub(super) fn adopt_shared(state: &mut WindowsState, base: u32, flags: u32) {
    let region = state
        .memory
        .iter_mut()
        .find(|r| r.base == base)
        .expect("shared view reservation");
    region.shared = true;
    region.mapped = true;
    region.pages.fill(Some(flags));
}

pub(super) fn can_protect(state: &WindowsState, address: u32, write: bool, execute: bool) -> bool {
    !state.memory.iter().any(|r| {
        r.shared
            && address >= r.base
            && address < r.base + r.pages.len() as u32 * 4096
            && (write || execute)
    })
}

pub(super) fn mark_mapped(state: &mut WindowsState, base: u32) {
    if let Some(region) = state.memory.iter_mut().find(|r| r.base == base) {
        region.mapped = true;
    }
}

/// Describe a contiguous run of pages with the same state/protection.
pub(super) fn query(state: &WindowsState, address: u32) -> Option<[u32; 7]> {
    if address >= super::USER_LIMIT {
        return None;
    }
    let base = address & !4095;
    if let Some(region) = state
        .memory
        .iter()
        .find(|r| base >= r.base && base < r.base + r.pages.len() as u32 * 4096)
    {
        let first = ((base - region.base) / 4096) as usize;
        let protection = super::memory_protection(state, base).unwrap_or(0);
        let committed = region.pages[first].is_some();
        let mut end = first + 1;
        while end < region.pages.len()
            && region.pages[end].is_some() == committed
            && super::memory_protection(state, region.base + end as u32 * 4096).unwrap_or(0)
                == protection
        {
            end += 1;
        }
        return Some([
            base,
            region.base,
            super::memory_protection(state, region.base).unwrap_or(1),
            (end - first) as u32 * 4096,
            if committed { 0x1000 } else { 0x2000 },
            protection,
            if region.image {
                0x1000000
            } else if region.mapped {
                0x40000
            } else {
                0x20000
            },
        ]);
    }
    if let Some(protection) = super::memory_protection(state, base) {
        // Static images and process/thread structures are committed too.
        let image = state.modules.iter().find_map(|m| {
            let size = super::pe::Image::parse(&m.data).ok()?.header.size_image;
            (base >= m.base && base < m.base + size)
                .then_some((m.base, (m.base + size + 4095) & !4095))
        });
        let (allocation, limit) = image.unwrap_or((base, base + 4096));
        let mut end = base + 4096;
        while end < limit && super::memory_protection(state, end) == Some(protection) {
            end += 4096;
        }
        return Some([
            base,
            allocation,
            protection,
            end - base,
            0x1000,
            protection,
            if image.is_some() { 0x1000000 } else { 0x20000 },
        ]);
    }
    // Find the next reserved range without reading or allocating guest memory.
    let mut end = super::USER_LIMIT;
    for region in &state.memory {
        if region.base > base {
            end = end.min(region.base);
        }
    }
    for module in &state.modules {
        if module.base > base {
            end = end.min(module.base);
        }
    }
    for fixed in [
        state.stack_base,
        super::PROCESS_DATA,
        super::TEB_BASE,
        super::PEB_BASE,
    ] {
        if fixed > base {
            end = end.min(fixed);
        }
    }
    Some([base, 0, 0, end - base, 0x10000, 1, 0])
}

pub(super) fn mark_image(state: &mut WindowsState, base: u32) {
    if let Some(region) = state.memory.iter_mut().find(|r| r.base == base) {
        region.mapped = true;
        region.image = true;
    }
}
