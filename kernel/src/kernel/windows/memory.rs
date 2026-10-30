//! Address reservations and page backing. NT flag/status translation lives in RETROOS.DLL.
use super::{Api, WindowsState};
use alloc::{vec, vec::Vec};

pub(super) struct Region {
    base: u32,
    pages: Vec<bool>,
}

// Kept below the DLL slots and the legacy Win16 heap. Explicit requests outside
// this arena are rejected, never silently mapped over images or process state.
const START: u32 = 0x0100_0000;
const END: u32 = 0x1000_0000;

pub(super) fn call<A: crate::Arch>(machine: &mut A, state: &mut WindowsState,
    api: Api, base: u32, size: u32, flags: u32) -> u32
{
    if api == Api::MemoryReserve {
        if size == 0 || size & 4095 != 0 || base & 65535 != 0 { return 0; }
        let mut candidate = if base == 0 { START } else { base };
        loop {
            let Some(end) = candidate.checked_add(size) else { return 0; };
            if candidate < START || end > END { return 0; }
            let regions = state.memory.iter().map(|r| (r.base, r.base + r.pages.len() as u32 * 4096));
            let images = state.modules.iter().filter_map(|m| {
                let image = super::pe::Image::parse(&m.data).ok()?;
                Some((m.base, m.base.checked_add(image.header.size_image)?))
            });
            let overlap = regions.chain(images).find(|&(lo, hi)| candidate < hi && end > lo);
            if let Some((_, hi)) = overlap {
                if base != 0 { return 0; }
                let Some(next) = hi.checked_add(65535) else { return 0; };
                candidate = next & !65535;
                continue;
            }
            state.memory.push(Region { base: candidate, pages: vec![false; (size / 4096) as usize] });
            return candidate;
        }
    }
    if api == Api::MemoryRelease {
        let Some(index) = state.memory.iter().position(|r| r.base == base) else { return 0; };
        let region = state.memory.remove(index);
        for (i, backed) in region.pages.into_iter().enumerate() {
            if backed { machine.unmap_range(base as usize / 4096 + i, 1); }
        }
        return 1;
    }
    if size == 0 || (base | size) & 4095 != 0 || flags & !3 != 0 { return 0; }
    let Some(end) = base.checked_add(size) else { return 0; };
    let Some(region) = state.memory.iter_mut().find(|r| base >= r.base && end <= r.base + r.pages.len() as u32 * 4096) else { return 0; };
    let first = ((base - region.base) / 4096) as usize;
    for i in first..first + (size / 4096) as usize {
        let address = region.base as usize + i * 4096;
        if api == Api::MemoryCommit {
            // Recommitting a page must preserve its contents and protection.
            if !region.pages[i] {
                machine.zero(address, 4096);
                machine.set_page_flags(address / 4096, 1, flags & 1 != 0, flags & 2 != 0);
                region.pages[i] = true;
            }
        } else if region.pages[i] {
            machine.unmap_range(address / 4096, 1);
            region.pages[i] = false;
        }
    }
    1
}
