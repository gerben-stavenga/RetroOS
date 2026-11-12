//! Per-address-space aliases of VFS-owned file pages.
use super::*;

#[derive(Clone, Copy)]
struct Alias { address: usize, key: vfs::mapping::Key, may_write: bool }

#[derive(Default)]
pub(super) struct State { aliases: alloc::vec::Vec<Alias> }

impl State {
    pub fn fork(&self) -> Self {
        for alias in &self.aliases { vfs::mapping::retain(alias.key); }
        Self { aliases: self.aliases.clone() }
    }

    pub fn intersects(&self, start: usize, end: usize) -> bool {
        self.aliases.iter().any(|alias| alias.address < end && alias.address + 4096 > start)
    }

    /// Guest aliases must already be unmapped (or the whole space freed).
    pub fn release<A: crate::Arch>(&mut self, machine: &mut A, start: usize, end: usize) {
        self.aliases.retain(|alias| {
            if alias.address >= start && alias.address < end {
                vfs::mapping::release(machine, alias.key);
                false
            } else { true }
        });
    }

    pub fn map<A: crate::Arch>(&mut self, machine: &mut A, handle: i32, offset: usize,
        base: usize, size: usize, protection: u64) -> Result<(), i32>
    {
        let may_write = vfs::mapping::validate(handle, offset, size, true).is_ok();
        let mut pending = alloc::vec::Vec::new();
        for page in 0..size / 4096 {
            match vfs::mapping::acquire(machine, handle, (offset + page * 4096) as u32, may_write) {
                Ok((key, pointer)) => pending.push((key, pointer)),
                Err(error) => {
                    for (key, _) in pending { vfs::mapping::release(machine, key); }
                    return Err(error);
                }
            }
        }
        // All backing pages are ready before MAP_FIXED replaces anything.
        machine.unmap_range(base / 4096, size / 4096);
        self.release(machine, base, base + size);
        for (index, &(_, frame)) in pending.iter().enumerate() {
            let address = base + index * 4096;
            if !machine.map_frame(address / 4096, frame, true, protection & 2 != 0, protection & 4 != 0) {
                machine.unmap_range(base / 4096, index);
                for (key, _) in pending { vfs::mapping::release(machine, key); }
                return Err(-12);
            }
        }
        self.aliases.extend(pending.into_iter().enumerate().map(|(index, (key, _))|
            Alias { address: base + index * 4096, key, may_write }));
        Ok(())
    }

    pub fn protect(&self, start: usize, end: usize, writable: bool) -> Result<(), i32> {
        if writable && self.aliases.iter().any(|alias|
            alias.address >= start && alias.address < end && !alias.may_write) { return Err(-13); }
        Ok(())
    }

    pub fn sync(&self, start: usize, end: usize) -> i32 {
        let mut files = alloc::collections::BTreeSet::new();
        for alias in &self.aliases {
            if alias.address >= start && alias.address < end && files.insert((alias.key.0, alias.key.1)) {
                let status = vfs::mapping::sync(alias.key);
                if status < 0 { return status; }
            }
        }
        0
    }
}

pub(super) fn msync(linux: &LinuxState, a: &Args) -> SyscallResult {
    if a.a0 & 4095 != 0 || a.a2 & !7 != 0 || a.a2 & 5 == 5 { return SyscallResult::val(-EINVAL); }
    let Some(end) = a.a0.checked_add(a.a1).and_then(|n| n.checked_add(4095)).map(|n| n & !4095)
        .filter(|end| *end <= 0xc0000000) else { return SyscallResult::val(-ENOMEM); };
    SyscallResult::val(linux.shared_mappings.sync(a.a0 as usize, end as usize))
}
