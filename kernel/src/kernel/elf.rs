//! ELF executable loader
//!
//! Uses lib::elf for parsing, handles memory mapping.
//! Eager segment frames are installed in batches before payload copies.

const PAGE_SIZE: usize = 4096;
extern crate alloc;
use alloc::vec::Vec;
pub use lib::elf::{ElfError, ElfClass};

/// True if `elf_data` is a 64-bit ELF (EI_CLASS = ELFCLASS64). Cheap ident
/// peek for the exec-time capability check — a 64-bit image on a backend
/// without 64-bit user execution must fail with ENOEXEC, not run misdecoded.
pub fn is_class64(elf_data: &[u8]) -> bool {
    elf_data.len() > 4 && elf_data[4] == 2
}

/// Peek at an ELF's dynamic-linking info without loading it:
/// `(is_pie /* ET_DYN */, PT_INTERP path if dynamically linked)`.
pub fn dyn_info(elf_data: &[u8]) -> Result<(bool, Option<Vec<u8>>), ElfError> {
    let elf = lib::elf::Elf::parse(elf_data)?;
    let is_pie = elf.elf_type() == 3; // ET_DYN
    let interp = elf.interp().map(|s| s.to_vec());
    Ok((is_pie, interp))
}

/// User stack top address (just below kernel space)
pub const USER_STACK_TOP: usize = 0xC000_0000;

fn load_page_ranges(segments: impl Iterator<Item = (usize, usize)>, bias: usize) -> Result<Vec<(usize, usize)>, ElfError> {
    let mut ranges = Vec::new();
    for (address, length) in segments {
        if length == 0 { continue; }
        let start = address.checked_add(bias).ok_or(ElfError::InvalidType)?;
        let end = start.checked_add(length).filter(|end| *end <= USER_STACK_TOP)
            .ok_or(ElfError::InvalidType)?;
        ranges.push((start / PAGE_SIZE, end.div_ceil(PAGE_SIZE)));
    }
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut() && start <= last.1 {
            last.1 = last.1.max(end);
        } else { merged.push((start, end)); }
    }
    Ok(merged)
}


/// Loaded ELF info
pub struct LoadedElf {
    pub entry: u64,
    pub class: ElfClass,
    /// Highest virtual address used by any PT_LOAD segment (page-aligned up)
    pub max_vaddr: usize,
    /// Address of the program header table in the loaded image
    /// (`load_bias + e_phoff`) — the dynamic linker's `AT_PHDR`.
    pub phdr_vaddr: usize,
    /// `AT_PHENT` / `AT_PHNUM` — program-header entry size and count.
    pub phentsize: usize,
    pub phnum: usize,
}

/// Load an ELF executable into user address space at `load_bias` (0 for a
/// fixed-address `ET_EXEC`; a nonzero base for a PIE / `ET_DYN` such as a
/// modern distro binary or the dynamic linker itself). Relocations are NOT
/// applied here — for dynamically-linked images the interpreter (ld.so) does
/// that; `load_bias` only places the segments.
pub(crate) fn load_elf_source<A: crate::Arch>(machine: &mut A, elf_data: &[u8], load_bias: usize, source: Option<&crate::kernel::exec::ExecutableFile>) -> Result<LoadedElf, ElfError> {
    let elf = lib::elf::Elf::parse(elf_data)?;
    // Adjacent PT_LOAD segments may share a page. Allocate the union before
    // copying any payload, so a later segment cannot clear an earlier one.
    let ranges = load_page_ranges(elf.segments().map(|s| (s.vaddr, s.memsz)), load_bias)?;
    let sample = crate::kernel::event_profile::file_io_start();
    let mut allocated = 0;
    for (start, end) in ranges {
        machine.map_fresh_range(start, end - start);
        allocated += (end - start) * PAGE_SIZE;
    }
    crate::kernel::event_profile::file_io_finish(6, allocated, sample);

    let mut max_vaddr = 0usize;

    // First pass: copy data into the active address space through the vcpu
    // (frames were installed above). Going through the vcpu's guest-memory
    // API — rather than dereferencing `seg.vaddr` as a host pointer — is what
    // keeps this loader backend-agnostic: on metal the guest VA is a valid
    // kernel pointer, while on the interpreter it indexes the software MMU's
    // address space.
    let mut scratch = source.map(|_| alloc::vec![0u8; 64 * 1024]);
    for seg in elf.segments() {
        let vaddr = seg.vaddr.checked_add(load_bias).ok_or(ElfError::InvalidType)?;
        let end = vaddr.checked_add(seg.memsz).ok_or(ElfError::InvalidType)?;
        if seg.filesz > seg.memsz { return Err(ElfError::InvalidType); }
        if end > max_vaddr { max_vaddr = end; }
        if let Some(source) = source {
            let scratch = scratch.as_mut().unwrap();
            let mut copied = 0;
            // Full interior pages can alias the unified file cache. Boundary
            // pages remain private: zeroing BSS must not change cached bytes
            // or another segment that shares the same destination page.
            if vaddr % PAGE_SIZE == seg.file_offset % PAGE_SIZE {
                let prefix = (PAGE_SIZE - vaddr % PAGE_SIZE) % PAGE_SIZE;
                let first = prefix.min(seg.filesz);
                if first > 0 {
                    source.read_exact(seg.file_offset, &mut scratch[..first]).map_err(|_| ElfError::InvalidType)?;
                    machine.copy_to(vaddr, &scratch[..first]);
                }
                copied = first;
                let full = (seg.filesz - copied) / PAGE_SIZE * PAGE_SIZE;
                if full > 0 {
                    source.map_private(machine, seg.file_offset + copied, vaddr + copied, full,
                        2 | if seg.is_executable() { 4 } else { 0 }).map_err(|_| ElfError::InvalidType)?;
                    copied += full;
                }
            }
            while copied < seg.filesz {
                let count = (seg.filesz - copied).min(scratch.len());
                let offset = seg.file_offset.checked_add(copied).ok_or(ElfError::InvalidType)?;
                let sample = crate::kernel::event_profile::file_io_start();
                let result = source.read_exact(offset, &mut scratch[..count]);
                crate::kernel::event_profile::file_io_finish(7, count, sample);
                result.map_err(|_| ElfError::InvalidType)?;
                let sample = crate::kernel::event_profile::file_io_start();
                machine.copy_to(vaddr + copied, &scratch[..count]);
                crate::kernel::event_profile::file_io_finish(8, count, sample);
                copied += count;
            }
        } else if seg.filesz > 0 {
            let data = seg.data.ok_or(ElfError::InvalidType)?;
            machine.copy_to(vaddr, data);
        }
        if seg.memsz > seg.filesz {
            machine.zero(vaddr + seg.filesz, seg.memsz - seg.filesz);
        }
    }

    // Second pass: set final permissions based on segment flags.
    // Process non-executable segments first so executable wins on shared pages.
    for executable_pass in [false, true] {
        for seg in elf.segments() {
            if seg.is_executable() != executable_pass { continue; }
            let vaddr = seg.vaddr + load_bias;
            let start_page = vaddr / PAGE_SIZE;
            let end_page = (vaddr + seg.memsz).div_ceil(PAGE_SIZE);
            let count = end_page - start_page;
            if count > 0 {
                machine.set_page_flags(start_page, count, seg.is_writable(), executable_pass);
            }
        }
    }

    // Page-align max_vaddr up for use as heap base
    max_vaddr = (max_vaddr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let (phoff, phentsize, phnum) = elf.ph_table_info();
    let phdr_vaddr = elf.segments().find_map(|seg| {
        let file_offset = seg.file_offset;
        if phoff >= file_offset && phoff + phentsize * phnum <= file_offset + seg.filesz {
            Some(load_bias + seg.vaddr + phoff - file_offset)
        } else { None }
    }).unwrap_or(0);
    Ok(LoadedElf {
        entry: elf.entry() + load_bias as u64,
        class: elf.class(),
        max_vaddr,
        phdr_vaddr,
        phentsize,
        phnum,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn eager_elf_frames_preserve_shared_segment_pages_and_sparse_holes() {
        assert_eq!(load_page_ranges([(0x1801, 0x1000), (0x2100, 0x1400), (0x8000, 1), (0, 0)].into_iter(), 0x10000).unwrap(),
            alloc::vec![(0x11, 0x14), (0x18, 0x19)]);
        assert!(load_page_ranges([(USER_STACK_TOP - 1, 2)].into_iter(), 0).is_err());
        assert!(load_page_ranges([(usize::MAX, 1)].into_iter(), 4096).is_err());
    }
}
