//! ELF executable loader
//!
//! Uses lib::elf for parsing, handles memory mapping.
//! Page tables are allocated on-demand via the page fault handler.

const PAGE_SIZE: usize = 4096;
extern crate alloc;
use alloc::vec::Vec;
use arch_abi::Arch;
use arch_abi::GuestBytes;
use crate::arch::Vcpu;
pub use lib::elf::{ElfError, ElfClass};

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
pub fn load_elf(machine: &mut crate::TheArch, regs: &mut Vcpu, elf_data: &[u8], load_bias: usize) -> Result<LoadedElf, ElfError> {
    let elf = lib::elf::Elf::parse(elf_data)?;

    let mut max_vaddr = 0usize;

    // First pass: copy data into the active address space through the vcpu
    // (pages demand-allocated on access). Going through the vcpu's guest-memory
    // API — rather than dereferencing `seg.vaddr` as a host pointer — is what
    // keeps this loader backend-agnostic: on metal the guest VA is a valid
    // kernel pointer, while on the interpreter it indexes the software MMU's
    // address space.
    for seg in elf.segments() {
        let vaddr = seg.vaddr + load_bias;
        let end = vaddr + seg.memsz;
        if end > max_vaddr { max_vaddr = end; }
        if let Some(data) = seg.data {
            regs.copy_to(vaddr, data);
            if seg.memsz > data.len() {
                regs.zero(vaddr + data.len(), seg.memsz - data.len());
            }
        }
    }

    // Second pass: set final permissions based on segment flags.
    // Process non-executable segments first so executable wins on shared pages.
    for executable_pass in [false, true] {
        for seg in elf.segments() {
            if seg.is_executable() != executable_pass { continue; }
            let vaddr = seg.vaddr + load_bias;
            let start_page = vaddr / PAGE_SIZE;
            let end_page = (vaddr + seg.memsz + PAGE_SIZE - 1) / PAGE_SIZE;
            let count = end_page - start_page;
            if count > 0 {
                machine.set_page_flags(start_page, count, seg.is_writable(), executable_pass);
            }
        }
    }

    // Page-align max_vaddr up for use as heap base
    max_vaddr = (max_vaddr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let (phoff, phentsize, phnum) = elf.ph_table_info();
    Ok(LoadedElf {
        entry: elf.entry() + load_bias as u64,
        class: elf.class(),
        max_vaddr,
        phdr_vaddr: load_bias + phoff,
        phentsize,
        phnum,
    })
}
