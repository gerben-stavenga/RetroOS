//! ELF executable loader
//!
//! Uses lib::elf for parsing, handles memory mapping.
//! Page tables are allocated on-demand via the page fault handler.

use crate::arch::paging2::PAGE_SIZE;
use crate::kernel::startup::arch_set_page_flags;
pub use lib::elf::{ElfError, ElfClass};

/// User stack top address (just below kernel space)
pub const USER_STACK_TOP: usize = 0xC000_0000;

/// User stack size in pages
pub const USER_STACK_PAGES: usize = 16;  // 64KB stack

/// Loaded ELF info
pub struct LoadedElf {
    pub entry: u64,
    pub class: ElfClass,
}

/// Load an ELF executable into user address space
pub fn load_elf(elf_data: &[u8]) -> Result<LoadedElf, ElfError> {
    let elf = lib::elf::Elf::parse(elf_data)?;

    // First pass: copy data (pages demand-allocated on access)
    for seg in elf.segments() {
        if let Some(data) = seg.data {
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), seg.vaddr as *mut u8, data.len());
            }
            if seg.memsz > data.len() {
                unsafe {
                    let bss = (seg.vaddr + data.len()) as *mut u8;
                    core::ptr::write_bytes(bss, 0, seg.memsz - data.len());
                }
            }
        }
    }

    // Second pass: set final permissions based on segment flags.
    // Process non-executable segments first so executable wins on shared pages.
    for executable_pass in [false, true] {
        for seg in elf.segments() {
            if seg.is_executable() != executable_pass { continue; }
            let start_page = seg.vaddr / PAGE_SIZE;
            let end_page = (seg.vaddr + seg.memsz + PAGE_SIZE - 1) / PAGE_SIZE;
            let count = end_page - start_page;
            if count > 0 {
                arch_set_page_flags(start_page, count, seg.is_writable(), executable_pass);
            }
        }
    }

    Ok(LoadedElf { entry: elf.entry(), class: elf.class() })
}
