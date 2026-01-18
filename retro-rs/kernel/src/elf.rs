//! ELF executable loader
//!
//! Uses lib::elf for parsing, handles memory mapping.

use crate::paging2::{self, page_idx, PAGE_SIZE};
use crate::phys_mm;
pub use lib::elf::ElfError;

/// Map a virtual page for user space
fn map_user_page(vaddr: usize, writable: bool) -> Result<(), ElfError> {
    let page = page_idx(vaddr);

    if paging2::is_present(page) {
        if writable && !paging2::is_writable(page) && !paging2::is_cow(page) {
            paging2::set_entry(page, paging2::get_phys_page(page), true, true, false);
        }
        return Ok(());
    }

    let phys_page = phys_mm::alloc_phys_page().ok_or(ElfError::OutOfMemory)?;
    paging2::set_entry(page, phys_page, writable, true, false);

    unsafe {
        let ptr = (vaddr & !(PAGE_SIZE - 1)) as *mut u8;
        core::ptr::write_bytes(ptr, 0, PAGE_SIZE);
    }

    Ok(())
}

/// Load an ELF executable into user address space
pub fn load_elf(elf_data: &[u8]) -> Result<u32, ElfError> {
    let elf = lib::elf::Elf::parse(elf_data)?;

    for seg in elf.segments() {
        let start_page = seg.vaddr / PAGE_SIZE;
        let end_page = (seg.vaddr + seg.memsz + PAGE_SIZE - 1) / PAGE_SIZE;

        for page in start_page..end_page {
            map_user_page(page * PAGE_SIZE, seg.is_writable())?;
        }

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

    paging2::flush_tlb();
    Ok(elf.entry())
}
