//! ELF executable loader
//!
//! Uses lib::elf for parsing, handles memory mapping.
//! Page tables are allocated on-demand via the page fault handler.

use crate::paging2::{self, page_idx, Entry, Entry32, Entry64, Entries, PAGE_SIZE};
use crate::x86;
pub use lib::elf::ElfError;

/// User stack top address (just below kernel space)
pub const USER_STACK_TOP: usize = 0xC000_0000;

/// User stack size in pages
pub const USER_STACK_PAGES: usize = 16;  // 64KB stack

/// Set final permissions on a page (called after loading is complete)
fn finalize_page_permissions<E: Entry>(entries: &mut [E], vaddr: usize, writable: bool, executable: bool) {
    let page = page_idx(vaddr);
    let page_addr = vaddr & !(PAGE_SIZE - 1);

    if entries[page].present() {
        let phys = entries[page].page();
        let mut entry = E::new(phys, writable, true);
        entry.set_soft_ro(!writable);
        // Clear NX only if this segment is executable; otherwise preserve
        // (executable wins if multiple segments share a page)
        if executable {
            entry.set_no_execute(false);
        }
        entries[page] = entry;
        x86::invlpg(page_addr);
    }
}

/// Load an ELF executable into user address space
pub fn load_elf(elf_data: &[u8]) -> Result<u32, ElfError> {
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

    // Second pass: set final permissions based on segment flags
    for seg in elf.segments() {
        let start_page = seg.vaddr / PAGE_SIZE;
        let end_page = (seg.vaddr + seg.memsz + PAGE_SIZE - 1) / PAGE_SIZE;
        let writable = seg.is_writable();
        let executable = seg.is_executable();

        for page in start_page..end_page {
            match paging2::entries() {
                Entries::Legacy(e) => {
                    finalize_page_permissions(e, page * PAGE_SIZE, writable, executable);
                }
                Entries::Pae(e) => {
                    finalize_page_permissions(e, page * PAGE_SIZE, writable, executable);
                }
            }
        }
    }

    paging2::flush_tlb();
    Ok(elf.entry())
}
