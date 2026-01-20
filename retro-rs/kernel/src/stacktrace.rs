//! Stack trace support via frame pointer walking
//!
//! Walks the EBP chain to produce a backtrace. Requires frame pointers
//! to be preserved (-Cforce-frame-pointers=yes).

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use crate::{print, println, startup, thread};
use core::arch::asm;
use lib::elf::{SymbolTable, STT_FUNC};

/// Owned symbol data - keeps ELF data alive for SymbolTable references
pub struct SymbolData {
    elf_data: Box<[u8]>,
}

impl SymbolData {
    /// Create symbol data from ELF bytes
    pub fn new(elf_data: Box<[u8]>) -> Option<Self> {
        // Verify we can parse symbols before storing
        let elf_ref: &[u8] = &elf_data;
        if SymbolTable::parse(elf_ref).is_some() {
            Some(SymbolData { elf_data })
        } else {
            None
        }
    }

    /// Look up a symbol by address
    pub fn lookup(&self, addr: u32) -> (&str, u32) {
        // SAFETY: elf_data is owned by self and won't move
        let elf_ref: &[u8] = unsafe {
            core::slice::from_raw_parts(self.elf_data.as_ptr(), self.elf_data.len())
        };
        if let Some(table) = SymbolTable::parse(elf_ref) {
            table.lookup(addr)
        } else {
            ("", 0)
        }
    }

    /// Get symbol count (for diagnostics)
    pub fn symbol_count(&self) -> (usize, usize) {
        let elf_ref: &[u8] = &self.elf_data;
        if let Some(table) = SymbolTable::parse(elf_ref) {
            let total = table.symbols().len();
            let funcs = table.symbols().iter().filter(|s| s.typ() == STT_FUNC).count();
            (total, funcs)
        } else {
            (0, 0)
        }
    }
}

static mut KERNEL_SYMBOLS: Option<SymbolData> = None;

fn kernel_symbols_ptr() -> *mut Option<SymbolData> {
    unsafe { core::ptr::addr_of_mut!(KERNEL_SYMBOLS) }
}

/// Initialize kernel symbol table by loading kernel.elf from TAR filesystem
pub fn init_from_tar() {
    let size = match startup::find_file(b"kernel.elf") {
        Some(s) => s,
        None => {
            println!("stacktrace: kernel.elf not found");
            return;
        }
    };

    println!("Loading kernel.elf ({} bytes) for symbols", size);

    // Allocate buffer and read ELF
    let mut elf_data = vec![0u8; size];
    startup::read_file(&mut elf_data);

    let elf_box: Box<[u8]> = elf_data.into_boxed_slice();

    match SymbolData::new(elf_box) {
        Some(data) => {
            let (total, funcs) = data.symbol_count();
            println!("Loaded {} symbols ({} functions)", total, funcs);
            unsafe {
                *kernel_symbols_ptr() = Some(data);
            }
        }
        None => {
            println!("stacktrace: failed to parse ELF symbols");
        }
    }
}

/// Print a stack trace starting from the current frame
pub fn stack_trace() {
    let bp: usize;
    unsafe {
        asm!("mov {}, ebp", out(reg) bp);
    }
    stack_trace_from(bp);
}

/// Print a stack trace starting from a specific frame pointer
pub fn stack_trace_from(mut bp: usize) {
    // Skip the first frame (this function)
    if bp != 0 {
        let frame = bp as *const usize;
        unsafe {
            bp = *frame;
        }
    }

    println!("Stack trace:");

    let mut depth = 0;
    const MAX_DEPTH: usize = 20;

    // Kernel stack bounds (approximate)
    const KERNEL_STACK_LOW: usize = 0xC0000000;
    const KERNEL_STACK_HIGH: usize = 0xD0000000;

    while bp != 0 && depth < MAX_DEPTH {
        // Validate frame pointer is in reasonable kernel memory range
        if bp < KERNEL_STACK_LOW || bp >= KERNEL_STACK_HIGH {
            break;
        }

        let frame = bp as *const usize;

        let (next_bp, ip) = unsafe {
            (*frame, *frame.add(1))
        };

        if ip == 0 || ip < 0x1000 {
            break;
        }

        let (name, offset) = lookup_symbol(ip as u32);

        print!("  {:2}: {:#010x}", depth, ip);
        if !name.is_empty() {
            print!(" {}+{:#x}", rustc_demangle::demangle(name), offset);
        }
        println!();

        bp = next_bp;
        depth += 1;
    }

    if depth == MAX_DEPTH {
        println!("  ... (truncated)");
    }
}

/// Kernel space starts at this address
const KERNEL_BASE: u32 = 0xC000_0000;

/// Look up a symbol name for an address
fn lookup_symbol(addr: u32) -> (&'static str, u32) {
    if addr >= KERNEL_BASE {
        // Kernel address - use kernel symbols
        let sym_data = unsafe { (*kernel_symbols_ptr()).as_ref() };
        if let Some(data) = sym_data {
            let (name, offset) = data.lookup(addr);
            if !name.is_empty() {
                // SAFETY: kernel symbols are 'static
                return (unsafe { core::mem::transmute(name) }, offset);
            }
        }
    } else {
        // User address - use current thread's symbols
        if let Some(thread) = thread::current() {
            if let Some(ref symbols) = thread.symbols {
                let (name, offset) = symbols.lookup(addr);
                if !name.is_empty() {
                    // SAFETY: thread symbols live as long as thread
                    return (unsafe { core::mem::transmute(name) }, offset);
                }
            }
        }
    }
    ("", 0)
}
