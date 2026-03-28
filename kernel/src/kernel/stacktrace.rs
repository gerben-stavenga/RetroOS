//! Stack trace support via frame pointer walking
//!
//! Walks the EBP/RBP chain to produce a backtrace. Requires frame pointers
//! to be preserved (-Cforce-frame-pointers=yes).

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use crate::{print, println};
use crate::kernel::{startup, thread};
use core::arch::asm;
use lib::elf::{SymbolTable, STT_FUNC};

/// Owned symbol data - keeps ELF data alive for SymbolTable references
#[derive(Clone)]
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
    pub fn lookup(&self, addr: u64) -> (&str, u64) {
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
            (table.symbol_count(), table.func_count())
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
    stack_trace_from(bp as u32);
}

/// Print a stack trace starting from a specific frame pointer.
///
/// Always starts walking 32-bit kernel frames (ebp chain with 4-byte pairs).
/// When the return IP drops below KERNEL_BASE, we've crossed the entry.asm
/// mock frame into user space. At that point, if the current thread is 64-bit,
/// we switch to 64-bit frame walking (rbp/rip pairs of 8 bytes each).
pub fn stack_trace_from(mut bp: u32) {
    unsafe extern "C" { fn isr_return(); }
    let isr_dispatch = isr_return as u32;

    // Skip the first frame (this function / trap handler)
    if bp != 0 {
        let frame = bp as *const u32;
        unsafe { bp = *frame; }
    }

    println!("Stack trace:");

    let mut depth = 0;
    const MAX_DEPTH: usize = 20;
    let mut user_64 = false;

    while bp != 0 && depth < MAX_DEPTH {
        if bp < 0x1000 {
            break;
        }

        if user_64 {
            // 64-bit user frames: [rbp(8), rip(8)]
            let frame = bp as usize as *const u64;
            let (next_bp, ip) = unsafe { (*frame, *frame.add(1)) };

            if ip == 0 || ip < 0x1000 {
                break;
            }

            let (name, offset) = lookup_symbol(ip);
            print!("  {:2}: {:#010x}", depth, ip);
            if !name.is_empty() {
                print!(" {}+{:#x}", rustc_demangle::demangle(name), offset);
            }
            println!();

            bp = next_bp as u32;
        } else {
            // 32-bit frames: [ebp(4), eip(4)]
            let frame = bp as *const u32;
            let (next_bp, ip) = unsafe { (*frame, *frame.add(1) as u64) };

            if ip == 0 || ip < 0x1000 {
                break;
            }

            // Detect ISR dispatch: next frame is a 16-byte mock frame
            // [ebp/rbp_lo, eip/rbp_hi, 0/rip_lo, 0/rip_hi]
            // rip==0 means 32-bit user, rip!=0 means 64-bit user
            if ip == isr_dispatch as u64 {
                let mock = next_bp as *const u64;
                let rip = unsafe { *mock.add(1) };
                if rip != 0 {
                    // 64-bit user: rbp and rip are full 64-bit values
                    user_64 = true;
                    bp = unsafe { *mock } as u32;
                } else {
                    // 32-bit user: ebp and eip are in the low 32 bits
                    bp = next_bp;
                }
                depth += 1;
                continue;
            }

            let (name, offset) = lookup_symbol(ip);
            print!("  {:2}: {:#010x}", depth, ip);
            if !name.is_empty() {
                print!(" {}+{:#x}", rustc_demangle::demangle(name), offset);
            }
            println!();

            bp = next_bp;
        }

        depth += 1;
    }

    if depth == MAX_DEPTH {
        println!("  ... (truncated)");
    }
}

/// Kernel space starts at this address
const KERNEL_BASE: u32 = 0xC000_0000;

/// Look up a symbol name for an address
fn lookup_symbol(addr: u64) -> (&'static str, u64) {
    if addr >= KERNEL_BASE as u64 {
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
        let thread = thread::current();
        if let Some(ref symbols) = thread.symbols {
            let (name, offset) = symbols.lookup(addr);
            if !name.is_empty() {
                // SAFETY: thread symbols live as long as thread
                return (unsafe { core::mem::transmute(name) }, offset);
            }
        }
    }
    ("", 0)
}
