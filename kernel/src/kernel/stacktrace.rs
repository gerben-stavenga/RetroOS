//! Stack trace support via frame pointer walking
//!
//! Walks the EBP/RBP chain to produce a backtrace. Requires frame pointers
//! to be preserved (-Cforce-frame-pointers=yes).

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use crate::{print, println};
use crate::kernel::{vfs, thread};
use core::arch::asm;
use lib::elf::SymbolTable;

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

/// Debug-only: current thread index for panic stacktraces.
/// Written by the event loop, read only by lookup_symbol during crash diagnostics.
static mut DEBUG_TID: usize = 0;

pub fn set_debug_tid(tid: usize) {
    unsafe { DEBUG_TID = tid; }
}

fn kernel_symbols_ptr() -> *mut Option<SymbolData> {
    core::ptr::addr_of_mut!(KERNEL_SYMBOLS)
}

/// Initialize kernel symbol table by loading kernel.elf from TAR filesystem
pub fn init_from_tar() {
    // Try both mount layouts (TAR at root or at tar/)
    // Use handle-based VFS access (no per-thread fd slot needed)
    let mut handle = vfs::open_to_handle(b"kernel.elf");
    if handle < 0 { handle = vfs::open_to_handle(b"tar/kernel.elf"); }
    if handle < 0 {
        println!("stacktrace: kernel.elf not found");
        return;
    }
    let size = vfs::file_size_by_handle(handle) as usize;

    println!("Loading kernel.elf ({} bytes) for symbols", size);

    let mut elf_data = vec![0u8; size];
    vfs::read_by_handle(handle, &mut elf_data);
    vfs::close_vfs_handle(handle);

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

/// Print a stack trace starting from the caller of this function. Used by the
/// panic handler; skips its own frame so the first line is whoever panicked.
pub fn stack_trace() {
    let bp: usize;
    unsafe { asm!("mov {}, ebp", out(reg) bp); }
    // Pre-advance one hop so `walk` starts at our caller's frame (panic's, say).
    let caller_bp = if bp != 0 {
        unsafe { *(bp as *const u32) as u64 }
    } else { 0 };
    println!("Stack trace:");
    walk(caller_bp, 0, false);
}

/// Print a stack trace for a saved interrupt context (F12 debug hotkey, etc).
/// Frame 0 is the exact IP that was interrupted. Whether to chain past it
/// depends on what was interrupted:
///   - Ring 1 (kernel): `regs.rbp` is a valid C-style frame pointer into the
///     ring-1 call chain — walk it.
///   - Ring 0 (arch self-reentry): rbp is mid-asm garbage — stop.
///   - Ring 3 / VM86 (user): rbp points into untrusted user memory — stop.
pub fn stack_trace_regs(regs: &crate::Regs) {
    println!("Stack trace:");
    print_frame(0, regs.ip());
    if (regs.frame.cs & 3) == 1 {
        let user_64 = regs.mode() == crate::UserMode::Mode64;
        walk(regs.rbp, 1, user_64);
    }
}

/// Print one line of the backtrace.
fn print_frame(depth: usize, ip: u64) {
    let (name, offset) = lookup_symbol(ip);
    print!("  {:2}: {:#010x}", depth, ip);
    if !name.is_empty() {
        print!(" {}+{:#x}", rustc_demangle::demangle(name), offset);
    }
    println!();
}

/// Walk the ebp/rbp chain starting at `bp`. Each iteration reads the frame's
/// saved-bp and return-ip pair, prints the return ip (i.e. the caller's
/// current IP at the time of the call), and advances.
///
/// Stops at the trap-entry boundary: when a return IP matches `isr_return`,
/// we've crossed from a kernel frame into arch's trap-handling code. Going
/// further would require interpreting whatever was in ebp at trap time —
/// junk for ring-0/arch self-reentry, untrusted for ring-3 user. The trap
/// context itself is shown via `stack_trace_regs`, which prints regs.rip
/// up front and decides whether to chain into ring-1 from there.
fn walk(mut bp: u64, mut depth: usize, user_64: bool) {
    unsafe extern "C" { fn isr_return(); }
    let isr_dispatch = isr_return as u64;
    const MAX_DEPTH: usize = 20;

    while depth < MAX_DEPTH && bp >= 0x1000 {
        let (next_bp, ip) = if user_64 {
            let frame = bp as usize as *const u64;
            unsafe { (*frame, *frame.add(1)) }
        } else {
            let frame = (bp as u32) as *const u32;
            unsafe { (*frame as u64, *frame.add(1) as u64) }
        };
        if ip == 0 || ip < 0x1000 { break; }
        if ip == isr_dispatch { break; }
        print_frame(depth, ip);
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
        // User address - use current thread's symbols (best-effort via debug tid)
        let tid = unsafe { DEBUG_TID };
        if let Some(thread) = thread::get_thread(tid) {
            if let Some(symbols) = &thread.kernel.symbols {
                let (name, offset) = symbols.lookup(addr);
                if !name.is_empty() {
                    return (unsafe { core::mem::transmute(name) }, offset);
                }
            }
        }
    }
    ("", 0)
}
