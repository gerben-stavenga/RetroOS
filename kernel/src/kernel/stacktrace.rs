//! Stack trace support via frame pointer walking
//!
//! Walks the EBP/RBP chain to produce a backtrace. Requires frame pointers
//! to be preserved (-Cforce-frame-pointers=yes).

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use crate::println;
use core::fmt::Write;
use crate::kernel::vfs;
#[cfg(target_arch = "x86")]
use core::arch::asm;

const SYMBOL_MAGIC: &[u8; 4] = b"RSYM";
const SYMBOL_VERSION: u32 = 1;
const HEADER_SIZE: usize = 16;
const ENTRY_SIZE: usize = 12;

/// Packed, address-sorted function symbols. Names are demangled by the build;
/// the kernel only validates the table and binary-searches it.
struct SymbolData {
    data: Box<[u8]>,
    count: usize,
    names_offset: usize,
}

impl SymbolData {
    fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
        Some(u32::from_le_bytes(data.get(offset..offset + 4)?.try_into().ok()?))
    }

    fn new(data: Box<[u8]>) -> Option<Self> {
        if data.get(..4)? != SYMBOL_MAGIC
            || Self::read_u32(&data, 4)? != SYMBOL_VERSION
        {
            return None;
        }
        let count = Self::read_u32(&data, 8)? as usize;
        let names_offset = Self::read_u32(&data, 12)? as usize;
        let entries_end = HEADER_SIZE.checked_add(count.checked_mul(ENTRY_SIZE)?)?;
        if names_offset != entries_end || names_offset > data.len() {
            return None;
        }

        let mut previous = 0;
        for index in 0..count {
            let entry = HEADER_SIZE + index * ENTRY_SIZE;
            let address = Self::read_u32(&data, entry)?;
            let name_offset = Self::read_u32(&data, entry + 8)? as usize;
            if address == 0 || (index != 0 && address <= previous) {
                return None;
            }
            previous = address;
            let name = data.get(names_offset.checked_add(name_offset)?..)?;
            let end = name.iter().position(|&byte| byte == 0)?;
            core::str::from_utf8(&name[..end]).ok()?;
        }
        Some(Self { data, count, names_offset })
    }

    fn entry(&self, index: usize) -> (u32, u32, usize) {
        let offset = HEADER_SIZE + index * ENTRY_SIZE;
        (
            Self::read_u32(&self.data, offset).unwrap(),
            Self::read_u32(&self.data, offset + 4).unwrap(),
            Self::read_u32(&self.data, offset + 8).unwrap() as usize,
        )
    }

    fn lookup(&self, addr: u64) -> (&str, u64) {
        let Ok(addr) = u32::try_from(addr) else { return ("", 0) };
        let mut low = 0;
        let mut high = self.count;
        while low < high {
            let middle = low + (high - low) / 2;
            if self.entry(middle).0 <= addr {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        if low == 0 {
            return ("", 0);
        }
        let (start, size, name_offset) = self.entry(low - 1);
        if addr > start.saturating_add(size) {
            return ("", 0);
        }
        let name = &self.data[self.names_offset + name_offset..];
        let end = name.iter().position(|&byte| byte == 0).unwrap();
        (core::str::from_utf8(&name[..end]).unwrap(), u64::from(addr - start))
    }
}

static mut KERNEL_SYMBOLS: Option<SymbolData> = None;

fn kernel_symbols_ptr() -> *mut Option<SymbolData> {
    core::ptr::addr_of_mut!(KERNEL_SYMBOLS)
}

/// Load the kernel's symbol table, for naming addresses in a backtrace.
///
/// `C:\BOOT\KERNEL.SYM` is generated from the unstripped linked kernel. It
/// contains only fixed-size address records and pre-demangled names.
pub fn init_from_vfs() {
    let sym = [crate::kernel::dos::c_root(), b"BOOT/KERNEL.SYM"].concat();
    let handle = vfs::open_to_handle(&sym);
    if handle < 0 {
        println!("stacktrace: no KERNEL.SYM — backtraces will be addresses only");
        return;
    }
    let size = vfs::file_size_by_handle(handle) as usize;

    println!("Loading kernel symbols ({} bytes)", size);

    let mut elf_data = vec![0u8; size];
    vfs::read_by_handle(handle, &mut elf_data);
    vfs::close_vfs_handle(handle);

    let elf_box: Box<[u8]> = elf_data.into_boxed_slice();

    match SymbolData::new(elf_box) {
        Some(data) => {
            println!("Loaded {} function symbols", data.count);
            unsafe {
                *kernel_symbols_ptr() = Some(data);
            }
        }
        None => {
            println!("stacktrace: invalid KERNEL.SYM");
        }
    }
}

/// Write a stack trace starting from the caller of this function. Used by the
/// panic handler, which passes the terminal directly so the trace lands on
/// the display (and, mirrored, in the log); skips its own frame so the first
/// line is whoever panicked. Only the metal boot path uses this entry; the
/// hosted backend traces via `stack_trace_regs`.
#[cfg(target_arch = "x86")]
pub fn stack_trace(out: &mut dyn Write) {
    let bp: usize;
    unsafe { asm!("mov {}, ebp", out(reg) bp); }
    // Pre-advance one hop so `walk` starts at our caller's frame (panic's, say).
    let caller_bp = if bp != 0 {
        unsafe { *(bp as *const u32) as u64 }
    } else { 0 };
    let _ = writeln!(out, "Stack trace:");
    walk(out, caller_bp, 0, false);
}

/// Print a stack trace for a saved interrupt context (F12 debug hotkey, etc).
/// Frame 0 is the exact IP that was interrupted. Whether to chain past it
/// depends on what was interrupted:
///   - Ring 1 (kernel): `regs.rbp` is a valid C-style frame pointer into the
///     ring-1 call chain — walk it.
///   - Ring 0 (arch self-reentry): rbp is mid-asm garbage — stop.
///   - Ring 3 / VM86 (user): rbp points into untrusted user memory — stop.
pub fn stack_trace_regs(regs: &crate::Regs) {
    let mut out = lib::log::DebugCon;
    let _ = writeln!(out, "Stack trace:");
    print_frame(&mut out, 0, regs.ip());
    if (regs.frame.cs & 3) == 1 {
        let user_64 = regs.mode() == crate::UserMode::Mode64;
        walk(&mut out, regs.rbp, 1, user_64);
    }
}

/// Write one line of the backtrace.
fn print_frame(out: &mut dyn Write, depth: usize, ip: u64) {
    let (name, offset) = lookup_symbol(ip);
    let _ = write!(out, "  {:2}: {:#010x}", depth, ip);
    if !name.is_empty() {
        let _ = write!(out, " {}+{:#x}", name, offset);
    }
    let _ = writeln!(out);
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
fn walk(out: &mut dyn Write, mut bp: u64, mut depth: usize, user_64: bool) {
    // The trap-entry boundary is an `entry.asm` label (metal only). The hosted
    // process has no such boundary, so the chain just walks to its natural end.
    #[cfg(target_arch = "x86")]
    let isr_dispatch = {
        unsafe extern "C" { fn isr_return(); }
        isr_return as *const () as u64
    };
    #[cfg(not(target_arch = "x86"))]
    let isr_dispatch = 0u64;
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
        print_frame(out, depth, ip);
        bp = next_bp;
        depth += 1;
    }

    if depth == MAX_DEPTH {
        let _ = writeln!(out, "  ... (truncated)");
    }
}

/// Kernel space starts at this address
const KERNEL_BASE: u32 = 0xC000_0000;

/// Look up a symbol name for an address. Only kernel addresses are resolved
/// (against the 'static kernel symbol table). User-space frames print their raw
/// address: symbolizing them would mean reaching the running thread's symbol
/// table — state the event loop owns — from the panic path, which can't thread
/// it in. Best-effort user names aren't worth a global; kernel frames are what
/// a panic backtrace needs.
fn lookup_symbol(addr: u64) -> (&'static str, u64) {
    if addr >= KERNEL_BASE as u64 {
        let sym_data = unsafe { (*kernel_symbols_ptr()).as_ref() };
        if let Some(data) = sym_data {
            let (name, offset) = data.lookup(addr);
            if !name.is_empty() {
                // SAFETY: kernel symbols are 'static
                return (unsafe { core::mem::transmute::<&str, &str>(name) }, offset);
            }
        }
    }
    ("", 0)
}

#[cfg(test)]
mod tests {
    use super::{ENTRY_SIZE, HEADER_SIZE, SYMBOL_MAGIC, SYMBOL_VERSION, SymbolData};
    use alloc::boxed::Box;
    use alloc::vec::Vec;

    fn packed(entries: &[(u32, u32, u32)], names: &[u8]) -> Box<[u8]> {
        let mut data = Vec::new();
        data.extend_from_slice(SYMBOL_MAGIC);
        data.extend_from_slice(&SYMBOL_VERSION.to_le_bytes());
        data.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        data.extend_from_slice(&((HEADER_SIZE + entries.len() * ENTRY_SIZE) as u32).to_le_bytes());
        for &(address, size, name) in entries {
            data.extend_from_slice(&address.to_le_bytes());
            data.extend_from_slice(&size.to_le_bytes());
            data.extend_from_slice(&name.to_le_bytes());
        }
        data.extend_from_slice(names);
        data.into_boxed_slice()
    }

    #[test]
    fn packed_symbols_binary_search_and_reject_gaps() {
        let symbols = SymbolData::new(packed(
            &[(0x1000, 0x20, 0), (0x1100, 0x10, 6)],
            b"first\0second\0",
        )).unwrap();
        assert_eq!(symbols.lookup(0x1014), ("first", 0x14));
        assert_eq!(symbols.lookup(0x1080), ("", 0));
        assert_eq!(symbols.lookup(0x1104), ("second", 4));
    }

    #[test]
    fn packed_symbols_validate_order_and_names() {
        assert!(SymbolData::new(packed(&[(0x1100, 1, 0), (0x1000, 1, 2)], b"a\0b\0")).is_none());
        assert!(SymbolData::new(packed(&[(0x1000, 1, 4)], b"a\0")).is_none());
        assert!(SymbolData::new(packed(&[(0x1000, 1, 0)], b"unterminated")).is_none());
    }
}
