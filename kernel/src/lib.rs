//! RetroOS Rust Kernel
//!
//! Entry flow:
//! 1. _start (asm stub: offset GDT, kernel stack, calls boot_kernel)
//! 2. boot_kernel (enables paging, initializes kernel, drops to ring 1)

#![no_std]
#![no_main]

use core::panic::PanicInfo;

extern crate alloc;
extern crate ext4_view;
extern crate rustc_demangle;

mod arch;
mod kernel;
pub mod pipe;  // Shared utility: ring buffer used by both arch and kernel

// Re-export kernel submodules so arch/ code can use crate::thread, crate::machine, etc.
pub use kernel::dos;
pub use kernel::machine;
pub use kernel::thread;

// Re-export lib's vga module and macros
pub use lib::vga;
pub use lib::{print, println, dbg_print, dbg_println};

// Re-export arch types used as opaque blobs by kernel code
pub use arch::{RootPageTable, PAGE_SIZE, KernelPages, RawPage, LOW_MEM_BASE};

/// Multiboot memory map entry
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct MultibootMmapEntry {
    pub size: u32,
    pub base: u64,
    pub length: u64,
    pub typ: u32,
}

/// Multiboot info structure (from GRUB or our bootloader)
#[repr(C)]
pub struct MultibootInfo {
    pub flags: u32,
    pub mem_lower: u32,
    pub mem_upper: u32,
    pub boot_device: u32,
    pub cmdline: u32,
    pub mods_count: u32,
    pub mods_addr: u32,
    pub syms: [u32; 4],
    pub mmap_length: u32,
    pub mmap_addr: u32,
}

static ZERO_PAGE: RawPage = unsafe { core::mem::zeroed() };
static mut SCRATCH: RawPage = unsafe { core::mem::zeroed() };

#[repr(C, align(16))]
pub struct AlignedStack<const N: usize>(pub [u8; N]);

impl<const N: usize> AlignedStack<N> {
    pub const fn new() -> Self {
        Self([0; N])
    }

    pub fn top(&self) -> *const u8 {
        self.0.as_ptr().wrapping_add(N)
    }

    pub fn top_mut(&mut self) -> *mut u8 {
        self.0.as_mut_ptr().wrapping_add(N)
    }
}

/// Kernel stack - 32KB (used for Ring 1 event loop).
/// ext4-view's call chain needs ~20KB in debug builds; keep opt-level >= 1
/// or increase this (max ~60KB before exceeding PDE[770]'s 1MB kernel region).
#[unsafe(no_mangle)]
pub static mut KERNEL_STACK: AlignedStack<{ 32 * 1024 }> = AlignedStack::new();

/// Ring-0 arch stack — used as TSS ESP0 so that interrupts from ring 1/3
/// don't clobber the kernel's call frames.  Must be in .data (not BSS)
/// so pages are physically backed even after fork marks BSS pages COW.
#[unsafe(link_section = ".data")]
pub static mut ARCH_STACK: AlignedStack<{ 16 * 1024 }> = AlignedStack::new();

// Linker symbols (used by panic stack trace)
unsafe extern "C" {
    static _kernel_start: u8;
    static _data: u8;
    static _edata: u8;
    static _end: u8;
}

/// Raw CPU-pushed interrupt frame for 32-bit mode.
/// This is only used by the 32-bit arch entry/exit path before conversion to
/// the kernel-facing `Frame64` form.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Frame32 {
    /// Padding to align with 64-bit frame layout
    pub _pad: [u32; 5],
    pub eip: u32,
    pub cs: u32,
    pub eflags: u32,
    pub esp: u32,
    pub ss: u32,
}

impl core::fmt::Debug for Frame32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Frame32")
            .field("eip", &format_args!("{:#010x}", self.eip))
            .field("cs", &format_args!("{:#06x}", self.cs))
            .field("eflags", &format_args!("{:#010x}", self.eflags))
            .field("esp", &format_args!("{:#010x}", self.esp))
            .field("ss", &format_args!("{:#06x}", self.ss))
            .finish()
    }
}

/// CPU-pushed interrupt frame for 64-bit mode
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Frame64 {
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl core::fmt::Debug for Frame64 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Frame64")
            .field("rip", &format_args!("{:#018x}", self.rip))
            .field("cs", &format_args!("{:#06x}", self.cs))
            .field("rflags", &format_args!("{:#018x}", self.rflags))
            .field("rsp", &format_args!("{:#018x}", self.rsp))
            .field("ss", &format_args!("{:#06x}", self.ss))
            .finish()
    }
}

/// User execution mode, derived from register state.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UserMode { VM86, Mode32, Mode64 }

/// CPU register state saved by interrupt handler.
/// Also used as the saved CPU state in Thread (identical layout).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Regs {
    // Segment registers (zero-extended)
    pub gs: u64,
    pub fs: u64,
    pub es: u64,
    pub ds: u64,
    // x86-64 extended registers (zero in 32-bit mode)
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    // General purpose registers
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rsp_dummy: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    // Interrupt info (software-pushed, zero-extended to 64-bit)
    pub int_num: u64,
    pub err_code: u64,
    // CPU-pushed interrupt frame normalized to Frame64 before the kernel sees it.
    pub frame: Frame64,
}

impl Regs {
    pub const fn empty() -> Self {
        Regs {
            gs: 0, fs: 0, es: 0, ds: 0,
            r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
            rdi: 0, rsi: 0, rbp: 0, rsp_dummy: 0, rbx: 0, rdx: 0, rcx: 0, rax: 0,
            int_num: 0, err_code: 0,
            frame: Frame64 { rip: 0, cs: 0, rflags: 0, rsp: 0, ss: 0 },
        }
    }

    /// Convert the in-place raw 32-bit frame encoding to the normalized
    /// `Frame64` representation.
    pub fn from_32(&mut self) {
        let raw = unsafe { core::ptr::read((&self.frame as *const Frame64).cast::<Frame32>()) };
        self.frame = Frame64 {
            rip: raw.eip as u64,
            cs: raw.cs as u64,
            rflags: raw.eflags as u64,
            rsp: raw.esp as u64,
            ss: raw.ss as u64,
        };
    }

    /// Convert the normalized `Frame64` representation to the raw 32-bit frame
    /// encoding expected by the 32-bit `iret` path.
    pub fn to_32(&mut self) {
        let raw = Frame32 {
            _pad: [0; 5],
            eip: self.frame.rip as u32,
            cs: self.frame.cs as u32,
            eflags: self.frame.rflags as u32,
            esp: self.frame.rsp as u32,
            ss: self.frame.ss as u32,
        };
        unsafe {
            core::ptr::write((&mut self.frame as *mut Frame64).cast::<Frame32>(), raw);
        }
    }

    pub fn ip32(&self) -> u32 {
        self.frame.rip as u32
    }

    pub fn set_ip32(&mut self, ip: u32) {
        self.frame.rip = ip as u64;
    }

    pub fn cs32(&self) -> u32 {
        self.frame.cs as u32
    }

    pub fn set_cs32(&mut self, cs: u32) {
        self.frame.cs = cs as u64;
    }

    pub fn flags32(&self) -> u32 {
        self.frame.rflags as u32
    }

    pub fn set_flags32(&mut self, flags: u32) {
        self.frame.rflags = flags as u64;
    }

    pub fn set_flag32(&mut self, mask: u32) {
        self.set_flags32(self.flags32() | mask);
    }

    pub fn clear_flag32(&mut self, mask: u32) {
        self.set_flags32(self.flags32() & !mask);
    }

    pub fn sp32(&self) -> u32 {
        self.frame.rsp as u32
    }

    pub fn set_sp32(&mut self, sp: u32) {
        self.frame.rsp = sp as u64;
    }

    pub fn ss32(&self) -> u32 {
        self.frame.ss as u32
    }

    pub fn set_ss32(&mut self, ss: u32) {
        self.frame.ss = ss as u64;
    }

    /// Get instruction pointer.
    pub fn ip(&self) -> u64 {
        self.frame.rip
    }

    /// Get code segment
    pub fn code_seg(&self) -> u16 {
        self.frame.cs as u16
    }

    /// Get flags
    pub fn flags(&self) -> u64 {
        self.frame.rflags
    }

    /// Derive execution mode from canonical register state.
    /// Checks CS first (64-bit wins over stale VM flag), then EFLAGS.VM.
    /// Returns Mode32 for kernel regs (ring 1 CS) too.
    pub fn mode(&self) -> UserMode {
        if self.frame.cs == arch::USER_CS64 as u64 {
            UserMode::Mode64
        } else if self.frame.rflags & (1 << 17) != 0 {
            UserMode::VM86
        } else {
            UserMode::Mode32
        }
    }

    /// Get stack pointer
    pub fn sp(&self) -> u64 {
        self.frame.rsp
    }

    /// Get stack segment
    pub fn stack_seg(&self) -> u16 {
        self.frame.ss as u16
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn regs_from_32(regs: *mut Regs) {
    unsafe { (*regs).from_32(); }
}

#[unsafe(no_mangle)]
pub extern "C" fn regs_to_32(regs: *mut Regs) {
    unsafe { (*regs).to_32(); }
}

impl core::fmt::Debug for Regs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "INT: {:#04x}  ERR: {:#010x}", self.int_num, self.err_code)?;
        writeln!(f, "IP:  {:#010x}  CS: {:#06x}  FL: {:#010x}", self.ip(), self.code_seg(), self.flags())?;
        writeln!(f, "SP:  {:#010x}  SS: {:#06x}", self.sp(), self.stack_seg())?;
        writeln!(f, "RAX: {:#018x}  RBX: {:#018x}", self.rax, self.rbx)?;
        writeln!(f, "RCX: {:#018x}  RDX: {:#018x}", self.rcx, self.rdx)?;
        writeln!(f, "RSI: {:#018x}  RDI: {:#018x}", self.rsi, self.rdi)?;
        writeln!(f, "RBP: {:#018x}  R8:  {:#018x}", self.rbp, self.r8)?;
        writeln!(f, "R9:  {:#018x}  R10: {:#018x}", self.r9, self.r10)?;
        writeln!(f, "R11: {:#018x}  R12: {:#018x}", self.r11, self.r12)?;
        writeln!(f, "R13: {:#018x}  R14: {:#018x}", self.r13, self.r14)?;
        writeln!(f, "R15: {:#018x}", self.r15)?;
        write!(f, "DS: {:#06x}  ES: {:#06x}  FS: {:#06x}  GS: {:#06x}",
               self.ds as u16, self.es as u16, self.fs as u16, self.gs as u16)
    }
}

/// Panic handler
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    arch::cli();
    println!();
    println!("\x1b[91m!!! KERNEL PANIC !!!\x1b[0m");

    if let Some(location) = info.location() {
        println!("at {}:{}", location.file(), location.line());
    } else {
        println!("at <unknown location>");
    }

    // PanicMessage implements Display
    println!("  {}", info.message());
    println!();

    kernel::stacktrace::stack_trace();

    loop {
        arch::cli();
        arch::hlt();
    }
}
