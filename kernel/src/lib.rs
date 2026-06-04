//! RetroOS Rust Kernel
//!
//! Entry flow:
//! 1. _start (asm stub: offset GDT, kernel stack, calls boot_kernel)
//! 2. boot_kernel (enables paging, initializes kernel, drops to ring 1)

#![no_std]
// The bare-metal (metal) build has no runtime entry point; the hosted build is
// an ordinary `std` binary with `fn main()`, so it keeps the default main shim.
#![cfg_attr(not(feature = "hosted"), no_main)]

extern crate alloc;
extern crate ext4_view;
extern crate rustc_demangle;

// The arch layer is a swappable backend. Metal: the in-tree `kernel/src/arch/`
// (real x86, INT 0x80). Hosted: the `arch-interp` crate (software x86 core),
// pulled in as `crate::arch` so every `crate::arch::*` path resolves the same.
#[cfg(not(feature = "hosted"))]
#[path = "arch/mod.rs"]
mod arch;
#[cfg(feature = "hosted")]
extern crate retroos_arch_interp as arch;

mod kernel;
pub mod pipe;  // Shared utility: ring buffer used by both arch and kernel

// Re-export kernel submodules so arch/ code can use crate::thread, crate::dos, etc.
pub use kernel::dos;
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

// Metal-only: scratch/zero page frames and linker-symbol statics are consumed
// only by the bare-metal arch boot/paging code. The hosted backend has neither
// a custom paging bring-up nor a linker script.
#[cfg(not(feature = "hosted"))]
static ZERO_PAGE: RawPage = unsafe { core::mem::zeroed() };
#[cfg(not(feature = "hosted"))]
static mut SCRATCH: RawPage = unsafe { core::mem::zeroed() };

// Linker symbols. Stacks and their guard pages live at the tail of .bss
// (see kernel.ld); only their addresses matter to Rust, so they're declared
// as opaque externs. Guard pages get unmapped at boot so kernel-stack
// overflow takes a clean #PF instead of corrupting adjacent memory.
#[cfg(not(feature = "hosted"))]
unsafe extern "C" {
    static _kernel_start: u8;
    static _data: u8;
    static _edata: u8;
    static _end: u8;
    pub static KERNEL_STACK_GUARD: u8;
    pub static KERNEL_STACK: u8;
    pub static KERNEL_STACK_TOP: u8;
    pub static ARCH_STACK_GUARD: u8;
    pub static ARCH_STACK: u8;
    pub static ARCH_STACK_TOP: u8;
}

// Frame64, UserMode, and Regs now live in the shared `arch-abi` crate (the
// backend-agnostic arch↔kernel contract) and are re-exported here so existing
// `crate::Frame64` / `crate::UserMode` / `crate::Regs` paths keep resolving
// unchanged. Both the metal and interpreter backends share this one register
// ABI rather than each defining its own.
pub use arch_abi::{Frame64, Regs, UserMode};

/// Hosted entry point. Where the metal build comes up through `boot_kernel`
/// (paging, GDT/IDT, ring-1 drop) before calling `startup()`, the hosted build
/// is an ordinary process. Called from the `retroos-host` binary.
///
/// Milestone 2 bring-up: the full `startup()` path needs a disk + the software
/// MMU + threads (M3/M4), so this drives a hand-assembled guest directly
/// through the *real* arch boundary (`arch::do_arch_execute` over Unicorn,
/// `arch::mem()` over shared guest RAM, the canonical `KernelEvent`s) to prove
/// the event loop turns over end-to-end on the interpreter backend.
#[cfg(feature = "hosted")]
pub fn host_start() -> ! {
    use arch::monitor::KernelEvent;

    // Flat guest-RAM region the software CPU and `arch::mem()` share.
    arch::init_guest_ram(64 << 20);
    println!("[host] RetroOS hosted kernel — interpreter (Unicorn) arch backend");

    // Hand-assembled 32-bit guest: syscall, port OUT, a ~2k-insn delay loop
    // (exercises timer slicing), then exit.
    const CODE: u32 = 0x1000;
    const STACK: u32 = 0x8000;
    #[rustfmt::skip]
    let code: &[u8] = &[
        0xB8, 0x04,0x00,0x00,0x00,   // mov eax,4
        0xBB, 0x39,0x05,0x00,0x00,   // mov ebx,0x539
        0xCD, 0x80,                  // int 0x80      -> SoftInt(0x80), eax=4
        0xB8, 0x42,0x00,0x00,0x00,   // mov eax,0x42
        0xBA, 0xE9,0x00,0x00,0x00,   // mov edx,0xE9
        0xEE,                        // out dx,al     -> Out{port=0xE9}
        0xB9, 0x00,0x08,0x00,0x00,   // mov ecx,0x800
        0x49,                        // dec ecx   <- loop
        0x75, 0xFD,                  // jnz -3
        0xB8, 0x01,0x00,0x00,0x00,   // mov eax,1
        0xCD, 0x80,                  // int 0x80      -> SoftInt(0x80), eax=1 (exit)
        0xF4,                        // hlt
    ];
    arch::mem().write_bytes(CODE as usize, code);

    let mut vcpu = arch::Vcpu::empty();
    vcpu.regs.init_user_process(CODE, STACK);
    arch::set_current_vcpu(vcpu);

    // Read the live guest registers (updated by each `do_arch_execute`).
    let eax = || unsafe { (*(&raw const arch::REGS)).regs.rax as u32 };

    println!("[host] running guest vcpu...");
    let mut irqs = 0u32;
    loop {
        match arch::do_arch_execute() {
            KernelEvent::SoftInt(0x80) if eax() == 1 => {
                println!("[host] guest exit syscall -> done ({irqs} timer ticks)");
                arch::shutdown();
            }
            KernelEvent::SoftInt(n) => {
                println!("[host] INT {:#x} (eax={:#x}) -> serviced", n, eax());
            }
            KernelEvent::Out { port, size } => {
                println!("[host] OUT port={:#06x} size={:?} val={:#x}", port, size, eax());
            }
            KernelEvent::In { port, size } => {
                println!("[host] IN  port={:#06x} size={:?}", port, size);
            }
            KernelEvent::Irq => {
                irqs += 1;
            }
            KernelEvent::PageFault { addr } => {
                println!("[host] page fault @ {:#x} -> stopping", addr);
                arch::shutdown();
            }
            ev => {
                println!("[host] unhandled event {:?} -> stopping", ev);
                arch::shutdown();
            }
        }
    }
}

/// Panic handler (metal only — std supplies its own for the hosted build).
#[cfg(not(feature = "hosted"))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Mirror to both VGA (println) and debugcon (dbg_println) so panic
    // shows up in out.log too, not just on the QEMU display.
    println!();
    println!("\x1b[91m!!! KERNEL PANIC !!!\x1b[0m");
    dbg_println!();
    dbg_println!("!!! KERNEL PANIC !!!");

    if let Some(location) = info.location() {
        println!("at {}:{}", location.file(), location.line());
        dbg_println!("at {}:{}", location.file(), location.line());
    } else {
        println!("at <unknown location>");
        dbg_println!("at <unknown location>");
    }

    println!("  {}", info.message());
    dbg_println!("  {}", info.message());
    println!();
    dbg_println!();

    kernel::stacktrace::stack_trace();

    arch::halt_forever();
}
