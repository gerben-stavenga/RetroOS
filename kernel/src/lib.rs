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

// The hosted binary calls the same `kernel::startup` symbol the metal crt0
// (`arch/boot.rs`) calls — the backend difference lives below the arch boundary
// (the interpreter serves the disk via its port handlers), so `startup` itself
// is identical on both. Re-exported here so `main` can reach it.
#[cfg(feature = "hosted")]
pub use kernel::startup::startup;

/// Hosted: run a 32-bit Linux ELF (already read into `data` by the binary)
/// through the *real* kernel path — thread creation, the ELF loader, the Linux
/// personality syscalls, and the real `event_loop` — all over the interpreter
/// arch backend, with no disk/filesystem boot. Mirrors what `run_init_program`
/// does for DOS. `path` is used for argv[0] / diagnostics.
#[cfg(feature = "hosted")]
pub fn host_run_elf(path: &[u8], data: alloc::vec::Vec<u8>) -> ! {
    use kernel::thread;

    arch::init_guest_ram(0);
    kernel::heap::init();
    thread::init_threading();

    // Console stdin pipe (kernel is the phantom writer, as in startup()).
    let cpipe = kernel::kpipe::alloc().expect("console pipe");
    kernel::kpipe::add_writer(cpipe);
    thread::set_console_pipe(cpipe);

    // Fresh process thread in the initial (active) address space.
    let tid = {
        let t = thread::create_thread(None, RootPageTable::empty(), true).expect("create thread");
        t.kernel.fds[0] = thread::FdKind::PipeRead(cpipe);
        t.kernel.fds[1] = thread::FdKind::ConsoleOut;
        t.kernel.fds[2] = thread::FdKind::ConsoleOut;
        t.kernel.tid as usize
    };
    kernel::kpipe::add_reader(cpipe);

    // Load the ELF (segments + argv/envp/auxv stack) into the active space and
    // set the thread's entry registers.
    let argv = alloc::vec![path.to_vec()];
    if let Err(e) = kernel::linux::exec_elf_into(tid, &data, path, &argv) {
        dbg_println!("[host] exec failed: errno {}", e);
        arch::shutdown();
    }

    // Seed the live execution context and run the real kernel event loop.
    let t = thread::get_thread(tid).expect("thread");
    arch::set_current_vcpu(t.kernel.vcpu);
    dbg_println!("[host] running 32-bit Linux ELF, interpreted");
    kernel::startup::event_loop(tid);
    dbg_println!("[host] guest exited");
    arch::shutdown();
}

/// Hosted no-argument fallback: a hand-assembled guest driven directly through
/// the arch boundary (syscall, port OUT, demand-paged write, timer slicing,
/// exit). Proves the interpreter mechanism without the full kernel.
#[cfg(feature = "hosted")]
pub fn host_run_demo() -> ! {
    use arch::monitor::KernelEvent;
    arch::init_guest_ram(0);
    println!("[host] RetroOS hosted kernel — interpreter (Unicorn) arch backend");

    // Above the 64 KiB null-pointer guard (the MMU faults guard-range accesses).
    const CODE: u32 = 0x0010_0000;
    const STACK: u32 = 0x0020_0000;
    const SCRATCH: u32 = 0x0040_0000;
    #[rustfmt::skip]
    let code: &[u8] = &[
        0xB8, 0x04,0x00,0x00,0x00,   // mov eax,4
        0xBB, 0x39,0x05,0x00,0x00,   // mov ebx,0x539
        0xCD, 0x80,                  // int 0x80
        0xB8, 0x42,0x00,0x00,0x00,   // mov eax,0x42
        0xBA, 0xE9,0x00,0x00,0x00,   // mov edx,0xE9
        0xEE,                        // out dx,al
        0xA3, 0x00,0x00,0x40,0x00,   // mov [0x00400000],eax
        0xB9, 0x00,0x08,0x00,0x00,   // mov ecx,0x800
        0x49,                        // dec ecx
        0x75, 0xFD,                  // jnz -3
        0xB8, 0x01,0x00,0x00,0x00,   // mov eax,1
        0xCD, 0x80,                  // int 0x80 (exit)
        0xF4,                        // hlt
    ];
    arch::mem().write_bytes(CODE as usize, code);

    let mut vcpu = arch::Vcpu::empty();
    vcpu.regs.init_user_process(CODE, STACK);
    arch::set_current_vcpu(vcpu);

    let eax = || unsafe { (*(&raw const arch::REGS)).regs.rax as u32 };
    println!("[host] running guest vcpu...");
    let mut irqs = 0u32;
    loop {
        match arch::do_arch_execute() {
            KernelEvent::SoftInt(0x80) if eax() == 1 => {
                let scratch: u32 = arch::mem().read(SCRATCH as usize);
                println!("[host] guest scratch[{:#x}] = {:#x} (demand-paged)", SCRATCH, scratch);
                println!("[host] guest exit syscall -> done ({irqs} timer ticks)");
                arch::shutdown();
            }
            KernelEvent::SoftInt(n) => println!("[host] INT {:#x} (eax={:#x}) -> serviced", n, eax()),
            KernelEvent::Out { port, size } =>
                println!("[host] OUT port={:#06x} size={:?} val={:#x}", port, size, eax()),
            KernelEvent::In { port, size } => println!("[host] IN  port={:#06x} size={:?}", port, size),
            KernelEvent::Irq => irqs += 1,
            ev => { println!("[host] unhandled event {:?} -> stopping", ev); arch::shutdown(); }
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
