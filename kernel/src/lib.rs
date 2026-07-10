//! RetroOS kernel — a pure library over the `arch_abi::Arch` trait.
//!
//! The kernel is generic over its arch backend: every function that touches
//! the machine takes `machine: &mut A` with `A: Arch`, and thread state
//! carries `Vcpu<A>` / `A::Fx`. No backend crate is linked here —
//! composition happens in the ENTRY crates, which pick the backend and call
//! `startup`:
//!
//!   * `entry-metal` — arch-metal (real x86), linked with `entry.asm` into kernel.elf.
//!   * `entry-hosted` — arch-interp (tcg or kvm engine), consumed by the retroos-host and retroos-play binaries.
//!
//! Host-side glue (platform probe, log sinks, symbolizers) is injected by the
//! entries through plain function hooks — no `cfg` anywhere in this crate.

#![no_std]

extern crate alloc;
extern crate rustc_demangle;

// The bare-metal entry glue lives with the kernel but is inherently 32-bit
// x86 (the `boot_kernel` crt0 called by `entry.asm`, the GOP fbcon console,
// and the metal linker symbols). It compiles ONLY for the metal target
// (`target_arch = "x86"`); the hosted build (x86-64) is an ordinary binary
// whose `main.rs` composes the interp backend. This is an ARCHITECTURE gate,
// not a backend feature — there is no `hosted` cfg anywhere in the kernel.
#[cfg(target_arch = "x86")]
extern crate arch_metal as arch;

#[cfg(target_arch = "x86")]
#[path = "arch/boot.rs"]
mod boot;

#[cfg(target_arch = "x86")]
#[path = "arch/fbcon.rs"]
pub mod fbcon;

// The kernel tree. Public: the entry crates compose from it (startup,
// event_loop, thread creation, the Linux ELF loader, kpipe, ...).
pub mod kernel;

// Re-export kernel submodules so arch/ code can use crate::thread, crate::dos, etc.
pub use kernel::dos;
pub use kernel::thread;

// The text console lives in the kernel (it crosses the arch boundary for the
// 0xE9 debug port); `print!`/`println!`/`dbg_*!` are defined there (macro_export
// puts them at the crate root, so `crate::println!` keeps working).
pub mod vga;
// The console macros live in `lib`; re-exporting them at the crate root makes
// both bare `println!` (crate-wide, via this 2018 path import) and the explicit
// `crate::println!` / `crate::dbg_println!` paths the kernel uses resolve.
pub use lib::{print, println, dbg_print, dbg_println};

// The backend-agnostic arch contract, re-exported at the crate root: the
// kernel is written against exactly this surface.
pub use arch_abi::{
    Arch, BootConfig, Frame64, GuestBytes, Irq, KernelEvent, Regs, UserMode, Vcpu,
    parse_debug_watch, LOW_MEM_BASE, PAGE_SIZE, RawPage,
};

pub use kernel::startup::startup;
pub use kernel::platform::{set_host_env, DebugSink, HostEnv};
pub use kernel::portio::{install_portio, PortIo};
pub use kernel::hostfs::{install_host_backend, host_backend_installed, HostBackendHooks};
pub use kernel::net::{install_socket_backend, socket_backend_installed, SocketHooks};

/// Hosted: point the VGA console framebuffer at a scratch buffer so its writes
/// (clear/scroll/putchar) don't dereference the unmapped `0xB8000` host
/// address. Console output reaches stdout via the injected debug sink, so the
/// framebuffer content itself is unused. Backend-agnostic.
pub fn host_console_init() {
    let fb = alloc::boxed::Box::leak(alloc::vec![0u16; 80 * 25].into_boxed_slice());
    vga::vga().base = fb.as_mut_ptr() as usize;
}

/// Hosted: run a 32-bit Linux ELF (already read into `data`) through the real
/// kernel path — thread creation, the ELF loader, the Linux personality, and
/// the real `event_loop` — over whatever backend the entry injected, with no
/// disk boot. `path` is used for argv[0] / diagnostics.
pub fn host_run_elf<A: Arch>(
    machine: &mut A,
    path: &[u8],
    data: alloc::vec::Vec<u8>,
    argv: alloc::vec::Vec<alloc::vec::Vec<u8>>,
) -> ! {
    use kernel::thread;

    let mut threads = thread::init_threading::<A>();
    let cpipe = kernel::kpipe::alloc().expect("console pipe");
    kernel::kpipe::add_writer(cpipe);
    thread::set_console_pipe(cpipe);

    let tid = {
        let t = thread::create_thread(&mut threads, machine, None, A::PageTable::default(), true)
            .expect("create thread");
        t.kernel.fds[0] = thread::FdKind::PipeRead(cpipe);
        t.kernel.fds[1] = thread::FdKind::ConsoleOut;
        t.kernel.fds[2] = thread::FdKind::ConsoleOut;
        t.kernel.tid as usize
    };
    kernel::kpipe::add_reader(cpipe);

    let argv = if argv.is_empty() { alloc::vec![path.to_vec()] } else { argv };
    if let Err(e) = kernel::linux::exec_elf_into(machine, &mut threads, tid, &data, path, &argv) {
        dbg_println!("[host] exec failed: errno {}", e);
        kernel::hda::emergency_quiesce(); // codec must not ride into poweroff unparked
        machine.shutdown();
    }

    dbg_println!("[host] running 32-bit Linux ELF");
    kernel::startup::event_loop(machine, &mut threads, tid);
    dbg_println!("[host] guest exited");
    kernel::hda::emergency_quiesce(); // codec must not ride into poweroff unparked
    machine.shutdown();
}

/// The embedded boot filesystem: a TAR (DN + COMMAND.COM + fallback
/// CONFIG.SYS) linked in as raw bytes (`//:bootfs_tar` → objcopy → the
/// `_binary_bootfs_tar_*` symbols), so /boot ALWAYS exists, mounted on top
/// of whatever the root is — a bare kernel.elf from someone's GRUB, an
/// imageless hosted run, anything. Every build links a bootfs object; None
/// only for the intentionally-empty TAR of the bare kernel (`kernel_elf_bare`
/// / `retroos-host-bare`, used by the in-OS toolchain to break the
/// COMMAND.COM cycle).
pub fn bootfs() -> Option<&'static [u8]> {
    unsafe extern "C" {
        static _binary_bootfs_tar_start: u8;
        static _binary_bootfs_tar_end: u8;
    }
    let start = (&raw const _binary_bootfs_tar_start) as usize;
    let end = (&raw const _binary_bootfs_tar_end) as usize;
    // A zero first byte is TAR end-of-archive: the bare kernel links an empty
    // TAR (objcopy can't embed 0 bytes), which counts as "no bootfs".
    if end - start < 512 || unsafe { *(start as *const u8) } == 0 {
        return None;
    }
    Some(unsafe { core::slice::from_raw_parts(start as *const u8, end - start) })
}

// Metal linker symbols. Stacks and their guard pages live at the tail of .bss
// (see kernel.ld); only their addresses matter to Rust, so they're opaque
// externs. Metal entry (`boot.rs`) unmaps the guard pages so a kernel-stack
// overflow takes a clean #PF. x86-only: the hosted process uses std's stack.
#[cfg(target_arch = "x86")]
unsafe extern "C" {
    pub static KERNEL_STACK_GUARD: u8;
    pub static KERNEL_STACK: u8;
    pub static KERNEL_STACK_TOP: u8;
    pub static ARCH_STACK_GUARD: u8;
    pub static ARCH_STACK: u8;
    pub static ARCH_STACK_TOP: u8;
}
