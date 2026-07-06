//! retroos-arch-interp — the **hosted** arch backend.
//!
//! This crate is the software counterpart of `kernel/src/arch/`. The kernel is
//! built against exactly one `arch` backend: the bare-metal one (real x86, INT
//! 0x80, Bazel) or *this* one (linked into a hosted `std` process). The kernel
//! selects between them with
//! `#[cfg(feature = "hosted")] extern crate retroos_arch_interp as arch;` so
//! every `crate::arch::*` path resolves here instead.
//!
//! The CPU under the hosted guest is itself a compile-time choice between two
//! **engines** (see `engine.rs`): `tcg` (default — the Unicorn/QEMU-TCG
//! software core) or `kvm` (real hardware execution via `/dev/kvm`). Both run
//! the same machine model — the shared phys frames, real x86 page tables,
//! descriptor tables, and device bus above the engine seam.
//!
//! Because of that, this crate must present the **identical public surface**
//! that `kernel/src/arch/mod.rs` re-exports — same type names, same function
//! signatures — over `arch-abi` (the shared pure-data contract) plus Unicorn.
//!
//! ## Status: Milestone 1 (structural seam)
//!
//! The surface is complete and the hosted kernel compiles + links against it.
//! The pure-data pieces (the `arch-abi` re-exports, `FxState`, the event/IRQ
//! enums, the call-number constants, the backend types) are real. The runtime
//! behaviour — running a Vcpu on Unicorn, the software MMU, and the 18 arch
//! calls — is `unimplemented!()` here and gets filled in by later milestones:
//!
//! * **M2** `do_arch_execute` over Unicorn slices + `GuestMem` over guest RAM.
//! * **M3** the software MMU and the paging-family arch calls.
//! * **M4** COW fork, LDT/TLS, ELF load → run a 32-bit flat-PM ELF.
//!
//! The self-contained Unicorn proof-of-concept that seeded this backend lives
//! at `examples/poc.rs` (`bazelisk run //arch-interp:poc --platforms=@platforms//host`).

// Re-export the backend-agnostic contract so `crate::arch::{Regs, KernelEvent,
// Irq, RawPage, PAGE_SIZE, LOW_MEM_BASE, USER_CS, ...}` resolve here exactly as
// they do through the metal backend.
pub use arch_abi::{
    Frame64, Irq, IoSize, KernelEvent, LOW_MEM_BASE, PAGE_SIZE, RawPage, Regs, UserMode,
    USER_CS, USER_CS64, USER_DS,
};

// Exactly one execution engine must be selected (`tcg` is the default feature).
#[cfg(all(feature = "tcg", feature = "kvm"))]
compile_error!("features `tcg` and `kvm` are mutually exclusive engine selections \
                (build the kvm engine with `--no-default-features --features kvm`)");
#[cfg(not(any(feature = "tcg", feature = "kvm")))]
compile_error!("select an execution engine: feature `tcg` (default) or `kvm`");
#[cfg(all(feature = "kvm", not(target_os = "linux")))]
compile_error!("the `kvm` engine requires Linux (/dev/kvm)");

mod backend;
mod calls;
#[cfg(feature = "tcg")]
mod cpu;
mod desc;
mod devices;
mod engine;
mod hostfs;
mod net;
#[cfg(feature = "kvm")]
mod kvm;
mod machine;
mod mmu;
mod paging;
mod phys;
mod screendump;
mod space;
mod sysdesc;
mod tty;
mod vcpu;
mod vga;

pub use backend::Interp;
pub use calls::*;
pub use machine::{
    clean_fx_template, drain, free_page_count, get_ticks, halt_forever, inb, inl, inw, outb, outl,
    outw, post_irq, rdtsc, set_irq_line, shutdown, take_pending_ticks, FxState,
};
// Interactive console (hosted `main` drives input): raw terminal mode; key
// events are posted via `post_irq` and surface to the kernel through `drain`.
pub use tty::enter_raw_mode;
pub use space::{KernelPages, RootPageTable};
pub use vcpu::{mem, GuestMem, Vcpu, REGS};

// Interpreter-specific host bring-up (not part of the metal surface):
// `init_guest_ram` creates the initial address space; `new_space` allocates a
// fresh one (until the kernel's thread/fork path drives this in M4);
// `attach_disk` backs the interpreted ATA ports with a host image file.
pub use vcpu::init_guest_ram;
pub use mmu::new_space;
// Platform device composition (the hosted `main` hooks ports): the PortIo trait
// + `register` for custom devices, and convenience hooks for the built-ins.
pub use devices::{
    attach_audio, attach_disk, attach_fw_cfg, attach_hostfs, register, register_debugcon,
    register_debugcon_file, PortIo,
};
// Native host-fs backend (hosted "punch-through"): `install_native_hostfs` sets
// the root; the `host_*` fns are the primitive hooks the kernel's
// `install_host_backend` points at (direct std::fs, no COM1).
pub use hostfs::{
    host_clunk, host_create, host_dir_exists, host_open, host_read, host_readdir,
    host_remove, host_write, install_native_hostfs,
};
// Native socket backend (hosted "punch-through"): `install_native_sockets`
// enables it; the `host_sock_*` fns are the primitive hooks the kernel's
// `install_socket_backend` points at (direct std::net).
pub use net::{
    host_sock_accept, host_sock_bind, host_sock_close, host_sock_connect,
    host_sock_getpeername, host_sock_getsockname, host_sock_listen, host_sock_recvfrom,
    host_sock_sendto, host_sock_setsockopt, host_sock_shutdown, host_sock_socket,
    install_native_sockets,
};
// Host-side VGA text-screen snapshotting (headless inspection of the guest's
// 0xB8000 text buffer): `set_dump_path` arms it, `request_vga_dump` flips the
// flag from a watcher thread, the CPU thread renders at the next slice boundary.
pub use screendump::{enable_live as enable_live_console, request as request_vga_dump, set_dump_path};
// Display frame mailbox: the kernel emulates the VGA and renders (single-VGA
// design); this backend only carries pixels. The hosted `main` publishes
// frames from the kernel's present sink; retroos-play takes them and blits;
// screenshots peek. Presentation (SDL et al.) lives in the consuming binary.
pub use vga::{peek_frame, publish as publish_frame, take_frame};
