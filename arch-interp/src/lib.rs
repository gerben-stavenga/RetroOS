//! Independent hosted x86 backend implementing arch-abi.
//! TCG implements the contract in the host; KVM runs arch-metal in the VM.

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
#[cfg(feature = "tcg")]
mod calls;
#[cfg(feature = "tcg")]
mod cpu;
#[cfg(feature = "tcg")]
mod desc;
mod devices;
mod engine;
mod net;
#[cfg(feature = "kvm")]
mod kvm;
mod machine;

#[cfg(feature = "tcg")]
mod paging;
#[cfg(feature = "kvm")]
use kvm::paging;
mod phys;
mod screendump;
mod space;
#[cfg(feature = "tcg")]
mod sysdesc;
mod tty;
mod vcpu;
mod vga;

pub use backend::Interp;
#[cfg(feature = "tcg")]
pub use calls::*;
pub mod suite_control;

pub use machine::{
    clean_fx_template, install_input_sink, halt_forever, inb, inl, insw, inw, now, outb, outl,
    outsw, outw, post_irq, shutdown, FxState,
};
// Interactive console (hosted `main` drives input): raw terminal mode; key
// events are delivered by `post_irq` to the entry-installed device sink.
pub use tty::enter_raw_mode;
pub use space::AddressSpace;
pub use vcpu::{mem, GuestMem, Vcpu, REGS};

// One-time host setup; runtime memory operations use arch-abi.
pub use vcpu::boot;
// Platform device composition (the hosted `main` hooks ports): the PortIo trait
// + `register` for custom devices, and convenience hooks for the built-ins.
pub use devices::{
    attach_audio, attach_fw_cfg, register, register_debugcon,
    register_debugcon_file, register_rtc, PortIo,
};
// Native socket backend (hosted "punch-through"): `install_native_sockets`
// enables it; the `host_sock_*` fns implement the typed hooks the kernel's
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
pub use screendump::{enable_live as enable_live_console, request as request_vga_dump, set_dump_path, write_suite_frame};
// Display frame mailbox: the kernel emulates the VGA and renders (single-VGA
// design); this backend only carries pixels. The hosted `main` publishes
// frames from the kernel's present sink; retroos-play takes them and blits;
// screenshots peek. Presentation (SDL et al.) lives in the consuming binary.
pub use vga::{peek_frame, publish as publish_frame, recycle_frame, take_frame};

pub use phys::{boot_paging_frames, frame_layout, ram as physical_ram};

#[cfg(test)]
extern crate self as retroos_arch_interp;
#[cfg(test)]
#[path = "../tests/mmu.rs"]
mod mmu_tests;
#[cfg(test)]
pub(crate) use mmu_tests::test_memory;
