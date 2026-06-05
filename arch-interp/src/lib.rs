//! retroos-arch-interp — the **interpreter** arch backend.
//!
//! This crate is the software counterpart of `kernel/src/arch/`. The kernel is
//! built against exactly one `arch` backend: the bare-metal one (real x86, INT
//! 0x80, Bazel) or *this* one (a software x86 core — Unicorn = QEMU's TCG —
//! linked into a hosted `std` process). The kernel selects between them with
//! `#[cfg(feature = "hosted")] extern crate retroos_arch_interp as arch;`, so
//! every `crate::arch::*` path resolves here instead.
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
//! at `examples/poc.rs` (`cargo run -p retroos-arch-interp --example poc`).

// Re-export the backend-agnostic contract so `crate::arch::{Regs, KernelEvent,
// Irq, RawPage, PAGE_SIZE, LOW_MEM_BASE, USER_CS, ...}` resolve here exactly as
// they do through the metal backend.
pub use arch_abi::{
    Frame64, Irq, IoSize, KernelEvent, LOW_MEM_BASE, PAGE_SIZE, RawPage, Regs, UserMode,
    USER_CS, USER_CS64, USER_DS,
};

mod calls;
mod cpu;
mod desc;
mod devices;
mod machine;
mod mmu;
pub mod monitor;
mod space;
mod vcpu;

pub use calls::*;
pub use machine::{
    clean_fx_template, drain, free_page_count, get_ticks, halt_forever, inb, inw, outb, outw,
    rdtsc, shutdown, take_pending_ticks, FxState,
};
pub use space::{KernelPages, RootPageTable};
pub use vcpu::{mem, set_current_vcpu, GuestMem, Vcpu, REGS};

// Interpreter-specific host bring-up (not part of the metal surface):
// `init_guest_ram` creates the initial address space; `new_space` allocates a
// fresh one (until the kernel's thread/fork path drives this in M4);
// `attach_disk` backs the interpreted ATA ports with a host image file.
pub use vcpu::init_guest_ram;
pub use mmu::new_space;
pub use devices::attach_disk;
