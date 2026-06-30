//! `arch-metal` — the bare-metal x86 backend (ring-0 privileged supervisor:
//! interrupt handling, paging, physical memory, descriptor tables, and the arch
//! call interface for the ring-1 kernel).
//!
//! This is one of the two `arch_abi::Arch` backends (the other is the software
//! `arch-interp`). The kernel depends on it only as `crate::arch`; the metal
//! *entry* (`boot.rs`, which calls `kernel::startup`) lives kernel-side and
//! drives the bring-up functions this crate exposes.

#![no_std]

extern crate alloc;

mod backend;
mod calls;
pub mod descriptors;
pub mod irq;
pub mod monitor;
pub mod paging2;
pub mod phys_mm;
mod traps;
mod vcpu;
pub mod x86;
pub mod xhci;

// === Metal-only boot data (consumed by the bring-up here and by the kernel's
// `boot.rs` entry). On the interp backend none of this exists. ===

/// Scratch / zero page frames the paging bring-up uses.
pub static ZERO_PAGE: paging2::RawPage = unsafe { core::mem::zeroed() };
pub static mut SCRATCH: paging2::RawPage = unsafe { core::mem::zeroed() };

// Kernel-stack guard linker symbol (defined in `kernel.ld`); the `#PF` handler
// labels overflow faults against it.
unsafe extern "C" {
    pub static KERNEL_STACK_GUARD: u8;
}

/// Multiboot memory map entry (from the bootloader's info block).
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct MultibootMmapEntry {
    pub size: u32,
    pub base: u64,
    pub length: u64,
    pub typ: u32,
}

/// Multiboot info structure (from GRUB or our bootloader).
///
/// `repr(C)` reproduces the spec offsets exactly: the u16 run keeps
/// `framebuffer_addr` at offset 88, which is 8-aligned, so no padding is
/// inserted anywhere. Fields past `mmap_addr` are only valid under their
/// `flags` bit; our legacy bootloader zero-fills them (bit 12 clear), GRUB
/// fills the framebuffer block when the header requests video.
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
    pub drives_length: u32,
    pub drives_addr: u32,
    pub config_table: u32,
    pub boot_loader_name: u32,
    pub apm_table: u32,
    pub vbe_control_info: u32,
    pub vbe_mode_info: u32,
    pub vbe_mode: u16,
    pub vbe_interface_seg: u16,
    pub vbe_interface_off: u16,
    pub vbe_interface_len: u16,
    pub framebuffer_addr: u64,
    pub framebuffer_pitch: u32,
    pub framebuffer_width: u32,
    pub framebuffer_height: u32,
    pub framebuffer_bpp: u8,
    /// 0 = indexed, 1 = direct RGB, 2 = EGA text (B8000-style cells).
    pub framebuffer_type: u8,
    /// The spec text puts color_info at offset 110, but GRUB fills the block
    /// through multiboot.h's struct, where color_info is a *union containing a
    /// u32* — 4-aligned, so it really lands at 112. Observed on GRUB 2.12/OVMF:
    /// reading at 110 yields (0,0,16,8,…). Match GRUB, the only multiboot
    /// loader we use (our own bootloader zero-fills all of this).
    pub color_pad: [u8; 2],
    /// For type 1: (red_pos, red_size, green_pos, green_size, blue_pos, blue_size).
    pub color_info: [u8; 6],
}

/// `flags` bit: the framebuffer fields above are valid.
pub const MULTIBOOT_INFO_FRAMEBUFFER: u32 = 1 << 12;

// --- Re-exports for the kernel layer (ring 1) ---

// Types
pub use backend::Metal;
pub use paging2::{KernelPages, RawPage, RootPageTable, PAGE_SIZE, LOW_MEM_BASE, HEAP_END, heap_base};
pub use vcpu::{Vcpu, set_current_vcpu};
pub use irq::Irq;
pub use descriptors::{USER_CS, USER_CS64, USER_DS};

// Arch call constants + the ring-1 wrappers that issue them (the kernel-facing
// arch API; the HW backend implements them as INT 0x80 stubs in `calls.rs`).
pub use traps::arch_call;
pub use calls::*;
pub(crate) use traps::REGS;

// Power/halt entry points. The kernel layer must not toggle IF directly —
// `cli`/`sti` stay arch-private; use `halt_forever` (panic) and
// `without_irqs` (critical sections) instead.
pub use x86::shutdown;

/// Disable interrupts and halt forever. For panic / shutdown failure.
pub fn halt_forever() -> ! {
    x86::cli();
    loop { x86::hlt(); }
}

// TODO: migrate to arch calls
pub use x86::{inb, outb, inw, outw};
pub use x86::rdtsc;
pub use x86::{FxState, clean_fx_template};
pub use irq::{get_ticks, take_pending_ticks, drain};

/// Assert/deassert the CPU INTR line from the virtual PIC. On metal the real
/// 8259 drives INTR in hardware, so this is a no-op; the interpreter backend
/// uses it to make its software CPU re-check for a pending IRQ at a basic-block
/// boundary (see `retroos_arch_interp::set_irq_line`).
#[inline]
pub fn set_irq_line(_asserted: bool) {}

/// Physical free-page count, for diagnostic logging. Walks PAGE_REFS;
/// O(MAX_PAGES) but small (~64 KB scan) and only called from instrumentation.
pub fn free_page_count() -> usize {
    phys_mm::free_page_count()
}
