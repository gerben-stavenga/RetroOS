//! Hardware device drivers and reusable device transports.
//!
//! Chip drivers use shared transports such as DMA and MHI. Kernel-side APIs
//! one level up — `block` (disks), `wifi` (radios),
//! `sound` (PCM), `console` (input) — own the policy and dispatch down here,
//! and the personalities in `dos/` / `linux/` call only those APIs.
//!
//! Drivers reach the machine through `kernel::portio` (the injected
//! `inb`/`outb` table) or `kernel::pci` config space, never through a bespoke
//! `Arch` method — `trait Arch` stays minimal.

pub mod ac97;
pub mod alc298_amp;
pub mod hda;
pub mod sb16;
pub mod isapnp;
pub mod sb_guest;
pub mod vga_hw;
pub mod nvidia_vga;
pub mod hdd;
pub mod nvme;
pub mod storage;
pub mod dma;
pub mod ahci;
pub mod uart16550;

pub mod isa_lpc;
pub mod virtio_net;
pub mod rdrand;
pub mod wcn785x;
pub mod mhi;
pub mod ce;

pub mod qca_dp;
pub(crate) mod srng;
