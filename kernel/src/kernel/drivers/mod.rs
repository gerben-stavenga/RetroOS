//! Hardware device drivers.
//!
//! Everything here talks to a *specific* piece of silicon. Nothing above this
//! layer names a driver: the kernel-side APIs one level up — `block` (disks),
//! `sound` (PCM), `console` (input) — own the policy and dispatch down here,
//! and the personalities in `dos/` / `linux/` call only those APIs.
//!
//! Drivers reach the machine through `kernel::portio` (the injected
//! `inb`/`outb` table) or `kernel::pci` config space, never through a bespoke
//! `Arch` method — `trait Arch` stays minimal.

pub mod ac97;
pub mod alc298_amp;
pub mod hda;
pub mod hdd;
pub mod nvme;
