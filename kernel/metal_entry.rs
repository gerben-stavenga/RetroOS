//! Metal kernel binary crate root.
//!
//! Links the backend-agnostic `kernel` rlib against the `arch-metal` backend
//! into the bootable `kernel.elf`. The real entry point is `_start`
//! (`entry.asm`) → `boot_kernel` (`kernel::boot`, cfg `target_arch = "x86"`);
//! `entry.asm` is linked as a native object, and its undefined `boot_kernel`
//! reference pulls the crt0 out of the kernel rlib. This crate root carries no
//! code — `#![no_main]`: there is no Rust `main`, the linker script's
//! `ENTRY(_start)` is the entry.
#![no_std]
#![no_main]

extern crate kernel;
