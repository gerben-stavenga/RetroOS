// `no_std` for the bare-metal build; the hosted build enables `std` so console
// output can route to stdout instead of x86 VGA MMIO / port 0xE9.
#![cfg_attr(not(feature = "std"), no_std)]

pub mod elf;
pub mod md5;
pub mod tar;
pub mod vga;
