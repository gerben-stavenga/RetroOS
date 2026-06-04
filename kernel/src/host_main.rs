//! Hosted RetroOS binary: the kernel running as an ordinary process on top of
//! the `arch-interp` software-CPU backend (the gVisor / User-Mode-Linux shape).
//!
//! The bare-metal build has no `main` (it boots via `entry.asm` → `boot_kernel`);
//! this entry exists only for the hosted (`std` + cargo) build. All the real
//! work lives in `kernel::host_start`, inside the kernel library, so this stays
//! a thin shim.

fn main() {
    kernel::host_start()
}
