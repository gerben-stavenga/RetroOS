//! Hosted RetroOS binary: the kernel running as an ordinary process on top of
//! the `arch-interp` software-CPU backend (the gVisor / User-Mode-Linux shape).
//!
//! The bare-metal build has no `main` (it boots via `entry.asm` → `boot_kernel`);
//! this entry exists only for the hosted (`std` + cargo) build. It does the
//! std-side I/O (reading argv and the ELF file) and hands off to the kernel
//! library, which is `no_std`.
//!
//!   cargo run -p kernel -- path/to/program.elf   # run a 32-bit Linux ELF
//!   cargo run -p kernel                            # arch-boundary demo

fn main() {
    match std::env::args().nth(1) {
        Some(path) => {
            let data = std::fs::read(&path).unwrap_or_else(|e| {
                eprintln!("retroos-host: cannot read {path}: {e}");
                std::process::exit(1);
            });
            kernel::host_run_elf(path.as_bytes(), data)
        }
        None => kernel::host_run_demo(),
    }
}
