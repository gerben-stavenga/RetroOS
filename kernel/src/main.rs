//! Hosted RetroOS entry. Exists only under the `hosted` feature (the metal build
//! is `#![no_main]` and boots via `entry.asm` → `boot_kernel`). A regular
//! `fn main()` that does the std-side I/O the `no_std` kernel can't, then hands
//! off to the kernel:
//!
//!   cargo run -p kernel -- disk.img      # boot the real kernel::startup()
//!                                         #   (disk served via interpreted ATA ports)
//!   cargo run -p kernel -- program.elf   # run one 32-bit Linux ELF directly
//!   cargo run -p kernel                  # arch-boundary demo

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        kernel::host_run_demo()
    };

    let data = std::fs::read(&path).unwrap_or_else(|e| {
        eprintln!("retroos-host: cannot read {path}: {e}");
        std::process::exit(1);
    });

    if data.starts_with(b"\x7fELF") {
        // A bare executable: run it directly (no disk).
        kernel::host_run_elf(path.as_bytes(), data);
    }

    // Otherwise treat it as a disk image: back the interpreted ATA ports with it
    // and boot the *same* kernel::startup() the metal crt0 calls — the backend
    // difference lives below the arch boundary (the port handlers serve the disk).
    retroos_arch_interp::init_guest_ram(0);
    retroos_arch_interp::attach_disk(&path).unwrap_or_else(|e| {
        eprintln!("retroos-host: cannot attach disk {path}: {e}");
        std::process::exit(1);
    });
    kernel::startup();
}
