//! Hosted RetroOS entry. Exists only under the `hosted` feature (the metal build
//! is `#![no_main]` and boots via `entry.asm` → `boot_kernel`). A regular
//! `fn main()` that composes the interpreter's platform — hooking its device
//! ports (0xE9→stdout, ATA→image, COM1→host directory) — then hands off to the
//! same `kernel::startup()` the metal crt0 calls.
//!
//!   cargo run -p kernel -- disk.img                 # boot the real kernel
//!   cargo run -p kernel -- --host DIR disk.img      # ...with /host = DIR
//!   cargo run -p kernel -- program.elf              # run one 32-bit Linux ELF directly
//!   cargo run -p kernel                             # arch-boundary demo

use retroos_arch_interp as arch;
use std::io::Read;

fn main() {
    let mut host_dir: Option<String> = None;
    let mut input: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--host" | "-h" => host_dir = args.next(),
            _ => input = Some(a),
        }
    }

    // Compose the platform: hook the device ports, and give the VGA console a
    // valid (scratch) framebuffer — its output reaches stdout via 0xE9.
    arch::register_debugcon(); // 0xE9 → stdout (the console stream)
    kernel::host_console_init();
    if let Some(dir) = host_dir {
        arch::attach_hostfs(&dir); // COM1 → /host
    }

    let Some(path) = input else {
        kernel::host_run_demo()
    };

    let mut data = Vec::new();
    std::fs::File::open(&path)
        .and_then(|mut f| f.read_to_end(&mut data))
        .unwrap_or_else(|e| {
            eprintln!("retroos-host: cannot read {path}: {e}");
            std::process::exit(1);
        });

    if data.starts_with(b"\x7fELF") {
        // A bare executable: run it directly (no disk).
        kernel::host_run_elf(path.as_bytes(), data);
    }

    // Otherwise treat it as a disk image: hook the ATA ports onto it and boot
    // the same kernel::startup() the metal crt0 calls.
    arch::init_guest_ram(0);
    arch::attach_disk(&path).unwrap_or_else(|e| {
        eprintln!("retroos-host: cannot attach disk {path}: {e}");
        std::process::exit(1);
    });
    kernel::startup();
}
