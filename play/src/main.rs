//! retroos-play — boot a RetroOS disk image with a live SDL window.
//!
//!   cargo run -p retroos-play -- bazel-bin/image_proprietary.bin \
//!       --cmd "GAMES/SKYROADS/SKYROADS.EXE" --cwd "GAMES/SKYROADS/"
//!
//! Threading: the SDL window (event pump + present) owns the MAIN thread; the
//! interpreter CPU + kernel run on a worker. All interpreter state — guest RAM,
//! the device bus — is thread-local, so every `attach_*` happens on the CPU
//! thread, before `startup()`. The two threads meet only at the backend's
//! thread-safe seams: `post_irq` (input in) and `request_frame`/`take_frame`
//! (pixels out). The window therefore stays live even when the CPU thread
//! stalls (disk I/O, a wedged guest).

mod display;

use retroos_arch_interp as arch;
use std::io::Write;

fn usage() -> ! {
    eprintln!(
        "usage: retroos-play DISK_IMAGE [--host DIR] [--cmd \"PROG ARGS\"] [--cwd DIR] [--wav FILE]"
    );
    std::process::exit(2);
}

/// Kernel debug-log sink: stderr. The window owns the video; the terminal that
/// launched us keeps the logs.
fn log_byte(b: u8) {
    let _ = std::io::stderr().write_all(&[b]);
}

fn main() {
    let mut host_dir: Option<String> = None;
    let mut cmd: Option<String> = None;
    let mut cwd: Option<String> = None;
    let mut c_root: Option<String> = None;
    let mut wav: Option<String> = None;
    let mut image: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--host" => host_dir = args.next(),
            "--cmd" => cmd = args.next(),
            "--cwd" => cwd = args.next(),
            "--c-root" => c_root = args.next(),
            "--wav" => wav = args.next(),
            _ if image.is_none() && !a.starts_with('-') => image = Some(a),
            _ => usage(),
        }
    }
    let Some(image) = image else { usage() };

    kernel::vga::set_debug_sink(log_byte);

    // The bootfs (DN + COMMAND.COM, the /boot invariant) is linked into this
    // binary the same way it is into retroos-host / kernel.elf: the Bazel
    // `bootfs_host` object supplies the `_binary_bootfs_tar_*` symbols and the
    // kernel is built `--cfg=bootfs_embedded`, so `bootfs()` reads them. (Before
    // retroos-play moved off cargo it had to load the TAR at runtime; embedding
    // keeps the windowed path a single host-platform build with no separate
    // bootfs_tar step.)

    // CPU/kernel worker: interpreter state is thread-local, so the platform is
    // composed here, on the thread that will run it.
    std::thread::spawn(move || {
        kernel::host_console_init();
        // Display: the kernel emulates the VGA and renders (single-VGA
        // design); install its present sink to park frames in the backend
        // mailbox the window thread blits from.
        lib::vga_render::set_present_sink(|w, h, px| arch::publish_frame(w, h, px));
        if let Some(dir) = &host_dir {
            arch::attach_hostfs(dir); // COM1 → /host
        }
        if let Some(path) = &wav {
            arch::attach_audio(path); // canonical audio → WAV (offline check)
        }
        arch::init_guest_ram(0);
        arch::attach_disk(&image).unwrap_or_else(|e| {
            eprintln!("retroos-play: cannot attach disk {image}: {e}");
            std::process::exit(1);
        });
        let mut config = kernel::BootConfig::empty();
        config.is_qemu = true; // no real VGA raster: fabricate 0x3DA, like QEMU
        if let Some(c) = &cmd {
            config.set_cmdline(c.as_bytes());
        }
        if let Some(c) = &cwd {
            config.set_cwd(c.as_bytes());
        }
        if let Some(c) = &c_root {
            config.set_c_root(c.as_bytes());
        }
        let mut machine = kernel::new_arch();
        kernel::startup(&mut machine, &config);
    });

    display::run() // main thread: SDL loop; exits the process on window close
}
