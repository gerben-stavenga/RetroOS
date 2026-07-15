//! retroos-play — boot a RetroOS disk image with a live SDL window.
//!
//!   ./run.sh hosted -i proprietary \
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
        "usage: retroos-play (DISK_IMAGE | --host DIR) [--cmd \"PROG ARGS\"] [--cwd DIR] [--wav FILE]"
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
    // Either a disk image or a `--host DIR` (the live host filesystem as root)
    // is required — the same as `retroos-host`. `--host` alone boots on the real
    // host tree (`Media::HostRoot`); an image boots the ext4 root (`DiskRoot`).
    if image.is_none() && host_dir.is_none() {
        usage();
    }

    kernel::vga::set_debug_sink(log_byte);

    // The bootfs (DN + COMMAND.COM, the /boot invariant) is linked into this
    // binary the same way it is into retroos-host / kernel.elf: the Bazel
    // `bootfs_host` object supplies the `_binary_bootfs_tar_*` symbols that
    // `bootfs()` reads — the windowed path is a single host-platform build
    // with no separate bootfs_tar step.

    // CPU/kernel worker: interpreter state is thread-local, so the platform is
    // composed here, on the thread that will run it.
    std::thread::spawn(move || {
        kernel::host_console_init();
        // Inject the interp backend into the backend-agnostic kernel: the port
        // I/O hooks (the deep driver call sites — `hdd::probe`, the vPIC/PIT —
        // reach the interp's port bus through these, never via `&mut Arch`) and
        // the host-environment facts the platform probe reads. `retroos-host`
        // does the identical injection in `install_hosted_backend`; without it
        // the port hooks stay `NONE`, `hdd::probe` reads garbage, and the disk
        // is never detected (Diskless, only the embedded bootfs shows).
        kernel::install_portio(kernel::PortIo {
            inb: arch::inb,
            inw: arch::inw,
            inl: arch::inl,
            insw: arch::insw,
            outb: arch::outb,
            outw: arch::outw,
            outl: arch::outl,
            outsw: arch::outsw,
        });
        kernel::set_host_env(kernel::HostEnv {
            fbcon_active: || false,
            debug: kernel::DebugSink::HostStdout,
            is_metal: false,
        });
        // Native socket backend (hosted "punch-through" → host std::net); the
        // socket table is thread-local, so install it on this CPU/kernel thread.
        arch::install_native_sockets();
        kernel::install_socket_backend(kernel::SocketHooks {
            socket: arch::host_sock_socket,
            connect: arch::host_sock_connect,
            bind: arch::host_sock_bind,
            listen: arch::host_sock_listen,
            accept: arch::host_sock_accept,
            sendto: arch::host_sock_sendto,
            recvfrom: arch::host_sock_recvfrom,
            setsockopt: arch::host_sock_setsockopt,
            getsockname: arch::host_sock_getsockname,
            getpeername: arch::host_sock_getpeername,
            shutdown: arch::host_sock_shutdown,
            close: arch::host_sock_close,
        });
        // Display: the kernel emulates the VGA and renders (single-VGA
        // design); install its present sink to park frames in the backend
        // mailbox the window thread blits from.
        lib::vga_render::set_present_sink(arch::publish_frame);
        if let Some(dir) = &host_dir {
            // Native host-fs backend (the hosted "punch-through"): /host is
            // served by direct std::fs calls, not byte-serial COM1. Install the
            // std::fs server root on this (CPU) thread and wire its primitive
            // hooks into the one kernel library — same injection shape as
            // install_portio above.
            arch::install_native_hostfs(dir);
            kernel::install_host_backend(kernel::HostBackendHooks {
                open: arch::host_open,
                read: arch::host_read,
                readdir: arch::host_readdir,
                dir_exists: arch::host_dir_exists,
                create: arch::host_create,
                write: arch::host_write,
                clunk: arch::host_clunk,
                remove: arch::host_remove,
            });
        }
        if let Some(path) = &wav {
            arch::attach_audio(path); // canonical audio → WAV (offline check)
        }
        arch::init_guest_ram(0);
        if let Some(image) = &image {
            arch::attach_disk(image).unwrap_or_else(|e| {
                eprintln!("retroos-play: cannot attach disk {image}: {e}");
                std::process::exit(1);
            });
        }
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
        let mut machine = arch::Interp;
        // The screen license (see lib::vga::Screen): one per boot, moved in.
        kernel::startup(&mut machine, &config, kernel::vga::Screen::new());
    });

    display::run() // main thread: SDL loop; exits the process on window close
}
