//! retroos-play — boot a host directory with a live SDL window.
//!
//!   ./run.sh hosted --directory /path/to/root \
//!       --cmd "GAMES/SKYROADS/SKYROADS.EXE" --cwd "GAMES/SKYROADS/"
//!
//! Threading: the SDL window (event pump + present) owns the MAIN thread; the
//! interpreter CPU + kernel run on a worker. All interpreter state — guest RAM,
//! the device bus — is thread-local, so every `attach_*` happens on the CPU
//! thread, before `startup()`. A separate Linux thread runs the kernel media
//! worker on shared resident buffers. The window meets the CPU thread at the backend's
//! thread-safe seams for IRQs and completed frames.
//! The window therefore stays live even when the CPU thread
//! stalls (disk I/O, a wedged guest).

mod audio;
mod display;

use retroos_arch_interp as arch;
use kernel::kernel::vfs::Filesystem;
use std::io::Write;

fn usage() -> ! {
    eprintln!(
        "usage: retroos-play DIRECTORY [--cmd \"PROG ARGS\"] [--cwd DIR] [--wav FILE] [--no-audio]"
    );
    std::process::exit(2);
}

/// Kernel debug-log sink: stderr. The window owns the video; the terminal that
/// launched us keeps the logs.
fn log_byte(b: u8) {
    let _ = std::io::stderr().write_all(&[b]);
}

fn main() {
    let mut cmd: Option<String> = None;
    let mut cwd: Option<String> = None;
    let mut c_root: Option<String> = None;
    let mut wav: Option<String> = None;
    let mut no_audio = false;
    let mut directory: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--cmd" => cmd = args.next(),
            "--cwd" => cwd = args.next(),
            "--c-root" => c_root = args.next(),
            "--wav" => wav = args.next(),
            "--no-audio" => no_audio = true,
            _ if directory.is_none() && !a.starts_with('-') => directory = Some(a),
            _ => usage(),
        }
    }
    if directory.is_none() {
        usage();
    }

    kernel::kernel::klog::init();
    lib::log::set_debug_sink(log_byte);

    arch::install_input_sink(kernel::kernel::irq_dispatch::post);

    let sdl = sdl2::init().expect("SDL init");
    let _playback = if no_audio {
        None
    } else {
        match audio::open(&sdl) {
            Ok(device) => Some(device),
            Err(error) => {
                eprintln!("Host audio unavailable: {error}");
                None
            }
        }
    };

    // CPU/kernel worker: interpreter state is thread-local, so the platform is
    // composed here, on the thread that will run it.
    std::thread::spawn(move || {
        kernel::host_console_init();
        // Inject the interp backend into the backend-agnostic kernel: the port
        // I/O hooks and the host-environment facts the platform probe reads.
        // Storage is supplied directly as host directories below.
        kernel::install_portio(kernel::PortIo {
            now_ns: arch::now,
            cycles: arch::cycles,
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
            framebuffer: || None, // hosted still presents through the window sink
            debug: kernel::DebugSink::HostStdout,
            is_metal: false,
        });
        arch::register_rtc();
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
        kernel::kernel::display::install_external_display(display::ENDPOINT);

        if let Some(path) = &wav {
            arch::attach_audio(path); // canonical audio → WAV (offline check)
        }
        let (ram, bytes) = arch::physical_ram();
        let paging = arch::boot_paging_frames();
        unsafe { kernel::kernel::phys_mm::install_direct_ram(ram, bytes); }
        let ownership = kernel::kernel::platform::init_memory(arch::frame_layout(), &[paging], u64::MAX);

        let root = hosted::HostFs::new(directory.as_deref().unwrap_or(".")).unwrap_or_else(|e| {
            eprintln!("cannot open host directory: {e}");
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
        config.set_c_root(c_root.as_deref().unwrap_or(if root.dir_exists(b"home/retroos") { "/home/retroos" } else { "/" }).as_bytes());
        hosted::start_media_worker();
        let storage = kernel::kernel::startup::Storage::Root(Box::leak(Box::new(root)));
        unsafe { arch::boot(ownership, &config, storage, kernel::startup) }
    });

    display::run(&sdl) // main thread: SDL loop; exits the process on window close
}
