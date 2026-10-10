//! Hosted RetroOS entry. Exists only under the `hosted` feature (the metal build
//! is `#![no_main]` and boots via `entry.asm` → `boot_kernel`). A regular
//! `fn main()` that composes the interpreter's platform — hooking its device
//! ports (0xE9→stdout, ATA→image, COM1→host directory) — then hands off to the
//! same `kernel::startup()` the metal crt0 calls.
//!
//!   retroos-host disk.img                  # boot the real kernel
//!   retroos-host --host DIR disk.img       # ...with /host = DIR
//!   retroos-host --cmd "PROG ARGS" disk.img  # boot straight into PROG, then halt
//!   retroos-host program.elf [args...]     # run one 32-bit Linux ELF directly
//!   retroos-host boot-bundle/bin/busybox sh   # ...e.g. an interactive BusyBox shell
//!   retroos-host                           # arch-boundary demo
//! (build: bazelisk build //kernel:retroos-host --platforms=@platforms//host)

use retroos_arch_interp as arch;
use std::io::Read;

/// Optional log file for the kernel debug sink (`--console` mode routes logs
/// here to keep them off the terminal showing the live VGA render). When unset,
/// logs go to stderr.
static LOG_FILE: std::sync::Mutex<Option<std::fs::File>> = std::sync::Mutex::new(None);

/// The kernel's installed debug-log sink: one byte to `LOG_FILE` if set, else to
/// stderr. Logging is a host concern here — straight to a stream, never through
/// the interpreter's port/device machinery.
fn host_log_byte(b: u8) {
    use std::io::Write;
    if let Ok(mut g) = LOG_FILE.lock()
        && let Some(f) = g.as_mut() {
            let _ = f.write_all(&[b]);
            return;
        }
    let _ = std::io::stderr().write_all(&[b]);
}

/// Linux stdout on a headless host is terminal output, not a kernel log.
fn host_console_byte(b: u8) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(&[b]);
    let _ = out.flush();
}

fn main() {

    let mut host_dir: Option<String> = None;
    let mut boot_disk: Option<String> = None;
    let mut cmd: Option<String> = None;
    let mut cwd: Option<String> = None;
    let mut c_root: Option<String> = None;
    let mut shot: Option<String> = None;
    let mut wav: Option<String> = None;
    let mut live_console = false;
    // Positional args: [0] = program/disk, [1..] = the program's own argv tail.
    let mut positional: Vec<String> = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--boot-disk" => boot_disk = args.next(),
            "--host" | "-h" => host_dir = args.next(),
            // Live-render the guest's VGA text screen to this terminal (for
            // driving a full-screen DOS TUI like DN). 0xE9 debug → retroos.log.
            "--console" => live_console = true,
            // Headless single-program launch via fw_cfg `opt/cmdline` — the same
            // mechanism QEMU's `-fw_cfg name=opt/cmdline,string=...` drives on
            // metal. `startup()` runs the program(s), then shuts down (no DN loop).
            "--cmd" | "-c" => cmd = args.next(),
            "--cwd" => cwd = args.next(),
            "--c-root" => c_root = args.next(),
            // Periodically snapshot the guest's VGA text screen (0xB8000) to a
            // file — lets a headless run of an interactive TUI (DN) be inspected.
            "--screenshot" => shot = args.next(),
            // Back the canonical audio device with a WAV file: the kernel's
            // emulated Sound Blaster streams PCM here so it can be verified
            // offline (no real card on the host). Without this flag the audio
            // ports are unpopulated and the kernel sound path is inert.
            "--wav" => wav = args.next(),
            // The live window moved to its own binary: retroos-play.
            "--window" => {
                eprintln!("retroos-host is headless; use `./run.sh hosted` (retroos-play) for the window");
                std::process::exit(2);
            }
            // First positional ends flag parsing; the rest are the program's argv.
            _ => {
                positional.push(a);
                positional.extend(args.by_ref());
            }
        }
    }
    let input = positional.first().cloned();

    let raw_console = !live_console && shot.is_none();
    // Arm VGA-screen snapshotting: a watcher thread flips the request flag every
    // second; the CPU thread renders at its next slice boundary.
    let shot_armed = shot.is_some();
    if let Some(path) = shot {
        arch::set_dump_path(&path);
        let ppm_path = format!("{path}.ppm");
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(1000));
            arch::request_vga_dump();
            if let Some((w, h, px)) = arch::take_frame() {
                let mut out = format!("P6\n{w} {h}\n255\n").into_bytes();
                for p in &px {
                    out.extend_from_slice(&[(p >> 16) as u8, (p >> 8) as u8, *p as u8]);
                }
                let _ = std::fs::write(&ppm_path, out);
                arch::recycle_frame(px);
            }
        });
    }

    // Install the kernel debug-log sink (a host stream, not the arch port bus):
    // stderr normally; a log file under --console so logs stay off the terminal
    // that's showing the live VGA render.
    if live_console {
        if let Ok(f) = std::fs::File::create("retroos.log") {
            *LOG_FILE.lock().unwrap() = Some(f);
        }
        arch::enable_live_console(); // paint guest 0xB8000 to this terminal
    }
    kernel::kernel::klog::init();
    lib::log::set_debug_sink(host_log_byte);
    if raw_console {
        lib::term::set_console_sink(host_console_byte);
    }
    // Inject the backend into the (backend-agnostic) kernel: its port I/O for
    // the deep driver call sites (portio), and the host environment facts the
    // platform probe reads (HostStdout debug, no fbcon, not metal).
    install_hosted_backend();
    install_socket_backend_hosted();
    kernel::host_console_init();
    // Display: the kernel emulates the VGA (single-VGA design) and renders
    // frames through its present sink; we just park them in the backend's
    // frame mailbox for the screenshot path. Only armed when a consumer
    // exists, so headless --cmd runs skip the render work entirely.
    if shot_armed {
        kernel::kernel::display::set_host_present_sink(arch::publish_frame);
    }
    // Sniff the ELF magic from the header alone — a disk image is attached by
    // path and streamed (`attach_disk`), so slurping it whole here just to read
    // four bytes put its entire size in RAM (a 200 GiB test disk OOM'd).
    let mut magic = [0u8; 4];
    if let Some(path) = &input {
        std::fs::File::open(path)
            .map(|mut f| {
                let _ = f.read(&mut magic); // short file → stays zeroed, not ELF
            })
            .unwrap_or_else(|e| {
                eprintln!("retroos-host: cannot read {path}: {e}");
                std::process::exit(1);
            });
    }
    // A bare executable is not a second way to boot: serve its directory over
    // the native host-fs punch-through and let the ordinary path name it, so
    // the kernel is entered once, through `startup()`, with the machine
    // probed. argv = the positional tail (so `… boot-bundle/bin/busybox sh` runs
    // BusyBox's `sh` applet).
    let elf = magic == *b"\x7fELF";
    if elf {
        let path = std::path::Path::new(input.as_deref().unwrap());
        let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
        let name = path.file_name().expect("ELF path names a file");
        if host_dir.is_none() {
            host_dir = Some(dir.unwrap_or(std::path::Path::new(".")).to_string_lossy().into_owned());
        }
        let mut line = name.to_string_lossy().into_owned();
        for arg in positional.iter().skip(1) {
            line.push(' ');
            line.push_str(arg);
        }
        cmd = Some(line);
    }

    if let Some(dir) = &host_dir {
        // Native host-fs backend (the hosted "punch-through"): /host (or the
        // root, per Media) is served by direct std::fs calls, not byte-serial
        // COM1. Same injection shape as install_hosted_backend above.
        arch::install_native_hostfs(dir);
        kernel::install_host_backend(kernel::HostBackendHooks {
            open: arch::host_open,
            read: arch::host_read,
            readdir: arch::host_readdir,
            dir_exists: arch::host_dir_exists,
            create: arch::host_create,
            write: arch::host_write,
            resize: arch::host_resize,
            clunk: arch::host_clunk,
            remove: arch::host_remove,
            mkdir: arch::host_mkdir,
            rmdir: arch::host_rmdir,
            rename: arch::host_rename,
        });
    }
    if let Some(path) = wav {
        arch::attach_audio(&path); // canonical audio device → WAV file
    }

    // Otherwise boot the same kernel::startup() the metal crt0 calls — with
    // the image's ATA disk attached when one was given, diskless otherwise
    // (the platform Media probe roots on hostfs or the embedded bootfs).
    arch::init_guest_ram(0);
    if let Some(path) = &input
        && !elf
    {
        arch::attach_disk(path).unwrap_or_else(|e| {
            eprintln!("retroos-host: cannot attach disk {path}: {e}");
            std::process::exit(1);
        });
    }
    if let Some(path) = &boot_disk {
        arch::attach_boot_disk(path).unwrap_or_else(|e| {
            eprintln!("cannot attach boot disk {path}: {e}");
            std::process::exit(1);
        });
    }
    // Drive the booted OS (DOS shell, DN) from the terminal: raw mode + the
    // stdin→keyboard pump. Keys reach the guest via the kernel's IRQ1 path and
    // the C BIOS INT 9/16h. Harmless headless (raw mode skips a non-TTY).
    arch::enter_raw_mode();
    spawn_keyboard();

    // Build the boot config from our CLI args directly — the interpreter is
    // QEMU-like (it must fabricate 0x3DA etc.), and we already know the headless
    // cmdline/cwd, so there's no fw_cfg port round-trip.
    let mut config = kernel::BootConfig::empty();
    config.is_qemu = true;
    if host_dir.is_some() { config.set_serial_services_from_cmdline(b"hostfs=com1"); }
    if let Some(c) = &cmd { config.set_cmdline(c.as_bytes()); }
    if let Some(c) = &cwd { config.set_cwd(c.as_bytes()); }
    if let Some(c) = &c_root { config.set_c_root(c.as_bytes()); }

    let mut machine = arch::Interp;
    // Hosted has no display to arbitrate until `startup` builds a Console;
    // mirroring the metal boot_kernel — one per boot, moved into startup.
    kernel::startup(&mut machine, &config);
}

/// Inject the interp backend into the backend-agnostic kernel: its port I/O
/// (for the deep driver call sites that never see the `&mut Arch`) and the
/// host-environment facts the platform probe reads.
fn install_hosted_backend() {
    kernel::install_portio(kernel::PortIo {
        now_ns: || {
            static EPOCH: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
            EPOCH.get_or_init(std::time::Instant::now).elapsed().as_nanos() as u64
        },
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
}

/// Install the native socket backend (hosted "punch-through" → host std::net).
/// Networking is always available on hosted; metal installs nothing here (its
/// NIC + smoltcp path is a future follow-up). Must run on the CPU/kernel thread
/// (the native socket table is thread-local), before `startup`.
fn install_socket_backend_hosted() {
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
}

/// Spawn the stdin → keyboard pump: read host terminal bytes, translate each to
/// a PC scancode make/break sequence, and post it as an `Irq::Key` for the
/// kernel event loop (which translates to Unicode and feeds guest input).
/// Ctrl-] quits the host. Runs forever on its own thread.
fn spawn_keyboard() {
    use std::io::Read;
    std::thread::spawn(|| {
        let mut stdin = std::io::stdin();
        let mut byte = [0u8; 1];
        while stdin.read_exact(&mut byte).is_ok() {
            let b = byte[0];
            if b == 0x03 || b == 0x1D {
                // Ctrl-C / Ctrl-]: quit the host. Raw mode disabled ISIG, so the
                // tty no longer turns Ctrl-C into SIGINT — intercept it here so
                // the kernel is still killable. `process::exit` runs the atexit
                // hook that restores the terminal.
                std::process::exit(130);
            }
            // ESC may start a CSI/SS3 escape sequence (arrows, F-keys). The tty
            // sends the whole sequence in one burst, so reading ahead is safe.
            // Space the make and break codes apart: games that poll a
            // key-state table once per frame (menu loops) miss a press whose
            // down and up both land between two polls.
            const TAP_GAP: std::time::Duration = std::time::Duration::from_millis(30);
            if b == 0x1B
                && let Some(sc) = read_escape_seq(&mut stdin) {
                    // A 101-key keyboard brackets the cursor block and
                    // Insert/Delete with an E0 prefix, and that prefix is what
                    // the BIOS turns into the enhanced AL=0xE0 keystroke a lot
                    // of DOS software matches arrows on. A terminal escape
                    // carries no such distinction, so put it back: from a
                    // terminal these are always the gray keys, never the
                    // keypad duplicates that share their scancodes.
                    let gray = GRAY_KEYS.contains(&sc);
                    if gray { arch::post_irq(arch::Irq::Key(0xE0)); }
                    arch::post_irq(arch::Irq::Key(sc));
                    std::thread::sleep(TAP_GAP);
                    if gray { arch::post_irq(arch::Irq::Key(0xE0)); }
                    arch::post_irq(arch::Irq::Key(sc | 0x80));
                    continue;
                }
            let character = if b.is_ascii() { char::from(b) } else {
                let length = match b { 0xc2..=0xdf => 2, 0xe0..=0xef => 3, 0xf0..=0xf4 => 4, _ => continue };
                let mut bytes = [0;4]; bytes[0] = b;
                if stdin.read_exact(&mut bytes[1..length]).is_err() { break; }
                let Ok(text) = std::str::from_utf8(&bytes[..length]) else { continue; };
                text.chars().next().unwrap()
            };
            for sc in character_to_scancodes(character) {
                arch::post_irq(arch::Irq::Key(sc));
                std::thread::sleep(TAP_GAP);
            }
        }
    });
}

/// The scancodes a 101-key keyboard sends with an E0 prefix: the dedicated
/// cursor block plus Insert/Delete. (F11/F12 are enhanced keys too, but they
/// are new scancodes, not E0-prefixed duplicates of keypad ones.)
const GRAY_KEYS: [u8; 10] = [0x47, 0x48, 0x49, 0x4B, 0x4D, 0x4F, 0x50, 0x51, 0x52, 0x53];

/// After an ESC, read a CSI (`[ … final`) or SS3 (`O P/Q/R/S`) sequence and
/// return the single PC scancode it maps to (arrows, Home/End/PgUp/Del, F1-F12),
/// or None for a bare ESC / unrecognized sequence. The tty delivers a sequence
/// atomically, so the blocking reads here complete immediately.
fn read_escape_seq(stdin: &mut std::io::Stdin) -> Option<u8> {
    use std::io::Read;
    let mut b = [0u8; 1];
    if stdin.read_exact(&mut b).is_err() {
        return None;
    }
    match b[0] {
        b'O' => {
            // SS3: F1-F4.
            if stdin.read_exact(&mut b).is_err() { return None; }
            match b[0] {
                b'P' => Some(0x3B), b'Q' => Some(0x3C), b'R' => Some(0x3D), b'S' => Some(0x3E),
                _ => None,
            }
        }
        b'[' => {
            // CSI: read digits/`;` then the final byte.
            let mut num = 0u32;
            let mut have_num = false;
            loop {
                if stdin.read_exact(&mut b).is_err() { return None; }
                let c = b[0];
                if c.is_ascii_digit() {
                    num = num * 10 + (c - b'0') as u32;
                    have_num = true;
                    continue;
                }
                return match c {
                    b'A' => Some(0x48), // Up
                    b'B' => Some(0x50), // Down
                    b'C' => Some(0x4D), // Right
                    b'D' => Some(0x4B), // Left
                    b'H' => Some(0x47), // Home
                    b'F' => Some(0x4F), // End
                    b'~' if have_num => match num {
                        1 | 7 => Some(0x47), // Home
                        2 => Some(0x52),     // Insert
                        3 => Some(0x53),     // Delete
                        4 | 8 => Some(0x4F), // End
                        5 => Some(0x49),     // PgUp
                        6 => Some(0x51),     // PgDn
                        11 => Some(0x3B), 12 => Some(0x3C), 13 => Some(0x3D), 14 => Some(0x3E), // F1-F4
                        15 => Some(0x3F), 17 => Some(0x40), 18 => Some(0x41), 19 => Some(0x42), // F5-F8
                        20 => Some(0x43), 21 => Some(0x44),                                     // F9-F10
                        23 => Some(0x57), 24 => Some(0x58),                                     // F11-F12
                        _ => None,
                    },
                    _ => None,
                };
            }
        }
        _ => None,
    }
}

/// Host text injection uses the same selected layout as the guest.
fn character_to_scancodes(character: char) -> Vec<u8> {
    let (sequence,length) = lib::keyboard::sequence(lib::keyboard::current(),character);
    sequence[..length].to_vec()
}
