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
//!   retroos-host apps/busybox/busybox sh   # ...e.g. an interactive BusyBox shell
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
    kernel::kernel::klog::push_byte(b);
    if let Ok(mut g) = LOG_FILE.lock()
        && let Some(f) = g.as_mut() {
            let _ = f.write_all(&[b]);
            return;
        }
    let _ = std::io::stderr().write_all(&[b]);
}

fn main() {

    let mut host_dir: Option<String> = None;
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
    kernel::vga::set_debug_sink(host_log_byte);
    // Inject the backend into the (backend-agnostic) kernel: its port I/O for
    // the deep driver call sites (portio), and the host environment facts the
    // platform probe reads (HostStdout debug, no fbcon, not metal).
    install_hosted_backend();
    install_socket_backend_hosted();
    // Prototype: VIF_DELTA=1 routes virtual-IF through the delta (tag-TF) path.
    if std::env::var("VIF_DELTA").as_deref() == Ok("1") {
        kernel::set_vif_delta(true);
    }
    kernel::host_console_init();
    // Display: the kernel emulates the VGA (single-VGA design) and renders
    // frames through its present sink; we just park them in the backend's
    // frame mailbox for the screenshot path. Only armed when a consumer
    // exists, so headless --cmd runs skip the render work entirely.
    if shot_armed {
        lib::vga_render::set_present_sink(arch::publish_frame);
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
            clunk: arch::host_clunk,
            remove: arch::host_remove,
        });
    }
    if let Some(path) = wav {
        arch::attach_audio(&path); // canonical audio device → WAV file
    }

    let mut data = Vec::new();
    if let Some(path) = &input {
        std::fs::File::open(path)
            .and_then(|mut f| f.read_to_end(&mut data))
            .unwrap_or_else(|e| {
                eprintln!("retroos-host: cannot read {path}: {e}");
                std::process::exit(1);
            });
    }

    if data.starts_with(b"\x7fELF") {
        let path = input.as_deref().unwrap();
        // A bare executable: run it directly (no disk). argv = the positional
        // tail (so `… apps/busybox/busybox sh` runs BusyBox's `sh` applet).
        let argv: Vec<Vec<u8>> = positional.iter().map(|s| s.clone().into_bytes()).collect();
        // Wire the interactive console: put the host terminal in raw mode and
        // spawn the stdin→keyboard pump, so the guest (a Linux shell) is
        // drivable. Output already flows to stdout via the kernel's 0xE9 mirror.
        arch::enter_raw_mode();
        spawn_keyboard();
        // Initialize guest RAM + the active address space before loading the
        // ELF into it — the disk-boot path below does this via `init_guest_ram`
        // too, but this branch diverges before reaching it. Without it the ELF
        // loader's first `copy_to` resolves against no active space and panics
        // ("active space missing").
        arch::init_guest_ram(0);
        let mut machine = arch::Interp;
        kernel::host_run_elf(&mut machine, path.as_bytes(), data, argv);
    }

    // Otherwise boot the same kernel::startup() the metal crt0 calls — with
    // the image's ATA disk attached when one was given, diskless otherwise
    // (the platform Media probe roots on hostfs or the embedded bootfs).
    arch::init_guest_ram(0);
    if let Some(path) = &input {
        arch::attach_disk(path).unwrap_or_else(|e| {
            eprintln!("retroos-host: cannot attach disk {path}: {e}");
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
    if let Some(c) = &cmd { config.set_cmdline(c.as_bytes()); }
    if let Some(c) = &cwd { config.set_cwd(c.as_bytes()); }
    if let Some(c) = &c_root { config.set_c_root(c.as_bytes()); }

    let mut machine = arch::Interp;
    // The screen license (see lib::vga::Screen): hosted constructs it here,
    // mirroring the metal boot_kernel — one per boot, moved into startup.
    kernel::startup(&mut machine, &config, kernel::vga::Screen::new());
}

/// Inject the interp backend into the backend-agnostic kernel: its port I/O
/// (for the deep driver call sites that never see the `&mut Arch`) and the
/// host-environment facts the platform probe reads.
fn install_hosted_backend() {
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
/// kernel event loop (which does scancode→ASCII and feeds the guest's stdin).
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
                    arch::post_irq(arch::Irq::Key(sc));
                    std::thread::sleep(TAP_GAP);
                    arch::post_irq(arch::Irq::Key(sc | 0x80));
                    continue;
                }
            for sc in byte_to_scancodes(b) {
                arch::post_irq(arch::Irq::Key(sc));
                std::thread::sleep(TAP_GAP);
            }
        }
    });
}

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

/// US-layout key table: (scancode, unshifted ASCII, shifted ASCII). Mirrors the
/// kernel's KBD_US/KBD_US_SHIFT tables (kept arch-side per the layer-isolation
/// rule — small duplicated primitive, not a cross-layer call).
#[rustfmt::skip]
const KEYS: &[(u8, u8, u8)] = &[
    (0x02,b'1',b'!'),(0x03,b'2',b'@'),(0x04,b'3',b'#'),(0x05,b'4',b'$'),(0x06,b'5',b'%'),
    (0x07,b'6',b'^'),(0x08,b'7',b'&'),(0x09,b'8',b'*'),(0x0A,b'9',b'('),(0x0B,b'0',b')'),
    (0x0C,b'-',b'_'),(0x0D,b'=',b'+'),
    (0x10,b'q',b'Q'),(0x11,b'w',b'W'),(0x12,b'e',b'E'),(0x13,b'r',b'R'),(0x14,b't',b'T'),
    (0x15,b'y',b'Y'),(0x16,b'u',b'U'),(0x17,b'i',b'I'),(0x18,b'o',b'O'),(0x19,b'p',b'P'),
    (0x1A,b'[',b'{'),(0x1B,b']',b'}'),
    (0x1E,b'a',b'A'),(0x1F,b's',b'S'),(0x20,b'd',b'D'),(0x21,b'f',b'F'),(0x22,b'g',b'G'),
    (0x23,b'h',b'H'),(0x24,b'j',b'J'),(0x25,b'k',b'K'),(0x26,b'l',b'L'),(0x27,b';',b':'),
    (0x28,b'\'',b'"'),(0x29,b'`',b'~'),(0x2B,b'\\',b'|'),
    (0x2C,b'z',b'Z'),(0x2D,b'x',b'X'),(0x2E,b'c',b'C'),(0x2F,b'v',b'V'),(0x30,b'b',b'B'),
    (0x31,b'n',b'N'),(0x32,b'm',b'M'),(0x33,b',',b'<'),(0x34,b'.',b'>'),(0x35,b'/',b'?'),
];

const LSHIFT: u8 = 0x2A;
const LCTRL: u8 = 0x1D;

fn lookup(c: u8) -> Option<(u8, bool)> {
    for &(sc, un, sh) in KEYS {
        if c == un { return Some((sc, false)); }
        if c == sh { return Some((sc, true)); }
    }
    None
}

/// One terminal byte → the scancode make/break sequence the kernel keyboard
/// path expects. Modifier-wrapped: shift for shifted glyphs, ctrl for C0 control
/// bytes (so the kernel's `scancode_to_ascii` recovers the same char).
fn byte_to_scancodes(b: u8) -> Vec<u8> {
    let tap = |sc: u8| vec![sc, sc | 0x80];
    match b {
        b'\r' | b'\n' => return tap(0x1C), // Enter
        0x08 | 0x7F => return tap(0x0E),    // Backspace
        b'\t' => return tap(0x0F),          // Tab
        0x1B => return tap(0x01),           // Esc
        b' ' => return tap(0x39),           // Space
        _ => {}
    }
    // C0 control bytes (Ctrl-A..Z, excluding the specials matched above).
    if (0x01..=0x1A).contains(&b)
        && let Some((sc, _)) = lookup(b + 0x60) {
            return vec![LCTRL, sc, sc | 0x80, LCTRL | 0x80];
        }
    if let Some((sc, shift)) = lookup(b) {
        return if shift {
            vec![LSHIFT, sc, sc | 0x80, LSHIFT | 0x80]
        } else {
            tap(sc)
        };
    }
    Vec::new()
}
