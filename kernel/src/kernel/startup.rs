//! Kernel startup - filesystem mount and DN.COM loader

extern crate alloc;

use crate::Regs;
use crate::kernel::{vfs, fs::tarfs::TarFs, fs::lwext4::{Lwext4Fs, MountMode}};
use crate::kernel::thread;

/// Startup: the kernel's ordered init spine — probe, then derive, then run.
/// Each phase is a named function below; this stays short enough to read as
/// the boot story. Called from enter_ring1 — we are already at ring 1.
pub fn startup<A: crate::Arch>(machine: &mut A, boot: &crate::BootConfig, mut screen: crate::vga::Screen) -> ! {
    // The global allocator is installed by the binary glue before startup runs
    // (metal: `arch/boot.rs`; hosted: std), so heap-using code is safe here on.

    // Allocate the in-memory kernel log now the heap is up; the debug sink tees
    // into it so `LOG` (COMMAND.COM, INT 31h AH=07h) can surface kernel output
    // on machines with no serial/debug port (real metal — 0xE9 goes nowhere).
    crate::kernel::klog::init();

    // Discover every disk. The block layer reports what exists; nothing below
    // this line picks a boot disk or decides where anything mounts.
    let disks = crate::kernel::block::probe(machine);
    for d in &disks {
        crate::println!("Storage: {} ({} MB)", d.name(), d.sectors() / 2048);
    }
    if disks.is_empty() {
        crate::println!("Storage: none detected");
    }
    crate::screenln!(screen, "Block devices initialized");

    // Probe the machine ONCE and freeze the result; all hardware policy
    // (VGA passthrough, BIOS choice, audio, console, IOPB) derives from this.
    // It no longer touches storage — the mount decision is made below, from
    // the partition tables, by the layer that owns it.
    let platform = crate::kernel::platform::probe(machine, boot);

    // Disk-write policy, applied by COMPOSITION: on real hardware the disk is
    // someone's actual home partition, so each one is wrapped in a volatile RAM
    // overlay and the wrapped disk becomes the only reference that exists from
    // here on — nothing downstream can reach the platter, and no write path has
    // to remember to check a flag. QEMU/hosted runs write through to their
    // disposable image file. Done before the partition scan, so every Volume
    // built below already carries the policy.
    let disks = if platform.host == crate::kernel::platform::Host::Metal {
        crate::screenln!(screen, "Disk writes: volatile RAM overlay (real hardware) — changes will NOT persist");
        disks
            .into_iter()
            .map(|d| -> &'static dyn crate::kernel::block::Disk {
                alloc::boxed::Box::leak(alloc::boxed::Box::new(
                    crate::kernel::block::overlay::RamOverlay::wrap(d)))
            })
            .collect()
    } else {
        disks
    };

    // The thread table is a plain owned Vec now (fixed MAX_THREADS slots,
    // reused) — startup owns it and threads `&mut threads` down through run →
    // run_program → event_loop. No global; no `&'static mut`.
    let mut threads = crate::kernel::thread::init_threading();
    crate::screenln!(screen, "Threading initialized");

    // FS-layout policy (DOS C: → VFS subtree) before any mount/resolve.
    crate::kernel::dos::set_c_root(boot.c_root());

    // Read every disk's partition table, then decide the mount tree from what
    // they declare. `plan_mounts` is a pure function of those facts.
    let parts: alloc::vec::Vec<_> = disks
        .iter()
        .flat_map(|&d| crate::kernel::block::partition::scan(crate::kernel::block::Volume::whole(d)))
        .collect();
    let plan = plan_mounts(&parts, platform.hostfs);
    mount_filesystems(&plan, &mut screen);
    init_device_policy(machine, platform);
    let master_env = load_master_env();
    init_console_pipe();

    run(machine, boot, &master_env, &mut threads, screen)
}

/// The host filesystem (COM1 transport). Mounted at /host beside a disk
/// root, or AS the root under `Media::HostRoot`.
static HOSTFS: crate::kernel::fs::hostfs::HostFs = crate::kernel::fs::hostfs::HostFs::new();

/// The host fs to mount: the injected native `std::fs` backend when the entry
/// installed one (hosted "punch-through" — direct calls, no COM1), else the
/// COM1 `HOSTFS` client (metal / the Python bridge).
fn host_fs() -> &'static dyn vfs::Filesystem {
    if crate::kernel::fs::hostfs::host_backend_installed() {
        &crate::kernel::fs::hostfs::INJECTED_HOSTFS
    } else {
        &HOSTFS
    }
}

/// Where the VFS root comes from. A closed set RetroOS defines, so an enum —
/// adding a root kind breaks every site that has to handle one.
enum RootSource {
    /// An ext filesystem on a disk — the natural root for metal, and for
    /// hosted runs with an image attached.
    Disk(crate::kernel::block::Volume),
    /// The host filesystem IS the root (DOSBox-style: a host directory is the
    /// drive, no image build). Linux binaries see /usr, /lib, /etc natively.
    Host,
    /// Neither: the embedded bootfs at /boot is the whole world (a bare
    /// kernel.elf booted from someone's GRUB).
    None,
}

/// The mount tree to build. Derived from facts, then executed — deciding and
/// doing are separate so the decision is inspectable and testable on its own.
struct MountPlan {
    root: RootSource,
    /// Additional ext filesystems: (mount prefix, volume). A dual-boot laptop
    /// has several; they are Linux-visible only, not under C:.
    extra: alloc::vec::Vec<(&'static [u8], crate::kernel::block::Volume)>,
    /// Also mount the host fs at /host, beside a disk root.
    host_alias: bool,
}

/// lwext4's device and mount-point registries are fixed-size arrays in the C
/// library, sized by CONFIG_EXT4_{BLOCKDEVS,MOUNTPOINTS}_COUNT — we build it
/// with 8 (upstream defaults to 2, which would cap us at a root plus one).
/// Keep this in step with //third_party/lwext4 and MODULE.bazel.
const MAX_EXT_MOUNTS: usize = 8;

/// Decide the mount tree from the partition tables and whether a host
/// transport answered. Pure: no I/O beyond the ext-root sniff, no globals, and
/// no mounting — see `mount_filesystems` for the doing.
fn plan_mounts(
    parts: &[crate::kernel::block::partition::Partition],
    hostfs: bool,
) -> MountPlan {
    use crate::kernel::block::partition::PartKind;

    let ext: alloc::vec::Vec<_> = parts
        .iter()
        .filter(|p| p.kind == PartKind::Ext)
        .map(|p| p.volume)
        .collect();

    if ext.is_empty() {
        // No ext filesystem anywhere: the host fs is the root if we have one.
        return MountPlan {
            root: if hostfs { RootSource::Host } else { RootSource::None },
            extra: alloc::vec::Vec::new(),
            host_alias: false,
        };
    }

    // Several ext partitions (a data partition AND the real Linux root) give no
    // order guarantee, so sniff for /etc + /usr to find the real root. Only
    // when ambiguous: a single ext partition IS the root, and probing it would
    // mean a needless lwext4 mount/unmount.
    let mut root_idx = 0;
    if ext.len() > 1 {
        for (i, vol) in ext.iter().enumerate() {
            if crate::kernel::fs::lwext4::is_linux_root(vol) {
                root_idx = i;
                break;
            }
        }
    }
    let mut extra = alloc::vec::Vec::new();
    for (i, &vol) in ext.iter().enumerate() {
        if i == root_idx {
            continue;
        }
        if extra.len() + 1 >= MAX_EXT_MOUNTS {
            // Never drop a filesystem silently — say which and why.
            crate::println!(
                "ext4: {} further partition(s) not mounted (lwext4 allows {} mounts)",
                ext.len() - extra.len() - 1, MAX_EXT_MOUNTS);
            break;
        }
        let n = extra.len() + 1;
        let mut name = alloc::vec::Vec::new();
        name.extend_from_slice(b"disk");
        name.push(b'0' + n as u8);
        name.push(b'/');
        extra.push((&*alloc::boxed::Box::leak(name.into_boxed_slice()), vol));
    }

    MountPlan { root: RootSource::Disk(ext[root_idx]), extra, host_alias: hostfs }
}

/// Execute the plan, then the invariant mounts.
/// /boot is an INVARIANT: the embedded bootfs (DN + COMMAND.COM), mounted on
/// top of whatever the root is — the disk's 0xDA boot-bundle partition is
/// bootloader-only and never mounted.
fn mount_filesystems(plan: &MountPlan, screen: &mut crate::vga::Screen) {
    match plan.root {
        RootSource::Disk(vol) => {
            crate::screenln!(screen, "ext4 root ({} MB)", vol.sectors / 2048);
            // The root is the only writable mount; the group+write-bit policy
            // inside lwext4 narrows it further.
            match Lwext4Fs::new(vol, 0, MountMode::ReadWrite) {
                Ok(fs) => vfs::mount(b"", alloc::boxed::Box::leak(alloc::boxed::Box::new(fs))),
                Err(e) => panic!("ext4 mount failed: {}", e),
            }
        }
        RootSource::Host => {
            vfs::mount(b"", host_fs());
            crate::screenln!(screen, "hostfs mounted as root");
        }
        RootSource::None => {}
    }

    // Extra ext filesystems mount at /disk1, /disk2, … An unreadable one is
    // logged and skipped, never fatal — the root is already mounted.
    for (i, (prefix, vol)) in plan.extra.iter().enumerate() {
        // Extra partitions (a laptop's data / another distro) are never
        // written: read-only at the lwext4 level and with no grant gid.
        match Lwext4Fs::new(*vol, i + 1, MountMode::ReadOnly) {
            Ok(fs) => {
                vfs::mount(prefix, alloc::boxed::Box::leak(alloc::boxed::Box::new(fs)));
                crate::screenln!(screen, "ext4 partition ({} MB) → /{}",
                    vol.sectors / 2048,
                    core::str::from_utf8(&prefix[..prefix.len() - 1]).unwrap_or("?"));
            }
            Err(e) => crate::screenln!(screen, "ext4 partition skipped: {}", e),
        }
    }

    if plan.host_alias && !matches!(plan.root, RootSource::Host) {
        vfs::mount(b"host/", host_fs());
        crate::screenln!(screen, "hostfs mounted at /host");
    }

    // The embedded DOS system mounts under C:\BOOT (= c_root + "boot/"). C:
    // itself is the disk/host fs; C:\BOOT is this overlay. Both the prefix and
    // the filesystem are leaked (one-time, boot-lifetime) to satisfy
    // vfs::mount's &'static requirement — the same shape as the ext4 and host
    // mounts above, so no `static mut` is involved.
    let mut root_tarfs = TarFs::new_ram(crate::bootfs().unwrap_or(&[]));
    if crate::bootfs().is_some() {
        root_tarfs.build_index();
    }
    let bootfs_prefix: &'static [u8] = alloc::boxed::Box::leak(
        [crate::kernel::dos::c_root(), b"boot/"].concat().into_boxed_slice());
    vfs::mount(bootfs_prefix, alloc::boxed::Box::leak(alloc::boxed::Box::new(root_tarfs)));

    mount_kernel_log_fs();

    crate::kernel::stacktrace::init_from_tar();
}

fn mount_kernel_log_fs() {
    vfs::mount_union(b"proc/", &crate::kernel::klog::KLOG_FS);

    let c_root = crate::kernel::dos::c_root();
    if !c_root.is_empty() {
        let dos_proc_prefix: &'static [u8] =
            alloc::boxed::Box::leak([c_root, b"proc/"].concat().into_boxed_slice());
        vfs::mount_union(dos_proc_prefix, &crate::kernel::klog::KLOG_FS);
    }
}

/// Device policy, derived from the platform probe — not re-probed here.
/// Port permissions are NOT set here: `io_policy::apply` rebuilds the I/O
/// bitmap per thread on every swap-in (the VGA window follows console
/// focus; Linux threads get nothing).
fn init_device_policy<A: crate::Arch>(
    machine: &mut A,
    _platform: &'static crate::kernel::platform::Platform,
) {
    // Probe for an AC'97 codec (metal). If present it becomes the kernel audio
    // output for the emulated Sound Blaster; absent (no PCI, e.g. the
    // interpreter) leaves the sound path on its port-window fallback.
    crate::kernel::drivers::ac97::init(machine);
    crate::kernel::drivers::hda::init(machine);
}

/// /CONFIG.SYS provides the master env handed to DN and any user-driven
/// launches. KEY=VALUE lines, `#` comments. No root CONFIG.SYS (diskless
/// boot) falls back to the embedded bootfs copy, whose PATH points into
/// C:\BOOT; with neither, the env is empty.
fn load_master_env() -> alloc::vec::Vec<u8> {
    // C:\CONFIG.SYS (user override) wins; else the embedded C:\BOOT\CONFIG.SYS.
    let cr = crate::kernel::dos::c_root();
    let user_cfg = [cr, b"CONFIG.SYS"].concat();
    let boot_cfg = [cr, b"boot/CONFIG.SYS"].concat();
    let config = crate::kernel::exec::load_file_resolved(&user_cfg)
        .or_else(|_| crate::kernel::exec::load_file_resolved(&boot_cfg))
        .unwrap_or_default();
    crate::kernel::dos::parse_config_env(&config)
}

/// Allocate the console stdin pipe (keyboard → Linux stdin). The kernel
/// itself is the writer (via process_key during the event loop drain), so
/// register a phantom writer permanently — without it, has_writers returns
/// false and the first read on fd 0 reports EOF immediately, which makes
/// busybox/sh bail out at startup.
fn init_console_pipe() {
    let console_pipe = crate::kernel::kpipe::alloc().expect("Failed to allocate console pipe");
    crate::kernel::kpipe::add_writer(console_pipe);
    crate::kernel::thread::set_console_pipe(console_pipe);
}

/// Run what the boot asked for: the headless `-fw_cfg opt/cmdline` program
/// sequence (shut down after), or the interactive DN loop.
fn run<A: crate::Arch>(machine: &mut A, boot: &crate::BootConfig, master_env: &[u8], threads: &mut [thread::Thread<A>], mut screen: crate::vga::Screen) -> ! {
    if let Some(raw) = boot.cmdline() {
        // CWD: explicit `opt/cwd` key wins; else fall back to each program's
        // own directory.
        let explicit_cwd = boot.cwd().map(trim_ascii);

        for one in raw.split(|&b| b == b';') {
            let cmdline = trim_ascii(one);
            if cmdline.is_empty() { continue; }
            // First token = program path, rest = cmdline tail (PSP:0080h).
            let split = cmdline.iter().position(|&b| b == b' ').unwrap_or(cmdline.len());
            let prog = &cmdline[..split];
            let tail_raw = if split < cmdline.len() { &cmdline[split + 1..] } else { &[][..] };
            let tail = trim_ascii(tail_raw);

            let path = prog;

            let cwd: &[u8] = match explicit_cwd {
                Some(c) => c,
                None => {
                    let cwd_end = path.iter().rposition(|&b| b == b'/').map_or(0, |i| i + 1);
                    &path[..cwd_end]
                }
            };
            crate::screenln!(screen, "Starting {} {} (cwd={})...",
                core::str::from_utf8(path).unwrap_or("?"),
                core::str::from_utf8(tail).unwrap_or(""),
                core::str::from_utf8(cwd).unwrap_or("?"));
            run_program(machine, threads, path, tail, cwd, master_env, boot.debug_watch);
        }
        crate::screenln!(screen, "All commands done — shutting down.");
        crate::kernel::drivers::hda::emergency_quiesce(); // codec must not ride into poweroff unparked
        machine.shutdown();
    }

    // COMMAND.COM is prebuilt (in-OS TCC at image-build time —
    // //apps-boot/command:command_com) and ships at C:\COMMAND.COM plus inside
    // the embedded bootfs at C:\BOOT\COMMAND.COM. The per-boot self-build from
    // BOOT\SRC\COMMAND.C is gone with it; the BCC EXEC-path exercise it
    // doubled as lives on in test/dpmi_smoke.sh.

    crate::screenln!(screen, "Welcome to RetroOS! Use F11 to switch tasks, F12 to dump the currently running thread's state, and type `help` for DOS commands.");

    crate::screenln!(screen, "Starting DN...");
    let dn_path = [crate::kernel::dos::c_root(), b"boot/DN/DN.COM"].concat();
    loop {
        run_program(machine, threads, &dn_path, b"", b"", master_env, boot.debug_watch);
        crate::screenln!(screen, "DN exited, restarting...");
    }
}

/// Load and run a single cmdline program until it exits. ELF binaries run
/// through the Linux loader (a fresh process thread); `.COM` / MZ `.EXE`
/// through the DOS VM86 loader. `cmdline_tail`/`env` apply only to the DOS
/// path (PSP:0080h cmdline + environment).
fn run_program<A: crate::Arch>(machine: &mut A, threads: &mut [thread::Thread<A>], path: &[u8], cmdline_tail: &[u8], cwd: &[u8], env: &[u8], debug_watch: Option<(u32, u32)>) {
    use crate::kernel::{dos, exec};

    // A cmdline path is user-facing: accept both a full VFS path and a DOS
    // C:-relative one (the common `--cmd GAMES/...` form — C: = c_root, same
    // resolution the DOS personality applies to the program's own file I/O).
    let buf = exec::load_file_resolved(path)
        .or_else(|_| exec::load_file_resolved(&[crate::kernel::dos::c_root(), path].concat()))
        .unwrap_or_else(|_| panic!("{} not found", core::str::from_utf8(path).unwrap_or("?")));
    // argv = path + the cmdline tail split into words. The ELF/Linux path
    // consumes the full argv (`--cmd "/usr/bin/dash -c 'echo hi'"` must reach
    // dash as ["-c", "echo hi"]); DOS ignores the extra entries and gets the
    // raw tail as PSP:0080h instead. Quotes group words, nothing more — the
    // launcher is not a shell.
    let mut args = alloc::vec![path.to_vec()];
    {
        let mut word: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        let mut quote: u8 = 0;
        for &b in cmdline_tail {
            match b {
                b'\'' | b'"' if quote == 0 => quote = b,
                b if quote != 0 && b == quote => quote = 0,
                b' ' if quote == 0 => {
                    if !word.is_empty() {
                        args.push(core::mem::take(&mut word));
                    }
                }
                b => word.push(b),
            }
        }
        if !word.is_empty() {
            args.push(word);
        }
    }
    let cmdline_tail = cmdline_tail.to_vec();
    let cwd = cwd.to_vec();
    let env = env.to_vec();

    // No screen handoff bookkeeping: on-screen kernel text requires the
    // `Screen` value, which our caller holds and does not touch until this
    // program's world ends — so kernel logs cannot trample user-space pixel
    // data when the program is in graphics mode (CGA modes use B8000 as a
    // pixel framebuffer, identical address to text-mode char+attr storage).
    // dos_putchar's direct VGA writes are the program's own output, not
    // kernel text, and keep working for text-mode programs.

    machine.set_debug_watch(None);

    // Format-detect: an ELF is a Linux process; everything else is DOS. (The
    // cmdline launcher used to force every program through the DOS loader,
    // which silently load_com'd an ELF and ran its header as VM86 garbage.)
    let tid = match exec::detect_format(&buf, path) {
        exec::BinaryFormat::Elf => launch_elf(machine, threads, buf, path, args),
        _ => dos::run_init_program(machine, threads, buf, args, cmdline_tail, cwd, env),
    };

    // The initial program owns the console outright (nothing to repaint) and
    // gets its port permissions from policy, not from boot-time leftovers.
    crate::kernel::focus::adopt(tid);
    {
        let t = thread::get_thread(threads, tid).expect("init program thread");
        crate::kernel::io_policy::apply(machine, &t.personality, true);
    }

    if let Some((addr0, addr1)) = debug_watch {
        machine.set_debug_watch(Some((addr0, addr1)));
        if addr1 != 0 {
            crate::dbg_println!("[WATCH] armed write watchpoints at {:08X} and {:08X}", addr0, addr1);
        } else {
            crate::dbg_println!("[WATCH] armed write watchpoint at {:08X}", addr0);
        }
    }
    event_loop(machine, threads, tid);
}

/// Launch an ELF as a fresh Linux process thread and return its tid: stdin is
/// the shared console pipe, stdout/stderr go to the console — mirroring the
/// hosted bare-ELF path (`host_run_elf`). The fresh empty address space is
/// already clean, so the ELF loader can write straight into it.
fn launch_elf<A: crate::Arch>(machine: &mut A, threads: &mut [thread::Thread<A>], buf: alloc::vec::Vec<u8>, path: &[u8], args: alloc::vec::Vec<alloc::vec::Vec<u8>>) -> usize {
    let cpipe = thread::console_pipe();
    let tid = {
        let t = thread::create_thread(threads, machine, None, A::PageTable::default(), true)
            .expect("create ELF thread");
        t.kernel.fds[0] = thread::FdKind::PipeRead(cpipe);
        t.kernel.fds[1] = thread::FdKind::ConsoleOut;
        t.kernel.fds[2] = thread::FdKind::ConsoleOut;
        t.kernel.tid as usize
    };
    crate::kernel::kpipe::add_reader(cpipe);
    crate::kernel::linux::exec_elf_into(machine, threads, tid, &buf, path, &args)
        .unwrap_or_else(|e| panic!("ELF exec failed ({}): errno {}",
            core::str::from_utf8(path).unwrap_or("?"), e));
    tid
}

/// Ring-1 kernel event loop. Returns when no threads remain.
///
/// One iteration is the whole kernel, in order: advance the running
/// thread's world (virtual time, console input, delivery), lend it the CPU,
/// canonicalize whatever came back into a `KernelAction`, and ask the
/// scheduler. Every concept lives behind its seam — `ExecutionContext`
/// (the CPU loan), `console` (input routing), `Personality` (the slice
/// hooks + event dispatch), `sched` (policy), `focus` (console ownership,
/// moved together with execution by `switch_focus_and_run` for now).
pub fn event_loop<A: crate::Arch>(machine: &mut A, threads: &mut [thread::Thread<A>], first_tid: usize) {
    crate::dbg_println!("event_loop entered, tid={}", first_tid);
    let mut ctx = crate::kernel::exec_ctx::ExecutionContext::seed(threads, first_tid);
    let mut stats = EventStats::new(machine);

    loop {
        stats.iteration(machine);
        let thread = ctx.thread(threads);

        // Advance this thread's world: virtual time, console input, delivery.
        thread.personality.on_slice(machine, &mut ctx.regs);
        crate::kernel::console::drain(machine, &mut ctx.regs, &mut thread.kernel, &mut thread.personality);
        thread.personality.after_input(machine, &mut thread.kernel, &mut ctx.regs);

        // A blocked thread holds the console but not the CPU: wait for input
        // to unblock it (above) or F11 to move on.
        if thread.kernel.state == thread::ThreadState::Blocked {
            match crate::kernel::sched::focus_request(threads, ctx.tid) {
                Some(next) => switch_focus_and_run(machine, threads, &mut ctx, next),
                None => core::hint::spin_loop(),
            }
            continue;
        }

        // Lend the CPU; canonicalize the outcome into an action.
        stats.pre_run(machine);
        let kevent = ctx.run(machine);
        stats.post_run(machine, &kevent, &ctx.regs);
        let action = dispatch(machine, thread, &mut ctx.regs, kevent);

        // Ask the scheduler.
        match crate::kernel::sched::verdict(machine, threads, &mut ctx.regs, ctx.tid, action) {
            crate::kernel::sched::Verdict::Stay => {}
            crate::kernel::sched::Verdict::Switch(next) => {
                switch_focus_and_run(machine, threads, &mut ctx, next);
            }
            crate::kernel::sched::Verdict::AllDead => {
                // The loop's contract: no thread resources survive it —
                // callers never inherit zombies.
                thread::reap_all_zombies(threads, machine);
                return;
            }
        }
    }
}

/// Canonicalize a kernel event into the action the scheduler decides on.
/// Page faults are decided here — an unhandled user fault is a SEGV exit,
/// and `signal_thread` wants the whole `Thread` for its diagnostics;
/// everything else is the personality's call.
fn dispatch<A: crate::Arch>(
    machine: &mut A,
    thread: &mut thread::Thread<A>,
    regs: &mut Regs,
    kevent: crate::KernelEvent,
) -> thread::KernelAction {
    if let crate::KernelEvent::PageFault { addr } = kevent {
        // A VGA planar-trap access (A0000 unmapped while unchained graphics
        // needs the write/read planar logic) is decoded + emulated here, not a
        // SEGV. Same path on both backends — both deliver this PageFault.
        if thread.personality.try_vga_fault(machine, regs, addr) {
            return thread::KernelAction::Done;
        }
        crate::println!("  fault rip={:#x} addr={:#x} err={:#x}",
            regs.frame.rip, addr, regs.err_code);
        crate::println!("  rax={:#x} rbx={:#x} rcx={:#x} rdx={:#x} rsi={:#x} rdi={:#x} rbp={:#x} rsp={:#x}",
            regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsi, regs.rdi, regs.rbp, regs.frame.rsp);
        crate::println!("  r8={:#x} r9={:#x} r10={:#x} r11={:#x} r12={:#x} r13={:#x} r14={:#x} r15={:#x}",
            regs.r8, regs.r9, regs.r10, regs.r11, regs.r12, regs.r13, regs.r14, regs.r15);
        thread::signal_thread(thread, addr as usize);
        return thread::KernelAction::Exit(-11);
    }
    thread.personality.handle_event(machine, &mut thread.kernel, regs, kevent)
}

/// Switch console focus and execution together — today's coupling, in one
/// named place. The event loop runs the focused thread, so every execution
/// switch is also a focus handoff (release: out-focus screen snapshot with
/// the old context live; acquire: in-focus repaint with the new context
/// live). When the scheduler decouples them, this helper is what splits.
///
/// Zombies skip the release because `exit_thread` already snapshotted
/// before `arch_user_clean` unmapped 0xA0000 (re-reading would fault). If
/// a parent wants the dying child's farewell screen to persist, it calls
/// `SYNTH_VGA_TAKE` explicitly — the kernel makes no inheritance policy.
fn switch_focus_and_run<A: crate::Arch>(
    machine: &mut A,
    threads: &mut [thread::Thread<A>],
    ctx: &mut crate::kernel::exec_ctx::ExecutionContext<A>,
    new_tid: usize,
) {
    if new_tid == ctx.tid {
        return;
    }
    {
        let old = thread::get_thread(threads, ctx.tid).expect("switch: invalid old thread");
        let old_personality = if old.kernel.state != thread::ThreadState::Zombie {
            Some(&mut old.personality)
        } else {
            None
        };
        crate::kernel::focus::release(machine, old_personality);
    }
    ctx.switch_to(threads, machine, new_tid);
    let new = thread::get_thread(threads, new_tid).expect("switch: invalid new thread");
    crate::kernel::focus::acquire(machine, new_tid, &mut new.personality);
    // switch_to derived the I/O bitmap before focus moved (it must — a bare
    // execution switch is valid without any focus change); now that this
    // thread holds focus, re-derive so the focused-only windows (VGA on a
    // real card) open. Cheap: a deny-all reset + a few range enables.
    crate::kernel::io_policy::apply(machine, &new.personality, true);
}

/// Fork the current process and exec a binary (DOS .COM/.EXE or ELF) in the child.
/// Blocks parent, returns child tid on success, None on error (caller stays on parent).
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_fork_exec<A: crate::Arch>(
    machine: &mut A,
    threads: &mut [thread::Thread<A>],
    vcpu: &mut Regs,
    parent_tid: usize,
    path: &[u8],
    cmdtail: &[u8],
    personality_name: Option<thread::PersonalityName>,
    viopl: u8,
    on_error: fn(&mut crate::Regs, i32),
    on_success: fn(&mut crate::Regs, i32),
) -> Option<usize> {
    use crate::kernel::exec;

    let parent = thread::get_thread(threads, parent_tid).expect("fork_exec: invalid parent");

    // Snapshot the parent's cwd and (DOS-only) env block while we're still in
    // the parent's address space. The COW fork + arch_user_clean inside
    // exec_dos_into tears the parent's pages out from under us, so anything
    // the child needs from parent memory must be copied to the kernel heap.
    //
    // cwd lives in the personality state (`DfsState` for DOS, `LinuxState`
    // for Linux); convert to common VFS-form (lowercase, forward-slash) for
    // child init.
    let mut parent_cwd_buf = [0u8; 64];
    let parent_cwd_len: usize;
    let parent_env_snapshot: Option<alloc::vec::Vec<u8>>;
    let parent_is_dos: bool;
    match &parent.personality {
        thread::Personality::Dos(dos) => {
            parent_is_dos = true;
            let dos_cwd = dos.dfs.get_cwd();
            let n = dos_cwd.len().min(parent_cwd_buf.len());
            for i in 0..n {
                parent_cwd_buf[i] = if dos_cwd[i] == b'\\' { b'/' } else { dos_cwd[i] };
            }
            parent_cwd_len = n;

            parent_env_snapshot = Some(crate::kernel::dos::snapshot_parent_env(machine, vcpu, dos));
        }
        thread::Personality::Linux(lin) => {
            parent_is_dos = false;
            let cwd = lin.cwd_str();
            parent_cwd_buf[..cwd.len()].copy_from_slice(cwd);
            parent_cwd_len = cwd.len();
            parent_env_snapshot = None;
        }
    }

    // `path` is in the launcher's namespace. For a DOS launcher it's a DOS path
    // — map it to VFS (DOS layer's translator) only for the read; the DOS form
    // is kept as-is for the program name. Otherwise it's already VFS.
    let read_path: alloc::vec::Vec<u8> = match personality_name {
        Some(thread::PersonalityName::Dos) => match crate::kernel::dos::dos_abs_to_vfs(path) {
            Some(v) => v,
            None => { on_error(vcpu, 2); return None; }
        },
        _ => path.to_vec(),
    };
    let buf = match exec::load_file_resolved(&read_path) {
        Ok(b) => b,
        Err(_) => { on_error(vcpu, 2); return None; }
    };

    let format = exec::detect_format(&buf, path);
    crate::dbg_println!("handle_fork_exec: {:?} size={} format={} free_pages={}",
        core::str::from_utf8(path), buf.len(),
        match format { exec::BinaryFormat::Elf => "elf", exec::BinaryFormat::MzExe => "exe", exec::BinaryFormat::Com => "com" },
        machine.free_page_count());

    // COW-fork parent address space for child
    let mut child_root = A::PageTable::default();
    machine.user_fork(&mut child_root);

    let child = match thread::create_thread(threads, machine, Some(parent_tid), child_root, true) {
        Some(t) => t,
        None => { on_error(vcpu, 8); return None; }
    };
    let child_tid = child.kernel.tid as usize;

    // Temporarily make the child's address space the active one so ELF load /
    // DOS setup operate on it (guest memory is the active space). The parent's
    // space is held aside and restored below. Unlike the old vcpu-swap, this
    // moves ONLY the space — the parent's live registers (`vcpu`) are never
    // touched, so no save/restore of them is needed.
    let parent_space = machine.activate(
        core::mem::take(&mut child.kernel.vcpu.space),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );

    // ELF needs user pages freed before loading; DOS handles its own address space
    if matches!(format, exec::BinaryFormat::Elf) {
        crate::dbg_println!("  fork done, loading ELF...");
        machine.free_user_pages();
    }

    let args = alloc::vec![path.to_vec()];
    let cmdtail = cmdtail.to_vec();
    let env = parent_env_snapshot.unwrap_or_default();
    let cwd = parent_cwd_buf[..parent_cwd_len].to_vec();
    if exec::init_thread(machine, threads, child_tid, buf, path, args, cmdtail, env, cwd, personality_name, viopl).is_err() {
        // Restore the parent's space and tear the half-built child down.
        let _ = machine.activate(parent_space, core::ptr::null_mut(), core::ptr::null_mut());
        thread::exit_thread(threads, machine, child_tid, 1);
        on_error(vcpu, 11);
        return None;
    }

    let child = thread::get_thread(threads, child_tid).unwrap();
    // Restore the parent's address space; the displaced child space re-parks in
    // its slot (init_thread already set the child's entry registers there).
    let child_space = machine.activate(parent_space, core::ptr::null_mut(), core::ptr::null_mut());
    child.kernel.vcpu.space = child_space;

    match &mut child.personality {
        thread::Personality::Linux(lin) => {
            // Inherit cwd from parent. (DOS path seeds DfsState inside
            // init_process_thread_vm86; Linux child stores cwd in LinuxState.)
            lin.cwd[..parent_cwd_len].copy_from_slice(&parent_cwd_buf[..parent_cwd_len]);
            lin.cwd_len = parent_cwd_len;
            let cpipe = thread::console_pipe();
            child.kernel.fds[0] = thread::FdKind::PipeRead(cpipe);
            child.kernel.fds[1] = thread::FdKind::ConsoleOut;
            child.kernel.fds[2] = thread::FdKind::ConsoleOut;
            crate::kernel::kpipe::add_reader(cpipe);
        }
        thread::Personality::Dos(_) => {
            // Only inherit the parent's screen if the parent is also DOS —
            // otherwise we'd save Linux console content into a DOS thread's
            // vga buffer, and the child would later "restore" Linux output
            // when focus returned to it. Cross-personality forks just leave
            // the child's vga empty; switch_thread's restore is a no-op on
            // empty planes, so the hardware shows whatever the previous
            // restore put up — the child draws on top.
            if parent_is_dos && crate::kernel::dos::vga_present() {
                let dos_state = child.dos_mut();
                dos_state.pc.vga.save_from_hardware();
            }
            machine.outb(0x3D4, 0x0E);
            let cursor_hi = machine.inb(0x3D5) as u16;
            machine.outb(0x3D4, 0x0F);
            let cursor_lo = machine.inb(0x3D5) as u16;
            let cursor_off = (cursor_hi << 8) | cursor_lo;
            let col = (cursor_off % 80) as u8;
            let row = (cursor_off / 80) as u8;
            // BDA 0040:0050 — the page-0 cursor position the child's BIOS
            // sees. Must go through the Vcpu guest accessor: a guest address
            // is a host address only on metal's low-mem identity window — on
            // the interp backend a raw 0x450 deref is the host null page
            // (SEGV'd on DN→PRINCE.EXE, the first task-spawn EXEC on interp).
            machine.write::<u8>(0x450, col);
            machine.write::<u8>(0x451, row);
        }
    }

    // Switch focus to child. Parent stays Ready; it'll poll SYNTH_WAITPID
    // when focus returns to it. No kernel-side blocking — the focused thread
    // runs continuously, so polling is just a status query.
    crate::dbg_println!("  child tid={}, parent tid={} continues without blocking", child_tid, parent_tid);
    on_success(vcpu, child_tid as i32);
    Some(child_tid)
}



/// F12 handler: dump the user thread state that was interrupted when F12 was
/// pressed. `regs` is always a user frame — the kernel event loop is never
/// interrupted by hardware IRQs.
/// - VM86: print guest CS:IP, common registers, BIOS timer, code bytes, and
///   the 80x25 VGA text buffer (for diagnosing hung DOS programs).
/// - PM: Rust stack trace via frame-pointer walking through user symbols.
///
/// `dos` (when present) adds virtual PIC/PIT state — useful for diagnosing
/// stuck IRQ delivery (e.g. an in-service bit never cleared by a missed EOI).
pub fn arch_dump_exception<A: crate::Arch>(machine: &mut A, dos: &thread::DosState<A>, regs: &Regs) {
    dump_interrupted_thread(machine, regs, Some(dos));
}

pub(crate) fn dump_interrupted_thread<A: crate::Arch>(machine: &mut A, regs: &Regs, dos: Option<&thread::DosState<A>>) {
    let vm86 = regs.flags32() & (1 << 17) != 0;
    if vm86 {
        // The guest's interrupt flag is VIF (bit 19); canonical bit 9 is
        // pinned to 1 and carries nothing.
        let vif = regs.flags32() & (1 << 19) != 0;
        let lin = (regs.cs32() << 4) + regs.ip32();
        // Guest reads via arch::mem() (identity on metal, mmap offset on the
        // interpreter) — raw `lin as *const u8` would fault on the interp.
        let mut b = [0u8; 8];
        machine.copy_from(lin as usize, &mut b);
        let ticks = machine.read::<u32>(0x46C);
        crate::dbg_println!("[DBG] VM86 {:04X}:{:04X} AX={:04X} BX={:04X} CX={:04X} DX={:04X} DS={:04X} SS:SP={:04X}:{:04X} flags={:04X} VIF={} ticks={} code={:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            regs.code_seg(), regs.ip32(),
            regs.rax as u16, regs.rbx as u16, regs.rcx as u16, regs.rdx as u16,
            regs.ds as u16, regs.stack_seg(), regs.sp32(),
            regs.flags32() as u16, vif as u8, ticks,
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
        if let Some(d) = dos { dump_virtual_hw(d); }
        // Dump VGA hardware register state (which one differs vs working
        // is the first thing to check when buffer paints but screen is
        // black — most often SEQ[1] bit 5 = screen-off, GC[6] framebuffer
        // mapping, or AC mode register text-vs-graphics).
        {
            use crate::kernel::portio::{inb, outb};
            let _ = inb(0x3DA);
            let misc = inb(0x3CC);
            let mut seq = [0u8; 5];
            for i in 0..5u8 { outb(0x3C4, i); seq[i as usize] = inb(0x3C5); }
            let mut crtc = [0u8; 25];
            for i in 0..25u8 { outb(0x3D4, i); crtc[i as usize] = inb(0x3D5); }
            let mut gc = [0u8; 9];
            for i in 0..9u8 { outb(0x3CE, i); gc[i as usize] = inb(0x3CF); }
            let _ = inb(0x3DA);
            let mut ac = [0u8; 21];
            for i in 0..21u8 { let _ = inb(0x3DA); outb(0x3C0, i | 0x20); ac[i as usize] = inb(0x3C1); }
            let _ = inb(0x3DA);
            outb(0x3C0, 0x20);   // re-enable display by setting PAS
            crate::dbg_println!("[VGA HW] misc={:02X} seq=[{:02X} {:02X} {:02X} {:02X} {:02X}]",
                misc, seq[0], seq[1], seq[2], seq[3], seq[4]);
            crate::dbg_println!("[VGA HW] gc=[{:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}]",
                gc[0], gc[1], gc[2], gc[3], gc[4], gc[5], gc[6], gc[7], gc[8]);
            crate::dbg_println!("[VGA HW] ac[10..14]={:02X} {:02X} {:02X} {:02X}  crtc[0C..0F]={:02X} {:02X} {:02X} {:02X}",
                ac[0x10], ac[0x11], ac[0x12], ac[0x13], crtc[0x0C], crtc[0x0D], crtc[0x0E], crtc[0x0F]);
        }
        // Dump VGA text buffer (80x25, char+attr interleaved at 0xB8000).
        // Through arch::mem() so it works on both backends — `0xB8000` is a
        // guest address, identity-mapped on metal but an mmap offset on the
        // interpreter (a raw `0xB8000 as *const u8` would fault there).
        let mut vga = [0u8; 4000];
        machine.copy_from(0xB8000, &mut vga);
        for row in 0..25 {
            let mut line = [b'.'; 80];
            for col in 0..80 {
                let ch = vga[(row * 80 + col) * 2];
                line[col] = if (0x20..0x7F).contains(&ch) { ch } else { b'.' };
            }
            crate::dbg_println!("[VGA {:02}] {}", row,
                core::str::from_utf8(&line).unwrap_or("???"));
        }
    } else {
        let fl = regs.flags32();
        crate::dbg_println!("[DBG] PM CS:EIP={:04x}:{:#010x} SS:ESP={:04x}:{:#010x} EFLAGS={:#010x} VIF={} vIOPL={}",
            regs.code_seg(), regs.ip32(), regs.stack_seg(), regs.sp32(), fl, (fl >> 19) & 1, (fl >> 12) & 3);
        crate::dbg_println!("[DBG] AX={:08x} BX={:08x} CX={:08x} DX={:08x} SI={:08x} DI={:08x} BP={:08x}",
            regs.rax as u32, regs.rbx as u32, regs.rcx as u32, regs.rdx as u32,
            regs.rsi as u32, regs.rdi as u32, regs.rbp as u32);
        crate::dbg_println!("[DBG] DS={:04x} ES={:04x} FS={:04x} GS={:04x}",
            regs.ds as u16, regs.es as u16, regs.fs as u16, regs.gs as u16);
        if let Some(d) = dos {
            crate::kernel::dos::dump_dpmi_state(machine, d, regs);
            dump_virtual_hw(d);
        }
        crate::kernel::stacktrace::stack_trace_regs(regs);
    }
}

/// Print virtual PIC/PIT state — the actual IRQ-delivery gating lives here,
/// so hangs that look like "timer stopped" usually show up as a stuck in-
/// service bit (a higher-priority pending line is blocked by it) or a
/// requested-but-masked line.
fn dump_virtual_hw<A: crate::Arch>(dos: &thread::DosState<A>) {
    let (mirr, misr, mimr, sirr, sisr, simr) = dos.pc.vpic.debug_state();
    crate::dbg_println!("[DBG] vpic master irr={:#04x} isr={:#04x} imr={:#04x}  slave irr={:#04x} isr={:#04x} imr={:#04x}",
        mirr, misr, mimr, sirr, sisr, simr);

    let (en, mode, reload, now, next) = dos.pc.vpit.debug_state();
    let delta = (next as i64).wrapping_sub(now as i64);
    crate::dbg_println!("[DBG] vpit ch0 en={} mode={} reload={} now={} next={} (next-now={})",
        en, mode, reload, now, next, delta);

    crate::kernel::dos::dump_if_ring();
    crate::kernel::dos::dump_gus_ring();
}


/// Event-loop diagnostics: per-event-type counts, user/kernel cycle split,
/// the periodic [prof] dump, and the free-page low-water sampling. Keeps
/// the loop body logic, not bookkeeping.
struct EventStats {
    iterations: u64,
    min_free: usize,
    last_free: usize,
    user_cycles: u64,
    kernel_cycles: u64,
    last_kernel_entry: u64,
    last_profile_dump: u64,
    counts: [u32; 11], // irq, softint, hlt, in, out, ins, outs, fault, pf, exc, syscall
}

impl EventStats {
    /// Sampling cadence for the free-page low-water mark.
    const MEM_DUMP_PERIOD: u64 = 1000;
    /// Profile dump cadence. Roughly assume 2 GHz host; only used to format
    /// the dump as seconds. Off by a constant factor but the ratio is exact.
    const PROFILE_DUMP_CYCLES: u64 = 2_000_000_000;
    /// Emit the periodic `[prof]` line. Off by default — it floods the kernel
    /// log (and the `LOG` ring buffer); flip to true to profile the event loop.
    const PROFILE_DUMP: bool = false;

    fn new<A: crate::Arch>(machine: &mut A) -> Self {
        let free = machine.free_page_count();
        let now = machine.rdtsc();
        EventStats {
            iterations: 0,
            min_free: free,
            last_free: free,
            user_cycles: 0,
            kernel_cycles: 0,
            last_kernel_entry: now,
            last_profile_dump: now,
            counts: [0; 11],
        }
    }

    fn iteration<A: crate::Arch>(&mut self, machine: &mut A) {
        self.iterations = self.iterations.wrapping_add(1);
        if self.iterations.is_multiple_of(Self::MEM_DUMP_PERIOD) {
            let free = machine.free_page_count();
            if free < self.min_free {
                self.min_free = free;
            }
            self.last_free = free;
        }
    }

    fn pre_run<A: crate::Arch>(&mut self, machine: &mut A) {
        let now = machine.rdtsc();
        self.kernel_cycles = self
            .kernel_cycles
            .wrapping_add(now.wrapping_sub(self.last_kernel_entry));
        self.last_kernel_entry = now;
    }

    fn post_run<A: crate::Arch>(
        &mut self,
        machine: &mut A,
        kevent: &crate::KernelEvent,
        regs: &Regs,
    ) {
        use crate::KernelEvent as KE;
        let now = machine.rdtsc();
        self.user_cycles = self
            .user_cycles
            .wrapping_add(now.wrapping_sub(self.last_kernel_entry));
        self.last_kernel_entry = now;
        let idx = match kevent {
            KE::Irq => 0,
            KE::SoftInt(_) => 1,
            KE::Hlt => 2,
            KE::In { .. } => 3,
            KE::Out { .. } => 4,
            KE::Ins { .. } => 5,
            KE::Outs { .. } => 6,
            KE::Fault => 7,
            KE::PageFault { .. } => 8,
            KE::Exception(_) => 9,
            KE::Syscall => 10,
            KE::VifWindow { .. } | KE::VifStep => 1,
        };
        self.counts[idx] += 1;
        if now.wrapping_sub(self.last_profile_dump) >= Self::PROFILE_DUMP_CYCLES {
            if Self::PROFILE_DUMP {
                let total = self.user_cycles.wrapping_add(self.kernel_cycles);
                let user_pct = self.user_cycles.wrapping_mul(100).checked_div(total).unwrap_or(0);
                let kern_pct = self.kernel_cycles.wrapping_mul(100).checked_div(total).unwrap_or(0);
                let c = &self.counts;
                crate::dbg_println!("[prof] user={}% kernel={}% irq={} softint={} hlt={} in={} out={} ins={} outs={} pf={} exc={} fault={} syscall={} ticks={} at={:04X}:{:08X} ss:sp={:04X}:{:08X}",
                    user_pct, kern_pct,
                    c[0], c[1], c[2], c[3], c[4], c[5], c[6],
                    c[8], c[9], c[7], c[10], machine.get_ticks(),
                    regs.code_seg(), regs.ip32(), regs.stack_seg(), regs.sp32());
            }
            self.user_cycles = 0;
            self.kernel_cycles = 0;
            self.counts = [0; 11];
            self.last_profile_dump = now;
        }
    }
}

fn trim_ascii(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|&c| c > b' ').unwrap_or(s.len());
    let end = s.iter().rposition(|&c| c > b' ').map_or(start, |i| i + 1);
    &s[start..end]
}
