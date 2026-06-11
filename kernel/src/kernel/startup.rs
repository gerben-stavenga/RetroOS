//! Kernel startup - filesystem mount and DN.COM loader

extern crate alloc;

extern crate ext4_view;


use crate::kernel::{vfs, tarfs::TarFs, ext4fs::Ext4Fs};
use crate::println;
use crate::kernel::thread;
use arch_abi::Arch; // the `machine: &mut TheArch` trait methods (execute/switch_to/…)
use arch_abi::GuestBytes;

/// The root filesystem instance (static so it lives forever for &'static dyn)
static mut ROOT_TARFS: TarFs = TarFs::new(0);

/// Ext4 filesystem (heap-allocated at boot, leaked to get &'static)
static mut EXT4_FS: Option<&'static Ext4Fs> = None;

/// Startup: the kernel's ordered init spine — probe, then derive, then run.
/// Each phase is a named function below; this stays short enough to read as
/// the boot story. Called from enter_ring1 — we are already at ring 1.
pub fn startup(machine: &mut crate::TheArch, boot: &crate::BootConfig) -> ! {
    // Heap must be live before any kernel code allocates. Arch only depends
    // on phys_mm during boot; everything heap-using lives at or below this
    // entry point.
    crate::kernel::heap::init();
    println!("Heap initialized");

    // Pick the boot disk: ATA where present, NVMe on UEFI-class machines —
    // before the platform probe, which reads the MBR for the Media verdict.
    crate::kernel::block::init(machine);
    println!("Block devices initialized");

    // Probe the machine ONCE and freeze the result; all hardware policy
    // (VGA passthrough, BIOS choice, audio, media/mounts, console, IOPB)
    // derives from this.
    let platform = crate::kernel::platform::probe(machine, boot);

    crate::kernel::thread::init_threading();
    println!("Threading initialized");

    mount_filesystems(platform);
    init_device_policy(machine, platform);
    let master_env = load_master_env();
    init_console_pipe();

    run(machine, boot, &master_env)
}

/// The host filesystem (COM1 transport). Mounted at /host beside a disk
/// root, or AS the root under `Media::HostRoot`.
static HOSTFS: crate::kernel::hostfs::HostFs = crate::kernel::hostfs::HostFs::new();

/// Derive the mount set from the platform's Media verdict (the probe already
/// scanned the MBR and the hostfs transport); then the symbol index.
/// /boot is an INVARIANT: the embedded bootfs (DN + COMMAND.COM), mounted on
/// top of whatever the root is — the disk's 0xDA boot-bundle partition is
/// bootloader-only and never mounted.
fn mount_filesystems(platform: &'static crate::kernel::platform::Platform) {
    use crate::kernel::platform::Media;

    match platform.media {
        Media::DiskRoot { ext4_lba, hostfs } => {
            println!("ext4 root at sector {:#x}", ext4_lba);
            match Ext4Fs::new(ext4_lba) {
                Ok(fs) => {
                    let leaked = alloc::boxed::Box::leak(alloc::boxed::Box::new(fs));
                    unsafe { EXT4_FS = Some(leaked); }
                    vfs::mount(b"", leaked);
                }
                Err(e) => panic!("ext4 mount failed: {}", e),
            }
            if hostfs {
                vfs::mount(b"host/", &HOSTFS);
                println!("hostfs mounted at /host");
            }
        }
        Media::HostRoot => {
            // The host directory IS the drive (DOSBox-style). Alias it at
            // /host too so DiskRoot-era `host/...` paths keep working.
            vfs::mount(b"", &HOSTFS);
            vfs::mount(b"host/", &HOSTFS);
            println!("hostfs mounted as root");
        }
        Media::Diskless => {}
    }

    if let Some(bytes) = crate::bootfs() {
        unsafe {
            ROOT_TARFS = TarFs::new_ram(bytes);
            (&raw mut ROOT_TARFS).as_mut().unwrap().build_index();
        }
    }
    #[allow(static_mut_refs)]
    unsafe { vfs::mount(b"boot/", &ROOT_TARFS); }

    crate::kernel::stacktrace::init_from_tar();
}

/// Device policy, derived from the platform probe — not re-probed here.
/// Port permissions are NOT set here: `io_policy::apply` rebuilds the I/O
/// bitmap per thread on every swap-in (the VGA window follows console
/// focus; Linux threads get nothing).
fn init_device_policy(
    machine: &mut crate::TheArch,
    _platform: &'static crate::kernel::platform::Platform,
) {
    // Probe for an AC'97 codec (metal). If present it becomes the kernel audio
    // output for the emulated Sound Blaster; absent (no PCI, e.g. the
    // interpreter) leaves the sound path on its port-window fallback.
    crate::kernel::ac97::init(machine);
}

/// /CONFIG.SYS provides the master env handed to DN and any user-driven
/// launches. KEY=VALUE lines, `#` comments. No root CONFIG.SYS (diskless
/// boot) falls back to the embedded bootfs copy, whose PATH points into
/// C:\BOOT; with neither, the env is empty.
fn load_master_env() -> alloc::vec::Vec<u8> {
    let config = crate::kernel::exec::load_file_resolved(b"CONFIG.SYS")
        .or_else(|_| crate::kernel::exec::load_file_resolved(b"boot/CONFIG.SYS"))
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
fn run(machine: &mut crate::TheArch, boot: &crate::BootConfig, master_env: &[u8]) -> ! {
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
            println!("Starting {} {} (cwd={})...",
                core::str::from_utf8(path).unwrap_or("?"),
                core::str::from_utf8(tail).unwrap_or(""),
                core::str::from_utf8(cwd).unwrap_or("?"));
            run_dos_program(machine, path, tail, cwd, master_env, boot.debug_watch);
        }
        println!("All commands done — shutting down.");
        machine.shutdown();
    }

    // COMMAND.COM is prebuilt (in-OS TCC at image-build time —
    // //apps-boot/command:command_com) and ships at C:\COMMAND.COM plus inside
    // the embedded bootfs at C:\BOOT\COMMAND.COM. The per-boot self-build from
    // BOOT\SRC\COMMAND.C is gone with it; the BCC EXEC-path exercise it
    // doubled as lives on in test/dpmi_smoke.sh.

    println!("Welcome to RetroOS! Use F11 to switch tasks, F12 to dump the currently running thread's state, and type `help` for DOS commands.");

    println!("Starting DN...");
    loop {
        run_dos_program(machine, b"boot/DN/DN.COM", b"", b"", master_env, boot.debug_watch);
        println!("DN exited, restarting...");
    }
}

/// Load a DOS program (.COM or MZ .EXE) into a fresh VM86 thread and run the
/// event loop until it exits. `cmdline_tail` is written to PSP:0080h (without
/// the length byte or terminator; those are added automatically).
fn run_dos_program(machine: &mut crate::TheArch, path: &[u8], cmdline_tail: &[u8], cwd: &[u8], env: &[u8], debug_watch: Option<(u32, u32)>) {
    use crate::kernel::{dos, exec};

    let buf = exec::load_file_resolved(path)
        .unwrap_or_else(|_| panic!("{} not found", core::str::from_utf8(path).unwrap_or("?")));
    let args = alloc::vec![path.to_vec()];
    let cmdline_tail = cmdline_tail.to_vec();
    let cwd = cwd.to_vec();
    let env = env.to_vec();

    // Hand the screen off to the user. From here on, kernel println!/print!
    // go to debugcon only — VGA writes from the kernel would otherwise
    // corrupt user-space pixel data when the program is in graphics mode
    // (CGA modes use B8000 as a pixel framebuffer, identical address to
    // text-mode char+attr storage). dos_putchar's direct VGA writes are
    // not gated by this flag and continue to work for text-mode programs.
    crate::vga::KERNEL_OWNS_SCREEN.store(false, core::sync::atomic::Ordering::Relaxed);

    machine.set_debug_watch(None);

    let tid = dos::run_init_program(machine, buf, args, cmdline_tail, cwd, env);

    // The initial program owns the console outright (nothing to repaint) and
    // gets its port permissions from policy, not from boot-time leftovers.
    crate::kernel::focus::adopt(tid);
    {
        let t = thread::get_thread(tid).expect("init program thread");
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
    event_loop(machine, tid);
}

const ASSERT_ADDR_HASH: bool = false;

/// Verify that a thread's saved cpu_state still matches the hash recorded on
/// the last switch-out. Print a diff-style dump on mismatch.
/// `tag` is printed in the header ("switch-in" / "reblock" / ...).
fn verify_cpu_hash(t: &thread::Thread, tag: &str) {
    let k = &t.kernel;
    if k.cpu_hash == 0 { return; }
    let actual = thread::hash_regs(&k.vcpu.regs);
    if actual == k.cpu_hash { return; }
    crate::println!(
        "\x1b[91mCPU STATE CORRUPTION [{}] tid={} expected={:#018x} actual={:#018x}\x1b[0m",
        tag, k.tid, k.cpu_hash, actual,
    );
    let r = &k.vcpu.regs;
    crate::println!(
        "  cs:ip={:04x}:{:08x} ss:sp={:04x}:{:08x} flags={:08x}",
        r.code_seg(), r.ip32(), r.stack_seg(), r.sp32(), r.flags32(),
    );
    crate::println!(
        "  ds={:04x} es={:04x} fs={:04x} gs={:04x}",
        r.ds as u16, r.es as u16, r.fs as u16, r.gs as u16,
    );
    crate::println!(
        "  eax={:08x} ebx={:08x} ecx={:08x} edx={:08x}",
        r.rax as u32, r.rbx as u32, r.rcx as u32, r.rdx as u32,
    );
    crate::println!(
        "  esi={:08x} edi={:08x} ebp={:08x} int={:02x} err={:08x}",
        r.rsi as u32, r.rdi as u32, r.rbp as u32, r.int_num as u32, r.err_code as u32,
    );
}

/// Ring-1 kernel event loop. Returns when no threads remain.
/// EXECUTE swaps kernel↔user regs. SWITCH_TO changes threads (root + mode toggle).
pub(crate) fn event_loop(machine: &mut crate::TheArch, first_tid: usize) {

    crate::dbg_println!("event_loop entered, tid={}", first_tid);
    let mut tid = first_tid;

    // The live CPU context, owned by the loop (no global `REGS`). Seeded from
    // the first thread's saved state; `machine.execute(&mut vcpu)` runs it and
    // writes the post-run state back, and `switch_thread` swaps it on a context
    // switch. Handlers receive `&mut vcpu` (disjoint from `&mut machine`), so the
    // borrow checker — not a `static mut` — keeps register and machine state
    // from aliasing.
    let mut vcpu = thread::get_thread(first_tid)
        .expect("event_loop: invalid first thread")
        .kernel.vcpu;

    // Page-allocator instrumentation: every MEM_DUMP_PERIOD iterations,
    // log free physical pages and the running low-water mark. Watch the
    // line for monotonic decrease to find leaks. Print to debug serial
    // only — does not clobber user VGA.
    const MEM_DUMP_PERIOD: u64 = 1000;
    let mut event_counter: u64 = 0;
    let mut min_free: usize = machine.free_page_count();
    let mut last_free: usize = min_free;
    // crate::dbg_println!("[mem] start free={}", min_free);

    // User/kernel cycle accounting. We bracket `do_arch_execute()` with
    // rdtsc; every iteration adds a chunk to USER_CYCLES and a chunk to
    // KERNEL_CYCLES. The split tells you whether app code is the
    // bottleneck or our trap/event handling is.
    let mut user_cycles: u64 = 0;
    let mut kernel_cycles: u64 = 0;
    let mut last_kernel_entry = machine.rdtsc();
    let mut last_profile_dump = last_kernel_entry;
    // Roughly assume 2 GHz host; only used to format the dump as ms. Off
    // by a constant factor across runs but the user/kernel ratio is exact.
    const PROFILE_DUMP_CYCLES: u64 = 2_000_000_000; // ~1 second on 2GHz host
    // Per-event-type counts for the same window, to identify which trap
    // kind is dominating when kernel% is high.
    let mut ev_irq: u32 = 0;
    let mut ev_softint: u32 = 0;
    let mut ev_hlt: u32 = 0;
    let mut ev_in: u32 = 0;
    let mut ev_out: u32 = 0;
    let mut ev_ins: u32 = 0;
    let mut ev_outs: u32 = 0;
    let mut ev_fault: u32 = 0;
    let mut ev_pf: u32 = 0;
    let mut ev_exc: u32 = 0;
    let mut ev_syscall: u32 = 0;
    // `vcpu` seeded from the first thread above; page tables correct from boot.
    loop {
        event_counter = event_counter.wrapping_add(1);
        if event_counter % MEM_DUMP_PERIOD == 0 {
            let free = machine.free_page_count();
            if free < min_free { min_free = free; }
            let _delta = (free as i64) - (last_free as i64);
            // crate::dbg_println!("[mem] iter={} free={} delta={} min={}",
            //     event_counter, free, delta, min_free);
            last_free = free;
        }
        crate::kernel::stacktrace::set_debug_tid(tid);
        let regs = &mut vcpu;

        // Phase 1: drain hardware events into the running thread's personality,
        // then try to satisfy any pending pipe read.
        {
            let thread = thread::get_thread(tid).expect("Invalid thread in event loop");
            let kt = &mut thread.kernel;
            match &mut thread.personality {
                thread::Personality::Dos(dos) => {
                    let is_blocked = kt.state == thread::ThreadState::Blocked;
                    let ticks = machine.take_pending_ticks();
                    for _ in 0..ticks {
                        crate::kernel::dos::queue_tick(machine, dos);
                    }
                    if ticks > 0 {
                        crate::kernel::dos::display_tick(dos, regs, ticks);
                    }
                    // Pump emulated-SB playback against the same virtual clock.
                    crate::kernel::dos::audio_tick(machine, dos, regs);
                    let dp = dos as *mut thread::DosState;
                    machine.drain(&mut |evt| {
                        if matches!(evt, crate::arch::Irq::Key(sc) if sc == F11_PRESS) {
                            thread::request_switch();
                        } else if matches!(evt, crate::arch::Irq::Key(sc) if sc == F12_PRESS) {
                            dump_interrupted_thread(regs, Some(unsafe { &*dp }));
                        } else if is_blocked {
                            if let crate::arch::Irq::Key(sc) = evt {
                                if crate::kernel::keyboard::update_key_state(sc) {
                                    let c = crate::kernel::keyboard::scancode_to_ascii(sc);
                                    if c != 0 {
                                        crate::vga::putchar(c);
                                        let cpipe = thread::console_pipe();
                                        crate::kernel::kpipe::write(cpipe, &[c]);
                                    }
                                }
                            }
                        } else {
                            if let crate::arch::Irq::Key(sc) = evt {
                                unsafe { (*dp).process_key(regs, sc); }
                            } else {
                                crate::kernel::dos::queue_irq(unsafe { &mut *dp }, regs, evt);
                            }
                        }
                    });
                    if !is_blocked {
                        crate::kernel::dos::raise_pending(machine, unsafe { &mut *dp }, regs);
                    }
                }
                thread::Personality::Linux(linux) => {
                    let ktp = kt as *mut thread::KernelThread;
                    let lp = linux as *mut thread::LinuxState;
                    machine.drain(&mut |evt| {
                        if let crate::arch::Irq::Key(sc) = evt {
                            if sc == F11_PRESS {
                                thread::request_switch();
                            } else if sc == F12_PRESS {
                                dump_interrupted_thread(regs, None);
                            } else {
                                unsafe { (*lp).process_key(&(*ktp).fds, sc); }
                            }
                        }
                    });
                }
            }

            if kt.state == thread::ThreadState::Blocked {
                if let thread::Personality::Linux(ref mut linux) = thread.personality {
                    if let Some(ref pr) = linux.pending_read {
                        if let thread::FdKind::PipeRead(idx) = pr.fd_kind {
                            let user_buf = unsafe {
                                core::slice::from_raw_parts_mut(pr.buf_ptr as *mut u8, pr.buf_len)
                            };
                            let n = crate::kernel::kpipe::read(idx, user_buf);
                            if n > 0 {
                                regs.rax = n as u64;
                                linux.pending_read = None;
                                kt.state = thread::ThreadState::Ready;
                            }
                        }
                    } else if let Some(ref pp) = linux.pending_poll {
                        let ready = crate::kernel::linux::run_poll(kt, pp.fds_ptr, pp.nfds);
                        if ready > 0 {
                            regs.rax = ready as u64;
                            linux.pending_poll = None;
                            kt.state = thread::ThreadState::Ready;
                        }
                    }
                }
            }
        }

        // Phase 2: if still parked, honour F11 (cycle focus) or spin. The
        // take_switch_request consumer below the do_arch_execute path is
        // unreachable from here, so we re-implement the switch step inline.
        if thread::get_thread(tid).expect("Invalid thread").kernel.state
            == thread::ThreadState::Blocked
        {
            if thread::take_switch_request() {
                if let Some(next) = thread::cycle_next(tid) {
                    tid = switch_thread(machine, &mut vcpu, tid, next);
                    continue;
                }
            }
            core::hint::spin_loop();
            continue;
        }

        // Phase 3: run user code and dispatch the resulting event.
        let thread = thread::get_thread(tid).expect("Invalid thread in event loop");
        let ts_before_user = machine.rdtsc();
        kernel_cycles = kernel_cycles.wrapping_add(ts_before_user.wrapping_sub(last_kernel_entry));
        let kevent = machine.execute(&mut vcpu);
        let ts_after_user = machine.rdtsc();
        user_cycles = user_cycles.wrapping_add(ts_after_user.wrapping_sub(ts_before_user));
        last_kernel_entry = ts_after_user;
        // The live register frame for this iteration (post-run). Borrows the
        // loop-owned `vcpu`; `machine.execute` above already returned, so there
        // is no aliasing with the run.
        let regs = &mut vcpu;
        match &kevent {
            crate::arch::monitor::KernelEvent::Irq => ev_irq += 1,
            crate::arch::monitor::KernelEvent::SoftInt(_) => ev_softint += 1,
            crate::arch::monitor::KernelEvent::Hlt => ev_hlt += 1,
            crate::arch::monitor::KernelEvent::In { .. } => ev_in += 1,
            crate::arch::monitor::KernelEvent::Out { .. } => ev_out += 1,
            crate::arch::monitor::KernelEvent::Ins { .. } => ev_ins += 1,
            crate::arch::monitor::KernelEvent::Outs { .. } => ev_outs += 1,
            crate::arch::monitor::KernelEvent::Fault => ev_fault += 1,
            crate::arch::monitor::KernelEvent::PageFault { .. } => ev_pf += 1,
            crate::arch::monitor::KernelEvent::Exception(_) => ev_exc += 1,
            crate::arch::monitor::KernelEvent::Syscall => ev_syscall += 1,
        }
        if ts_after_user.wrapping_sub(last_profile_dump) >= PROFILE_DUMP_CYCLES {
            let total = user_cycles.wrapping_add(kernel_cycles);
            let user_pct = if total > 0 { user_cycles.wrapping_mul(100) / total } else { 0 };
            let kern_pct = if total > 0 { kernel_cycles.wrapping_mul(100) / total } else { 0 };
            crate::dbg_println!("[prof] user={}% kernel={}% irq={} softint={} hlt={} in={} out={} ins={} outs={} pf={} exc={} fault={} syscall={} ticks={} at={:04X}:{:08X} ss:sp={:04X}:{:08X}",
                user_pct, kern_pct,
                ev_irq, ev_softint, ev_hlt, ev_in, ev_out, ev_ins, ev_outs,
                ev_pf, ev_exc, ev_fault, ev_syscall, machine.get_ticks(),
                regs.code_seg(), regs.ip32(), regs.stack_seg(), regs.sp32());
            user_cycles = 0;
            kernel_cycles = 0;
            ev_irq = 0; ev_softint = 0; ev_hlt = 0;
            ev_in = 0; ev_out = 0; ev_ins = 0; ev_outs = 0;
            ev_fault = 0; ev_pf = 0; ev_exc = 0; ev_syscall = 0;
            last_profile_dump = ts_after_user;
        }

        // PageFault is handled at the loop level because `signal_thread`
        // needs the full `&Thread`. Everything else dispatches through
        // the personality's `handle_event`. The `Exit(-11)` below runs
        // against the faulting `tid` so `exit_thread` does the standard
        // cleanup (parent wake, last_child_exit_status, arch_user_clean,
        // on_exit) — exactly what a normal program exit does.
        let action = if let crate::arch::monitor::KernelEvent::PageFault { addr } = kevent {
            let rip = regs.frame.rip;
            crate::println!("  fault rip={:#x} addr={:#x} err={:#x}", rip, addr, regs.err_code);
            thread::signal_thread(thread, addr as usize);
            thread::KernelAction::Exit(-11)
        } else {
            let kt = &mut thread.kernel;
            match &mut thread.personality {
                thread::Personality::Dos(dos) => crate::kernel::dos::handle_event(machine, kt, dos, regs, kevent),
                thread::Personality::Linux(linux) => crate::kernel::linux::handle_event(machine, kt, linux, regs, kevent),
            }
        };


        let new_tid: Option<usize> = match action {
            thread::KernelAction::Done => None,
            thread::KernelAction::Yield => thread::yield_thread(tid, regs),
            thread::KernelAction::Exit(code) => Some(thread::exit_thread(machine, tid, code)),
            thread::KernelAction::Switch(next) => Some(next),
            thread::KernelAction::ForkExec { path, path_len, cmdtail, cmdtail_len, on_error, on_success } => {
                handle_fork_exec(machine, regs, tid, &path[..path_len], &cmdtail[..cmdtail_len], on_error, on_success)
            }
            thread::KernelAction::Fork(_) => {
                // TODO: implement Fork in event loop
                None
            }
            thread::KernelAction::Exec { path: _, path_len: _, args: _ } => {
                // TODO: implement Exec in event loop
                None
            }
        };

        // F11: round-robin thread cycle. Pure focus shift — does not wake any
        // blocked thread or break any waitpid. The shell (command.com) decides
        // backgrounding semantics by polling SYNTH_WAITPID + reading kbd.
        let new_tid = if new_tid.is_none() && thread::take_switch_request() {
            thread::cycle_next(tid)
        } else {
            new_tid
        };

        if let Some(new_tid) = new_tid {
            if new_tid == 0 {
                // No runnable threads left. Reap every zombie NOW — the
                // loop's contract is that all thread resources (address
                // spaces, VGA state) are released before it returns;
                // callers never inherit zombies.
                thread::reap_all_zombies(machine);
                return; // respawn DN / next cmdline program
            }
            tid = switch_thread(machine, &mut vcpu, tid, new_tid);
        }
    }
}

/// Swap CPU state, address space, FPU, and the VGA framebuffer to make
/// `new_tid` the running thread. No-op when `new_tid == tid`. Returns the
/// new tid.
///
/// Lifecycle hooks live on the personalities:
///   - `suspend`     — snapshot screen state on out-focus.
///   - `materialize` — repaint screen state on in-focus.
///   - `on_resume`   — rebind CPU state (LDT/TLS/...) on every swap-in.
///
/// Zombies skip the suspend here because `exit_thread` already called it
/// before `arch_user_clean` unmapped 0xA0000 (re-reading would fault). If
/// a parent wants the dying child's farewell screen to persist, it calls
/// `SYNTH_VGA_TAKE` explicitly — the kernel makes no inheritance policy.
fn switch_thread(machine: &mut crate::TheArch, live: &mut crate::arch::Vcpu, tid: usize, new_tid: usize) -> usize {
    if new_tid == tid { return tid; }
    let (old, new) = thread::get_two_threads(tid, new_tid);
    // Console focus follows the run switch today (the event loop runs the
    // focused thread); the concepts stay separate so a future scheduler can
    // run background threads without moving focus.
    let old_personality = if old.kernel.state != thread::ThreadState::Zombie {
        Some(&mut old.personality)
    } else {
        None
    };
    crate::kernel::focus::release(old_personality);
    verify_cpu_hash(new, "switch-in");
    let mut swap_vcpu = new.kernel.vcpu;
    let mut swap_fx = new.kernel.fx_state;
    if ASSERT_ADDR_HASH {
        let mut hash = new.kernel.addr_hash;
        machine.switch_to(live, &mut swap_vcpu, &mut hash, &mut swap_fx);
        old.kernel.addr_hash = hash;
    } else {
        machine.switch_to(live, &mut swap_vcpu, core::ptr::null_mut(), &mut swap_fx);
    }
    old.kernel.vcpu = swap_vcpu;
    old.kernel.fx_state = swap_fx;
    old.kernel.cpu_hash = thread::hash_regs(&old.kernel.vcpu.regs);
    crate::kernel::focus::acquire(new_tid, &mut new.personality);
    // The incoming thread's port permissions: rebuilt from (personality,
    // platform, focus) — never inherited from whoever ran last.
    crate::kernel::io_policy::apply(
        machine,
        &new.personality,
        new_tid == crate::kernel::focus::focused(),
    );
    new.personality.on_resume(machine);
    new_tid
}

/// Fork the current process and exec a binary (DOS .COM/.EXE or ELF) in the child.
/// Blocks parent, returns child tid on success, None on error (caller stays on parent).
fn handle_fork_exec(
    machine: &mut crate::TheArch,
    vcpu: &mut crate::arch::Vcpu,
    parent_tid: usize,
    path: &[u8],
    cmdtail: &[u8],
    on_error: fn(&mut crate::Regs, i32),
    on_success: fn(&mut crate::Regs, i32),
) -> Option<usize> {
    use crate::kernel::exec;

    let parent = thread::get_thread(parent_tid).expect("fork_exec: invalid parent");

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

            parent_env_snapshot = Some(crate::kernel::dos::snapshot_parent_env(vcpu, dos));
        }
        thread::Personality::Linux(lin) => {
            parent_is_dos = false;
            let cwd = lin.cwd_str();
            parent_cwd_buf[..cwd.len()].copy_from_slice(cwd);
            parent_cwd_len = cwd.len();
            parent_env_snapshot = None;
        }
    }

    let buf = match exec::load_file_resolved(path) {
        Ok(b) => b,
        Err(_) => { on_error(&mut vcpu.regs, 2); return None; }
    };

    let format = exec::detect_format(&buf, path);
    crate::dbg_println!("handle_fork_exec: {:?} size={} format={} free_pages={}",
        core::str::from_utf8(path), buf.len(),
        match format { exec::BinaryFormat::Elf => "elf", exec::BinaryFormat::MzExe => "exe", exec::BinaryFormat::Com => "com" },
        machine.free_page_count());

    // COW-fork parent address space for child
    let mut child_root = crate::RootPageTable::empty();
    machine.user_fork(&mut child_root);

    let child = match thread::create_thread(machine, Some(parent_tid), child_root, true) {
        Some(t) => t,
        None => { on_error(&mut vcpu.regs, 8); return None; }
    };
    let child_tid = child.kernel.tid as usize;

    // Save parent's user regs (the live frame) before the swap — exec_dos_into
    // bundles address-space setup + init_process_thread_vm86, which would
    // overwrite the parent state that the first swap parks in child.vcpu.regs.
    let parent_regs = vcpu.regs;

    machine.switch_to(vcpu, &mut child.kernel.vcpu, core::ptr::null_mut(), core::ptr::null_mut());

    // ELF needs user pages freed before loading; DOS handles its own address space
    if matches!(format, exec::BinaryFormat::Elf) {
        crate::dbg_println!("  fork done, loading ELF...");
        machine.free_user_pages();
    }

    let args = alloc::vec![path.to_vec()];
    let cmdtail = cmdtail.to_vec();
    let env = parent_env_snapshot.unwrap_or_default();
    let cwd = parent_cwd_buf[..parent_cwd_len].to_vec();
    if let Err(_) = exec::init_thread(machine, child_tid, buf, path, args, cmdtail, env, cwd) {
        let child = thread::get_thread(child_tid).unwrap();
        machine.switch_to(vcpu, &mut child.kernel.vcpu, core::ptr::null_mut(), core::ptr::null_mut());
        thread::exit_thread(machine, child_tid, 1);
        on_error(&mut vcpu.regs, 11);
        return None;
    }

    let child = thread::get_thread(child_tid).unwrap();
    // Swap back to parent's address space. Save child's cpu_state (set by
    // init_thread) and restore after — the swap would overwrite it.
    let saved_cpu = child.kernel.vcpu.regs;
    machine.switch_to(vcpu, &mut child.kernel.vcpu, core::ptr::null_mut(), core::ptr::null_mut());
    child.kernel.vcpu.regs = saved_cpu;
    // Restore parent's user regs into the live frame (the swap left stale data).
    vcpu.regs = parent_regs;

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
            vcpu.write::<u8>(0x450, col);
            vcpu.write::<u8>(0x451, row);
        }
    }

    // Switch focus to child. Parent stays Ready; it'll poll SYNTH_WAITPID
    // when focus returns to it. No kernel-side blocking — the focused thread
    // runs continuously, so polling is just a status query.
    crate::dbg_println!("  child tid={}, parent tid={} continues without blocking", child_tid, parent_tid);
    on_success(&mut vcpu.regs, child_tid as i32);
    Some(child_tid)
}

/// F11 scancode (press)
const F11_PRESS: u8 = 0x57;

/// F12 scancode (press) — debug dump hotkey
const F12_PRESS: u8 = 0x58;

/// F12 handler: dump the user thread state that was interrupted when F12 was
/// pressed. `regs` is always a user frame — the kernel event loop is never
/// interrupted by hardware IRQs.
/// - VM86: print guest CS:IP, common registers, BIOS timer, code bytes, and
///   the 80x25 VGA text buffer (for diagnosing hung DOS programs).
/// - PM: Rust stack trace via frame-pointer walking through user symbols.
/// `dos` (when present) adds virtual PIC/PIT state — useful for diagnosing
/// stuck IRQ delivery (e.g. an in-service bit never cleared by a missed EOI).
pub fn arch_dump_exception(dos: &thread::DosState, regs: &crate::arch::Vcpu) {
    dump_interrupted_thread(regs, Some(dos));
}

fn dump_interrupted_thread(regs: &crate::arch::Vcpu, dos: Option<&thread::DosState>) {
    let vm86 = regs.flags32() & (1 << 17) != 0;
    if vm86 {
        let vif = regs.flags32() & (1 << 9) != 0;
        let lin = (regs.cs32() << 4) + regs.ip32();
        // Guest reads via arch::mem() (identity on metal, mmap offset on the
        // interpreter) — raw `lin as *const u8` would fault on the interp.
        let mut b = [0u8; 8];
        regs.copy_from(lin as usize, &mut b);
        let ticks = regs.read::<u32>(0x46C);
        crate::dbg_println!("[DBG] VM86 {:04X}:{:04X} AX={:04X} BX={:04X} CX={:04X} DX={:04X} DS={:04X} SS:SP={:04X}:{:04X} flags={:04X} IF={} ticks={} code={:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
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
            use crate::arch::{inb, outb};
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
        regs.copy_from(0xB8000, &mut vga);
        for row in 0..25 {
            let mut line = [b'.'; 80];
            for col in 0..80 {
                let ch = vga[(row * 80 + col) * 2];
                line[col] = if ch >= 0x20 && ch < 0x7F { ch } else { b'.' };
            }
            crate::dbg_println!("[VGA {:02}] {}", row,
                core::str::from_utf8(&line).unwrap_or("???"));
        }
    } else {
        let fl = regs.flags32();
        crate::dbg_println!("[DBG] PM CS:EIP={:04x}:{:#010x} SS:ESP={:04x}:{:#010x} EFLAGS={:#010x} IF={}",
            regs.code_seg(), regs.ip32(), regs.stack_seg(), regs.sp32(), fl, (fl >> 9) & 1);
        crate::dbg_println!("[DBG] AX={:08x} BX={:08x} CX={:08x} DX={:08x} SI={:08x} DI={:08x} BP={:08x}",
            regs.rax as u32, regs.rbx as u32, regs.rcx as u32, regs.rdx as u32,
            regs.rsi as u32, regs.rdi as u32, regs.rbp as u32);
        crate::dbg_println!("[DBG] DS={:04x} ES={:04x} FS={:04x} GS={:04x}",
            regs.ds as u16, regs.es as u16, regs.fs as u16, regs.gs as u16);
        if let Some(d) = dos {
            crate::kernel::dos::dump_dpmi_state(d, regs);
            dump_virtual_hw(d);
        }
        crate::kernel::stacktrace::stack_trace_regs(regs);
    }
}

/// Print virtual PIC/PIT state — the actual IRQ-delivery gating lives here,
/// so hangs that look like "timer stopped" usually show up as a stuck in-
/// service bit (a higher-priority pending line is blocked by it) or a
/// requested-but-masked line.
fn dump_virtual_hw(dos: &thread::DosState) {
    let (mirr, misr, mimr, sirr, sisr, simr) = dos.pc.vpic.debug_state();
    crate::dbg_println!("[DBG] vpic master irr={:#04x} isr={:#04x} imr={:#04x}  slave irr={:#04x} isr={:#04x} imr={:#04x}",
        mirr, misr, mimr, sirr, sisr, simr);

    let (en, mode, reload, now, next) = dos.pc.vpit.debug_state();
    let delta = (next as i64).wrapping_sub(now as i64);
    crate::dbg_println!("[DBG] vpit ch0 en={} mode={} reload={} now={} next={} (next-now={})",
        en, mode, reload, now, next, delta);

    crate::kernel::dos::dump_if_ring();
}


fn trim_ascii(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|&c| c > b' ').unwrap_or(s.len());
    let end = s.iter().rposition(|&c| c > b' ').map_or(start, |i| i + 1);
    &s[start..end]
}
