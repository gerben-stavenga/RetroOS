//! Kernel startup - filesystem mount and DN.COM loader

extern crate alloc;

extern crate ext4_view;


use crate::kernel::{hdd, vfs, tarfs::TarFs, ext4fs::Ext4Fs};
use crate::println;
use crate::kernel::thread;
// Arch interface wrappers now live in arch::calls; these are called bare here.
use crate::arch::{do_arch_execute, arch_switch_to, arch_user_fork, arch_free_user_pages};

/// The root filesystem instance (static so it lives forever for &'static dyn)
static mut ROOT_TARFS: TarFs = TarFs::new(0);

/// Ext4 filesystem (heap-allocated at boot, leaked to get &'static)
static mut EXT4_FS: Option<&'static Ext4Fs> = None;

/// Startup: mount filesystem and run DN.COM in a loop.
/// Called from enter_ring1 — we are already at ring 1.
pub fn startup(machine: &mut crate::TheArch) -> ! {
    // Heap must be live before any kernel code allocates. Arch only depends
    // on phys_mm during boot; everything heap-using lives at or below this
    // entry point.
    crate::kernel::heap::init();
    println!("Heap initialized");

    crate::kernel::thread::init_threading();

    // Reset ATA controller (needed when booted via GRUB)
    hdd::reset();

    // Read MBR sector 0 to get partition table
    let mut mbr = [0u8; 512];
    hdd::read_sectors(0, &mut mbr);

    // Scan MBR partition table: 4 entries at 0x1BE, each 16 bytes
    // Entry: [status, CHS_start(3), type, CHS_end(3), LBA_start(4), LBA_size(4)]
    // Layout: 0xDA boot bundle TAR (mounts at /boot/) + 0x83 ext4 (root).
    for i in 0..4 {
        let base = 0x1BE + i * 16;
        let ptype = mbr[base + 4];
        let lba = u32::from_le_bytes(mbr[base + 8..base + 12].try_into().unwrap());
        if ptype == 0 { continue; }

        match ptype {
            0xDA => {
                println!("Partition {}: TAR at sector {:#x}", i, lba);
                unsafe {
                    ROOT_TARFS = TarFs::new(lba);
                    (&raw mut ROOT_TARFS).as_mut().unwrap().build_index();
                }
            }
            0x83 => {
                println!("Partition {}: ext4 at sector {:#x}", i, lba);
                match Ext4Fs::new(lba) {
                    Ok(fs) => {
                        let leaked = alloc::boxed::Box::leak(alloc::boxed::Box::new(fs));
                        unsafe { EXT4_FS = Some(leaked); }
                        vfs::mount(b"", leaked);
                        println!("  ext4 mounted as root");
                    }
                    Err(e) => panic!("ext4 mount failed: {}", e),
                }
            }
            _ => {}
        }
    }

    // Boot bundle TAR mounts at /boot/; the ext4 root holds everything else.
    #[allow(static_mut_refs)]
    unsafe { vfs::mount(b"boot/", &ROOT_TARFS); }

    // Mount host filesystem on COM1 serial (hostfs.py must be running)
    if crate::kernel::hostfs::init() {
        static HOSTFS: crate::kernel::hostfs::HostFs = crate::kernel::hostfs::HostFs::new();
        vfs::mount(b"host/", &HOSTFS);
        println!("hostfs mounted at /host");
    }

    crate::kernel::stacktrace::init_from_tar();

    // /CONFIG.SYS provides the master env handed to DN and any user-driven
    // launches. KEY=VALUE lines, `#` comments. Missing is fine -- yields an
    // empty env; the boot self-build below uses its own self-contained env.
    let config = crate::kernel::exec::load_file_resolved(b"CONFIG.SYS").unwrap_or_default();
    let master_env = crate::kernel::dos::parse_config_env(&config);

    // Allocate console stdin pipe (keyboard → Linux stdin). The kernel
    // itself is the writer (via process_key during the event loop drain),
    // so register a phantom writer permanently — without it, has_writers
    // returns false and the first read on fd 0 reports EOF immediately,
    // which makes busybox/sh bail out at startup.
    let console_pipe = crate::kernel::kpipe::alloc().expect("Failed to allocate console pipe");
    crate::kernel::kpipe::add_writer(console_pipe);
    crate::kernel::thread::set_console_pipe(console_pipe);

    // Host may select a program via QEMU `-fw_cfg name=opt/cmdline,string=...`.
    // Multiple commands separated by `;` are run in sequence; the machine
    // shuts down when the last one exits. If absent, run DN.COM in a loop
    // (default interactive shell).
    let mut cmdline_buf = [0u8; 4096];
    if let Some(raw) = fw_cfg_read(b"opt/cmdline", &mut cmdline_buf) {
        // CWD: explicit `opt/cwd` fw_cfg key wins; else fall back to each
        // program's own directory.
        let mut cwd_buf = [0u8; 256];
        let explicit_cwd = fw_cfg_read(b"opt/cwd", &mut cwd_buf).map(trim_ascii);

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
            run_dos_program(machine, path, tail, cwd, &master_env);
        }
        println!("All commands done — shutting down.");
        crate::arch::shutdown();
    }

    // Self-build: recompile BOOT\SRC\COMMAND.C -> root COMMAND.COM at boot.
    // cwd="" so the linker writes the output to the drive root (C:\COMMAND.COM);
    // DN's EXEC of "COMMAND.COM /C ..." then picks up the freshly-built one.
    //
    // Prefer Borland C++ when present (the proprietary image, \BORLANDC): BCC
    // compiling + EXEC'ing TLINK — a 16-bit DPMI parent that execs a child,
    // which exits and returns — exercises the INT 21h AH=4Bh EXEC / MCB path
    // end-to-end every boot, so breakage there surfaces immediately. BC++ 3.1
    // is abandonware (not officially free like TC 2.01), so it ships only in
    // the proprietary image. The open image has no \BORLANDC and falls back to
    // freeware Turbo C 2.01 in the boot bundle; with neither present, the tar's
    // pre-built COMMAND.COM runs as-is.
    if crate::kernel::exec::load_file_resolved(b"BORLANDC/BIN/BCC.EXE").is_ok() {
        println!("Building COMMAND.COM from BOOT\\SRC\\COMMAND.C via BCC + Borland TLINK...");
        // Hermetic env: PATH has ONLY C:\BORLANDC\BIN so BCC EXECs Borland's
        // own TLINK 5.1 — not TC's TLINK 2.0 (which a PATH listing C:\BOOT\TC
        // first would shadow it with). Include/lib paths come from
        // BORLANDC\BIN\TURBOC.CFG / TLINK.CFG (-I/-L), which BCC and TLINK read
        // from their own EXE directory, so no INCLUDE/LIB env is needed.
        run_dos_program(machine, 
            b"BORLANDC/BIN/BCC.EXE",
            b"-mt -lt BOOT\\SRC\\COMMAND.C",
            b"",
            b"PATH=C:\\BORLANDC\\BIN\0\0",
        );
        println!("Build done.");
    } else if crate::kernel::exec::load_file_resolved(b"boot/TC/TCC.EXE").is_ok() {
        println!("Building COMMAND.COM from BOOT\\SRC\\COMMAND.C via TC...");
        // Hermetic env: only PATH so TCC can find TLINK; bypasses CONFIG.SYS.
        run_dos_program(machine, 
            b"boot/TC/TCC.EXE",
            b"-mt -lt BOOT\\SRC\\COMMAND.C",
            b"",
            b"PATH=C:\\BOOT\\TC\0\0",
        );
        println!("Build done.");
    }

    println!("Welcome to RetroOS! Use F11 to switch tasks, F12 to dump the currently running thread's state, and type `help` for DOS commands.");

    println!("Starting DN...");
    loop {
        run_dos_program(machine, b"boot/DN/DN.COM", b"", b"", &master_env);
        println!("DN exited, restarting...");
    }
}

/// Load a DOS program (.COM or MZ .EXE) into a fresh VM86 thread and run the
/// event loop until it exits. `cmdline_tail` is written to PSP:0080h (without
/// the length byte or terminator; those are added automatically).
fn run_dos_program(machine: &mut crate::TheArch, path: &[u8], cmdline_tail: &[u8], cwd: &[u8], env: &[u8]) {
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

    set_debug_watch(None);

    let tid = dos::run_init_program(buf, args, cmdline_tail, cwd, env);

    if let Some((addr0, addr1)) = debug_watch_config() {
        set_debug_watch(Some((addr0, addr1)));
        if addr1 != 0 {
            crate::dbg_println!("[WATCH] armed write watchpoints at {:08X} and {:08X}", addr0, addr1);
        } else {
            crate::dbg_println!("[WATCH] armed write watchpoint at {:08X}", addr0);
        }
    }
    event_loop(machine, tid);
}

// Hardware write-watchpoints via debug registers — a metal-only arch call. The
// interpreter has no debug-register feature, so hosted makes this a no-op.
#[cfg(not(feature = "hosted"))]
fn set_debug_watch(addrs: Option<(u32, u32)>) {
    let (count, addr0, addr1) = match addrs {
        Some((addr0, addr1)) if addr1 != 0 => (2u32, addr0, addr1),
        Some((addr0, _)) => (1u32, addr0, 0),
        None => (0u32, 0, 0),
    };
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::SET_DEBUG_WATCH as u32,
            in("ebx") count,
            in("edx") addr0,
            in("ecx") addr1,
        );
    }
}

#[cfg(feature = "hosted")]
fn set_debug_watch(_addrs: Option<(u32, u32)>) {}

fn debug_watch_config() -> Option<(u32, u32)> {
    let mut buf = [0u8; 64];
    let raw = fw_cfg_read(b"opt/debug-watch", &mut buf)?;
    let raw = trim_ascii(raw);
    if raw.is_empty() {
        return None;
    }

    let split = raw.iter().position(|&b| b == b',' || b == b' ' || b == b';');
    let addr0 = parse_u32(raw.get(..split.unwrap_or(raw.len()))?)?;
    let addr1 = match split {
        Some(idx) => parse_u32(trim_ascii(&raw[idx + 1..])).unwrap_or(0),
        None => 0,
    };
    Some((addr0, addr1))
}

fn parse_u32(mut s: &[u8]) -> Option<u32> {
    s = trim_ascii(s);
    if s.starts_with(b"0x") || s.starts_with(b"0X") {
        s = &s[2..];
    }
    if s.is_empty() {
        return None;
    }

    let mut value = 0u32;
    for &b in s {
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as u32,
            b'a'..=b'f' => (b - b'a' + 10) as u32,
            b'A'..=b'F' => (b - b'A' + 10) as u32,
            b'_' => continue,
            _ => return None,
        };
        value = value.checked_mul(16)?.checked_add(digit)?;
    }
    Some(value)
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
    use crate::arch::REGS;
    use arch_abi::Arch;

    crate::dbg_println!("event_loop entered, tid={}", first_tid);
    let mut tid = first_tid;

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
    // REGS already set up by startup, page tables correct from boot
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
        let regs = unsafe { &mut *(&raw mut REGS) };

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
                        crate::kernel::dos::queue_irq(dos, crate::arch::Irq::Tick);
                    }
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
                                unsafe { (*dp).process_key(sc); }
                            } else {
                                crate::kernel::dos::queue_irq(unsafe { &mut *dp }, evt);
                            }
                        }
                    });
                    if !is_blocked {
                        crate::kernel::dos::raise_pending(unsafe { &mut *dp }, regs);
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
                    tid = switch_thread(tid, next);
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
        let kevent = crate::arch::do_arch_execute();
        let ts_after_user = machine.rdtsc();
        user_cycles = user_cycles.wrapping_add(ts_after_user.wrapping_sub(ts_before_user));
        last_kernel_entry = ts_after_user;
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
            crate::dbg_println!("[prof] user={}% kernel={}% irq={} softint={} hlt={} in={} out={} ins={} outs={} pf={} exc={} fault={} syscall={} at={:04X}:{:08X} ss:sp={:04X}:{:08X}",
                user_pct, kern_pct,
                ev_irq, ev_softint, ev_hlt, ev_in, ev_out, ev_ins, ev_outs,
                ev_pf, ev_exc, ev_fault, ev_syscall,
                regs.code_seg(), regs.ip32(), regs.stack_seg(), regs.sp32());
            user_cycles = 0;
            kernel_cycles = 0;
            ev_irq = 0; ev_softint = 0; ev_hlt = 0;
            ev_in = 0; ev_out = 0; ev_ins = 0; ev_outs = 0;
            ev_fault = 0; ev_pf = 0; ev_exc = 0; ev_syscall = 0;
            last_profile_dump = ts_after_user;
        }

        let regs = unsafe { &mut *(&raw mut REGS) };

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
                thread::Personality::Dos(dos) => crate::kernel::dos::handle_event(kt, dos, regs, kevent),
                thread::Personality::Linux(linux) => crate::kernel::linux::handle_event(kt, linux, regs, kevent),
            }
        };


        let new_tid: Option<usize> = match action {
            thread::KernelAction::Done => None,
            thread::KernelAction::Yield => thread::yield_thread(tid, regs),
            thread::KernelAction::Exit(code) => Some(thread::exit_thread(tid, code)),
            thread::KernelAction::Switch(next) => Some(next),
            thread::KernelAction::ForkExec { path, path_len, cmdtail, cmdtail_len, on_error, on_success } => {
                handle_fork_exec(tid, regs, &path[..path_len], &cmdtail[..cmdtail_len], on_error, on_success)
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
            if new_tid == 0 { return; } // no threads left — respawn DN
            tid = switch_thread(tid, new_tid);
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
fn switch_thread(tid: usize, new_tid: usize) -> usize {
    if new_tid == tid { return tid; }
    let (old, new) = thread::get_two_threads(tid, new_tid);
    if old.kernel.state != thread::ThreadState::Zombie {
        old.personality.suspend();
    }
    verify_cpu_hash(new, "switch-in");
    let mut swap_vcpu = new.kernel.vcpu;
    let mut swap_fx = new.kernel.fx_state;
    if ASSERT_ADDR_HASH {
        let mut hash = new.kernel.addr_hash;
        arch_switch_to(&mut swap_vcpu, &mut hash, &mut swap_fx);
        old.kernel.addr_hash = hash;
    } else {
        arch_switch_to(&mut swap_vcpu, core::ptr::null_mut(), &mut swap_fx);
    }
    old.kernel.vcpu = swap_vcpu;
    old.kernel.fx_state = swap_fx;
    old.kernel.cpu_hash = thread::hash_regs(&old.kernel.vcpu.regs);
    new.personality.materialize();
    new.personality.on_resume();
    new_tid
}

/// Fork the current process and exec a binary (DOS .COM/.EXE or ELF) in the child.
/// Blocks parent, returns child tid on success, None on error (caller stays on parent).
fn handle_fork_exec(
    parent_tid: usize,
    regs: &mut crate::Regs,
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

            parent_env_snapshot = Some(crate::kernel::dos::snapshot_parent_env(dos));
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
        Err(_) => { on_error(regs, 2); return None; }
    };

    let format = exec::detect_format(&buf, path);
    crate::dbg_println!("handle_fork_exec: {:?} size={} format={} free_pages={}",
        core::str::from_utf8(path), buf.len(),
        match format { exec::BinaryFormat::Elf => "elf", exec::BinaryFormat::MzExe => "exe", exec::BinaryFormat::Com => "com" },
        crate::arch::free_page_count());

    // COW-fork parent address space for child
    let mut child_root = crate::RootPageTable::empty();
    arch_user_fork(&mut child_root);

    let child = match thread::create_thread(Some(parent_tid), child_root, true) {
        Some(t) => t,
        None => { on_error(regs, 8); return None; }
    };
    let child_tid = child.kernel.tid as usize;

    // Save parent's user regs (in REGS) before the swap — exec_dos_into
    // bundles address-space setup + init_process_thread_vm86, which would
    // overwrite the parent state that the first swap parks in child.vcpu.regs.
    let parent_regs = *regs;

    arch_switch_to(&mut child.kernel.vcpu, core::ptr::null_mut(), core::ptr::null_mut());

    // ELF needs user pages freed before loading; DOS handles its own address space
    if matches!(format, exec::BinaryFormat::Elf) {
        crate::dbg_println!("  fork done, loading ELF...");
        arch_free_user_pages();
    }

    let args = alloc::vec![path.to_vec()];
    let cmdtail = cmdtail.to_vec();
    let env = parent_env_snapshot.unwrap_or_default();
    let cwd = parent_cwd_buf[..parent_cwd_len].to_vec();
    if let Err(_) = exec::init_thread(child_tid, buf, path, args, cmdtail, env, cwd) {
        let child = thread::get_thread(child_tid).unwrap();
        arch_switch_to(&mut child.kernel.vcpu, core::ptr::null_mut(), core::ptr::null_mut());
        thread::exit_thread(child_tid, 1);
        on_error(regs, 11);
        return None;
    }

    let child = thread::get_thread(child_tid).unwrap();
    // Swap back to parent's address space. Save child's cpu_state (set by
    // init_thread) and restore after — the swap would overwrite it.
    let saved_cpu = child.kernel.vcpu.regs;
    arch_switch_to(&mut child.kernel.vcpu, core::ptr::null_mut(), core::ptr::null_mut());
    child.kernel.vcpu.regs = saved_cpu;
    // Restore parent's user regs into REGS (the swap left stale data there).
    *regs = parent_regs;

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
            if parent_is_dos {
                let dos_state = child.dos_mut();
                dos_state.pc.vga.save_from_hardware();
            }
            use crate::arch::{inb, outb};
            outb(0x3D4, 0x0E);
            let cursor_hi = inb(0x3D5) as u16;
            outb(0x3D4, 0x0F);
            let cursor_lo = inb(0x3D5) as u16;
            let cursor_off = (cursor_hi << 8) | cursor_lo;
            let col = (cursor_off % 80) as u8;
            let row = (cursor_off / 80) as u8;
            unsafe {
                core::ptr::write_volatile(0x450 as *mut u8, col);
                core::ptr::write_volatile(0x451 as *mut u8, row);
            }
        }
    }

    // Switch focus to child. Parent stays Ready; it'll poll SYNTH_WAITPID
    // when focus returns to it. No kernel-side blocking — the focused thread
    // runs continuously, so polling is just a status query.
    crate::dbg_println!("  child tid={}, parent tid={} continues without blocking", child_tid, parent_tid);
    on_success(regs, child_tid as i32);
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
pub fn arch_dump_exception(dos: &thread::DosState, regs: &crate::Regs) {
    dump_interrupted_thread(regs, Some(dos));
}

fn dump_interrupted_thread(regs: &crate::Regs, dos: Option<&thread::DosState>) {
    let vm86 = regs.flags32() & (1 << 17) != 0;
    if vm86 {
        let vif = regs.flags32() & (1 << 9) != 0;
        let lin = (regs.cs32() << 4) + regs.ip32();
        // Guest reads via arch::mem() (identity on metal, mmap offset on the
        // interpreter) — raw `lin as *const u8` would fault on the interp.
        let b = crate::arch::mem().slice(lin as usize, 8);
        let ticks = crate::arch::mem().read::<u32>(0x46C);
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
        let vga = crate::arch::mem().slice(0xB8000, 4000);
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


// --- QEMU fw_cfg reader --------------------------------------------------
// Lets the host select which program to run via:
//   -fw_cfg name=opt/cmdline,string=PATH
// Selector register is big-endian over the wire; data port is byte-stream.
const FW_CFG_SEL: u16 = 0x510;
const FW_CFG_DATA: u16 = 0x511;
const FW_CFG_SIG: u16 = 0x0000;
const FW_CFG_FILE_DIR: u16 = 0x0019;

fn fw_cfg_select(sel: u16) {
    crate::arch::outw(FW_CFG_SEL, sel);
}

fn fw_cfg_read_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() { *b = crate::arch::inb(FW_CFG_DATA); }
}

// Cached host identity. QEMU exposes the fw_cfg "QEMU" signature; Bochs and
// real hardware have no fw_cfg interface. 0 = not yet probed, 1 = not QEMU,
// 2 = QEMU. Primed at boot by the `opt/cmdline` read below (it calls
// fw_cfg_present), so the hot-path `is_qemu()` is a plain cached load.
static HOST_QEMU: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

fn fw_cfg_present() -> bool {
    fw_cfg_select(FW_CFG_SIG);
    let mut sig = [0u8; 4];
    fw_cfg_read_bytes(&mut sig);
    let qemu = &sig == b"QEMU";
    HOST_QEMU.store(if qemu { 2 } else { 1 }, core::sync::atomic::Ordering::Relaxed);
    qemu
}

/// True iff running under QEMU (vs Bochs / real hardware), detected once via
/// the fw_cfg signature and cached. Cheap to call on hot paths.
///
/// Used to gate QEMU-specific emulation-bug workarounds — e.g. the synthetic
/// 0x3DA vtrace in the DOS machine layer, which exists only because QEMU's
/// 0x3DA doesn't sweep a raster; Bochs/real hardware drive it correctly and
/// are passed through.
pub fn is_qemu() -> bool {
    match HOST_QEMU.load(core::sync::atomic::Ordering::Relaxed) {
        2 => true,
        1 => false,
        _ => fw_cfg_present(), // not yet probed (no cmdline read ran): probe + cache now
    }
}

fn fw_cfg_read<'a>(name: &[u8], buf: &'a mut [u8]) -> Option<&'a [u8]> {
    if !fw_cfg_present() { return None; }
    fw_cfg_select(FW_CFG_FILE_DIR);
    let mut count_be = [0u8; 4];
    fw_cfg_read_bytes(&mut count_be);
    let count = u32::from_be_bytes(count_be);
    for _ in 0..count {
        let mut entry = [0u8; 64];
        fw_cfg_read_bytes(&mut entry);
        let size = u32::from_be_bytes(entry[0..4].try_into().unwrap()) as usize;
        let sel = u16::from_be_bytes(entry[4..6].try_into().unwrap());
        let name_end = entry[8..].iter().position(|&c| c == 0).unwrap_or(56);
        if &entry[8..8 + name_end] == name {
            let n = size.min(buf.len());
            fw_cfg_select(sel);
            fw_cfg_read_bytes(&mut buf[..n]);
            return Some(&buf[..n]);
        }
    }
    None
}

fn trim_ascii(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|&c| c > b' ').unwrap_or(s.len());
    let end = s.iter().rposition(|&c| c > b' ').map_or(start, |i| i + 1);
    &s[start..end]
}
