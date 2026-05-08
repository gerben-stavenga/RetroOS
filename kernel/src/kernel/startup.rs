//! Kernel startup - filesystem mount and DN.COM loader

extern crate alloc;

extern crate ext4_view;


use crate::kernel::{hdd, vfs, tarfs::TarFs, ext4fs::Ext4Fs};
use crate::println;
use crate::kernel::thread;

/// The root filesystem instance (static so it lives forever for &'static dyn)
static mut ROOT_TARFS: TarFs = TarFs::new(0);

/// Ext4 filesystem (heap-allocated at boot, leaked to get &'static)
static mut EXT4_FS: Option<&'static Ext4Fs> = None;

/// Startup: mount filesystem and run DN.COM in a loop.
/// Called from enter_ring1 — we are already at ring 1.
pub fn startup() -> ! {
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
    let mut has_ext4 = false;
    for i in 0..4 {
        let base = 0x1BE + i * 16;
        let ptype = mbr[base + 4];
        let lba = u32::from_le_bytes(mbr[base + 8..base + 12].try_into().unwrap());
        if ptype == 0 { continue; }

        match ptype {
            0xDA => {
                // TAR filesystem
                println!("Partition {}: TAR at sector {:#x}", i, lba);
                unsafe {
                    ROOT_TARFS = TarFs::new(lba);
                    (&raw mut ROOT_TARFS).as_mut().unwrap().build_index();
                }
            }
            0x83 if !has_ext4 => {
                // Linux ext4
                println!("Partition {}: ext4 at sector {:#x}", i, lba);
                match Ext4Fs::new(lba) {
                    Ok(fs) => {
                        let leaked = alloc::boxed::Box::leak(alloc::boxed::Box::new(fs));
                        unsafe { EXT4_FS = Some(leaked); }
                        vfs::mount(b"", leaked);
                        has_ext4 = true;
                        println!("  ext4 mounted as root");
                    }
                    Err(e) => println!("  ext4 mount failed: {}", e),
                }
            }
            _ => {}
        }
    }

    // Mount TAR: at "tar/" if ext4 is root, otherwise as root itself
    let tar_prefix: &[u8] = if has_ext4 { b"tar/" } else { b"" };
    #[allow(static_mut_refs)]
    unsafe { vfs::mount(tar_prefix, &ROOT_TARFS); }

    // Mount host filesystem on COM1 serial (hostfs.py must be running)
    if crate::kernel::hostfs::init() {
        static HOSTFS: crate::kernel::hostfs::HostFs = crate::kernel::hostfs::HostFs::new();
        vfs::mount(b"host/", &HOSTFS);
        println!("hostfs mounted at /host");
    }

    crate::kernel::stacktrace::init_from_tar();

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

            let mut path_buf = [0u8; 260];
            let path: &[u8] = if has_ext4 {
                let n = 4 + prog.len();
                path_buf[..4].copy_from_slice(b"tar/");
                path_buf[4..n].copy_from_slice(prog);
                &path_buf[..n]
            } else {
                path_buf[..prog.len()].copy_from_slice(prog);
                &path_buf[..prog.len()]
            };

            let cwd: &[u8] = match explicit_cwd {
                Some(c) => c,
                None => {
                    let cwd_end = path.iter().rposition(|&b| b == b'/').map_or(0, |i| i + 1);
                    &path_buf[..cwd_end]
                }
            };
            println!("Starting {} {} (cwd={})...",
                core::str::from_utf8(path).unwrap_or("?"),
                core::str::from_utf8(tail).unwrap_or(""),
                core::str::from_utf8(cwd).unwrap_or("?"));
            run_dos_program(path, tail, cwd);
        }
        println!("All commands done — shutting down.");
        crate::arch::shutdown();
    }

    // Self-build: if Turbo C is on the image, compile SRC\COMMAND.C →
    // root COMMAND.COM via TC at boot. The output lands in the VFS RAM
    // overlay, shadowing the BC++-built COMMAND.COM that ships in the
    // tar. DN's EXEC of "COMMAND.COM /C ..." then picks up the freshly-
    // built one. With TC absent (empty apps/tc/), the tar's pre-built
    // COMMAND.COM is what runs.
    let tcc_path: &[u8] = if has_ext4 { b"tar/TC/TCC.EXE" } else { b"TC/TCC.EXE" };
    if crate::kernel::exec::load_file_resolved(tcc_path).is_ok() {
        println!("Building COMMAND.COM from SRC\\COMMAND.C via TC...");
        run_dos_program(tcc_path, b"-mt -lt SRC\\COMMAND.C", b"");
        println!("Build done.");
    }

    println!("Welcome to RetroOS! Use F11 to switch tasks, F12 to dump the currently running thread's state, and type `help` for DOS commands.");

    let dn_path: &[u8] = if has_ext4 { b"tar/DN/DN.COM" } else { b"DN/DN.COM" };
    let dn_cwd: &[u8] = if has_ext4 { b"tar/" } else { b"" };
    println!("Starting DN...");
    loop {
        run_dos_program(dn_path, b"", dn_cwd);
        println!("DN exited, restarting...");
    }
}

/// Load a DOS program (.COM or MZ .EXE) into a fresh VM86 thread and run the
/// event loop until it exits. `cmdline_tail` is written to PSP:0080h (without
/// the length byte or terminator; those are added automatically).
fn run_dos_program(path: &[u8], cmdline_tail: &[u8], cwd: &[u8]) {
    use crate::kernel::{dos, exec};

    let buf = exec::load_file_resolved(path)
        .unwrap_or_else(|_| panic!("{} not found", core::str::from_utf8(path).unwrap_or("?")));

    // Hand the screen off to the user. From here on, kernel println!/print!
    // go to debugcon only — VGA writes from the kernel would otherwise
    // corrupt user-space pixel data when the program is in graphics mode
    // (CGA modes use B8000 as a pixel framebuffer, identical address to
    // text-mode char+attr storage). dos_putchar's direct VGA writes are
    // not gated by this flag and continue to work for text-mode programs.
    crate::vga::KERNEL_OWNS_SCREEN.store(false, core::sync::atomic::Ordering::Relaxed);

    let tid = dos::run_init_program(&buf, path, cmdline_tail, cwd);
    event_loop(tid);
}

const ASSERT_ADDR_HASH: bool = false;

/// Verify that a thread's saved cpu_state still matches the hash recorded on
/// the last switch-out. Print a diff-style dump on mismatch.
/// `tag` is printed in the header ("switch-in" / "reblock" / ...).
fn verify_cpu_hash(t: &thread::Thread, tag: &str) {
    let k = &t.kernel;
    if k.cpu_hash == 0 { return; }
    let actual = thread::hash_regs(&k.cpu_state);
    if actual == k.cpu_hash { return; }
    crate::println!(
        "\x1b[91mCPU STATE CORRUPTION [{}] tid={} expected={:#018x} actual={:#018x}\x1b[0m",
        tag, k.tid, k.cpu_hash, actual,
    );
    let r = &k.cpu_state;
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
fn event_loop(first_tid: usize) {
    use crate::arch::REGS;

    crate::dbg_println!("event_loop entered, tid={}", first_tid);
    let mut tid = first_tid;

    // Page-allocator instrumentation: every MEM_DUMP_PERIOD iterations,
    // log free physical pages and the running low-water mark. Watch the
    // line for monotonic decrease to find leaks. Print to debug serial
    // only — does not clobber user VGA.
    const MEM_DUMP_PERIOD: u64 = 1000;
    let mut event_counter: u64 = 0;
    let mut min_free: usize = crate::arch::free_page_count();
    let mut last_free: usize = min_free;
    // crate::dbg_println!("[mem] start free={}", min_free);

    // User/kernel cycle accounting. We bracket `do_arch_execute()` with
    // rdtsc; every iteration adds a chunk to USER_CYCLES and a chunk to
    // KERNEL_CYCLES. The split tells you whether app code is the
    // bottleneck or our trap/event handling is.
    let mut user_cycles: u64 = 0;
    let mut kernel_cycles: u64 = 0;
    let mut last_kernel_entry = crate::arch::rdtsc();
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
    // Cycle time spent in each phase, accumulated over a profile period:
    //   - phase1_cycles: arch::drain + queue_irq + raise_pending in Phase 1.
    //   - dispatch_cycles: handle_event after the user trap.
    //   - max_dispatch: largest single handle_event call this period.
    let mut phase1_cycles: u64 = 0;
    let mut dispatch_cycles: u64 = 0;
    let mut max_dispatch: u64 = 0;
    // Per-INT-vector counts so when softint=N is high we can see whether
    // it's INT 21 (DOS), INT 67 (EMS), INT 31 (DPMI), etc.
    let mut ev_softint_hist: [u32; 256] = [0; 256];
    let mut ev_in_hist: [u32; 16] = [0; 16];   // bucketed by port high-nibble
    let mut ev_out_hist: [u32; 16] = [0; 16];

    // REGS already set up by startup, page tables correct from boot
    loop {
        event_counter = event_counter.wrapping_add(1);
        if event_counter % MEM_DUMP_PERIOD == 0 {
            let free = crate::arch::free_page_count();
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
                    let ticks = crate::arch::take_pending_ticks();
                    for _ in 0..ticks {
                        crate::kernel::dos::queue_irq(dos, crate::arch::Irq::Tick);
                    }
                    let dp = dos as *mut thread::DosState;
                    crate::arch::drain(|evt| {
                        if matches!(evt, crate::arch::Irq::Key(sc) if sc == F11_PRESS) {
                            thread::request_switch();
                        } else if matches!(evt, crate::arch::Irq::Key(sc) if sc == F12_PRESS) {
                            dump_interrupted_thread(regs, Some(unsafe { &*dp }));
                        } else if is_blocked {
                            if let crate::arch::Irq::Key(sc) = evt {
                                if crate::kernel::keyboard::update_key_state(sc) {
                                    let c = crate::kernel::keyboard::scancode_to_ascii(sc);
                                    if c != 0 {
                                        crate::vga::vga().putchar(c);
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
                    crate::arch::drain(|evt| {
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
        let ts_before_user = crate::arch::rdtsc();
        kernel_cycles = kernel_cycles.wrapping_add(ts_before_user.wrapping_sub(last_kernel_entry));
        let kevent = do_arch_execute();
        let ts_after_user = crate::arch::rdtsc();
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
            crate::dbg_println!("[prof] user={}% kernel={}% irq={} softint={} hlt={} in={} out={} ins={} outs={} pf={} exc={} fault={} syscall={}",
                user_pct, kern_pct,
                ev_irq, ev_softint, ev_hlt, ev_in, ev_out, ev_ins, ev_outs,
                ev_pf, ev_exc, ev_fault, ev_syscall);
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
    let mut swap_regs = new.kernel.cpu_state;
    let mut swap_root = new.kernel.root;
    let mut swap_fx = new.kernel.fx_state;
    if ASSERT_ADDR_HASH {
        let mut hash = new.kernel.addr_hash;
        arch_switch_to(&mut swap_regs, &mut swap_root, &mut hash, &mut swap_fx);
        old.kernel.addr_hash = hash;
    } else {
        arch_switch_to(&mut swap_regs, &mut swap_root, core::ptr::null_mut(), &mut swap_fx);
    }
    old.kernel.cpu_state = swap_regs;
    old.kernel.root = swap_root;
    old.kernel.fx_state = swap_fx;
    old.kernel.cpu_hash = thread::hash_regs(&old.kernel.cpu_state);
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
    // overwrite the parent state that the first swap parks in child.cpu_state.
    let parent_regs = *regs;

    arch_switch_to(&mut child.kernel.cpu_state, &mut child.kernel.root, core::ptr::null_mut(), core::ptr::null_mut());

    // ELF needs user pages freed before loading; DOS handles its own address space
    if matches!(format, exec::BinaryFormat::Elf) {
        crate::dbg_println!("  fork done, loading ELF...");
        arch_free_user_pages();
    }

    let prog_arg = alloc::vec::Vec::from(path);
    let args = alloc::vec![prog_arg];
    let env_slice = parent_env_snapshot.as_deref();
    let parent_cwd_slice = &parent_cwd_buf[..parent_cwd_len];
    if let Err(_) = exec::init_thread(child_tid, &buf, path, &args, cmdtail, env_slice, parent_cwd_slice) {
        let child = thread::get_thread(child_tid).unwrap();
        arch_switch_to(&mut child.kernel.cpu_state, &mut child.kernel.root, core::ptr::null_mut(), core::ptr::null_mut());
        thread::exit_thread(child_tid, 1);
        on_error(regs, 11);
        return None;
    }

    let child = thread::get_thread(child_tid).unwrap();
    // Swap back to parent's address space. Save child's cpu_state (set by
    // init_thread) and restore after — the swap would overwrite it.
    let saved_cpu = child.kernel.cpu_state;
    arch_switch_to(&mut child.kernel.cpu_state, &mut child.kernel.root, core::ptr::null_mut(), core::ptr::null_mut());
    child.kernel.cpu_state = saved_cpu;
    // Restore parent's user regs into REGS (the swap left stale data there).
    *regs = parent_regs;

    match &mut child.personality {
        thread::Personality::Linux(lin) => {
            // Inherit cwd from parent. (DOS path seeds DfsState inside
            // init_process_thread_vm86; Linux child stores cwd in LinuxState.)
            lin.cwd[..parent_cwd_len].copy_from_slice(parent_cwd_slice);
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
/// stuck IRQ delivery (e.g. vpic.isr never cleared by a missed EOI).
pub fn arch_dump_exception(dos: &thread::DosState, regs: &crate::Regs) {
    dump_interrupted_thread(regs, Some(dos));
}

fn dump_interrupted_thread(regs: &crate::Regs, dos: Option<&thread::DosState>) {
    let vm86 = regs.flags32() & (1 << 17) != 0;
    if vm86 {
        let vif = regs.flags32() & (1 << 9) != 0;
        let lin = (regs.cs32() << 4) + regs.ip32();
        let b = unsafe { core::slice::from_raw_parts(lin as *const u8, 8) };
        let ticks = unsafe { *(0x46Cu32 as *const u32) };
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
        unsafe {
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
        // Dump VGA text buffer (80x25, char+attr interleaved at 0xB8000)
        let vga = unsafe { core::slice::from_raw_parts(0xB8000 as *const u8, 4000) };
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
/// so hangs that look like "timer stopped" almost always show up as a stuck
/// vpic.isr bit (any bit blocks all deliveries in raise_pending).
fn dump_virtual_hw(dos: &thread::DosState) {
    let vpic = &dos.pc.vpic;
    let (q, n) = vpic.debug_queue();
    let mut pending = [0u8; 32];
    let mut plen = 0;
    for i in 0..n.min(8) {
        let hi = q[i] >> 4;
        let lo = q[i] & 0xF;
        pending[plen] = if hi < 10 { b'0' + hi } else { b'A' + hi - 10 }; plen += 1;
        pending[plen] = if lo < 10 { b'0' + lo } else { b'A' + lo - 10 }; plen += 1;
        if i + 1 < n { pending[plen] = b','; plen += 1; }
    }
    let pending_str = core::str::from_utf8(&pending[..plen]).unwrap_or("?");
    crate::dbg_println!("[DBG] vpic isr={:#04x} imr={:#04x} pending=[{}] ({}),",
        vpic.isr, vpic.imr, pending_str, n);

    let (en, mode, reload, now, next) = dos.pc.vpit.debug_state();
    let delta = (next as i64).wrapping_sub(now as i64);
    crate::dbg_println!("[DBG] vpit ch0 en={} mode={} reload={} now={} next={} (next-now={})",
        en, mode, reload, now, next, delta);
}

/// Resume user code via arch `EXECUTE` (INT 0x80) and return the next
/// kernel-visible event. The arch→kernel boundary is `(eax, edx)` =
/// `(event, extra)`; this function decodes it into `KernelEvent` right away
/// so the event loop never sees raw tag numbers.
#[inline(never)]
fn do_arch_execute() -> crate::arch::monitor::KernelEvent {
    let event: u32;
    let extra: u32;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("eax") crate::arch::arch_call::EXECUTE as u32 => event,
            out("edx") extra,
            out("ecx") _,
            out("ebx") _,
            out("edi") _,
        );
    }
    crate::arch::monitor::KernelEvent::decode(event, extra)
}

/// Switch threads: swap live state with pointed-to state.
/// On entry: ptrs hold incoming state. On exit: ptrs hold saved outgoing state.
/// hash_ptr: null = no hashing. Non-null: on entry = expected hash (0=don't check),
/// on exit = old address space hash.
pub fn arch_switch_to(
    regs: &mut crate::Regs, root: &mut crate::RootPageTable,
    hash_ptr: *mut u64,
    fx_ptr: *mut crate::arch::FxState,
) {
    // LLVM reserves ESI/EDI for its own use in inline asm on x86, so we
    // can't name them directly. Stash fx_ptr in ESI around the int 0x80.
    unsafe {
        core::arch::asm!(
            "xchg esi, {fx}",
            "int 0x80",
            "xchg esi, {fx}",
            fx = inout(reg) fx_ptr as u32 => _,
            in("eax") crate::arch::arch_call::SWITCH_TO as u32,
            in("edx") regs as *mut _ as u32,
            in("ecx") root as *mut _ as u32,
            in("ebx") hash_ptr as u32,
        );
    }
}

/// COW fork the current address space. Fills child root.
/// Caller must save parent root after (fork modifies entries for COW).
pub fn arch_user_fork(child_root: &mut crate::RootPageTable) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::FORK as u32,
            in("edx") child_root as *mut _ as u32,
        );
    }
}

pub fn arch_user_clean() {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::CLEAN as u32,
        );
    }
}



/// Set page permissions for a range. flags: bit 0 = writable, bit 1 = executable.
pub fn arch_set_page_flags(start_vpage: usize, count: usize, writable: bool, executable: bool) {
    let flags = (writable as u32) | ((executable as u32) << 1);
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::SET_PAGE_FLAGS as u32,
            in("edx") start_vpage as u32,
            in("ecx") count as u32,
            in("ebx") flags,
        );
    }
}

/// Map first 1MB user-accessible for VM86.
pub fn arch_map_low_mem() {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::MAP_LOW_MEM as u32,
        );
    }
}

/// Copy page table entries from src to dst.
pub fn arch_copy_page_entries(src_vpage: usize, dst_vpage: usize, count: usize) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::COPY_PAGE_ENTRIES as u32,
            in("edx") src_vpage as u32,
            in("ecx") dst_vpage as u32,
            in("ebx") count as u32,
        );
    }
}

pub fn arch_swap_page_entries(a_vpage: usize, b_vpage: usize, count: usize) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::SWAP_PAGE_ENTRIES as u32,
            in("edx") a_vpage as u32,
            in("ecx") b_vpage as u32,
            in("ebx") count as u32,
        );
    }
}

/// Clear page entries to absent (enables demand paging on next access).
pub fn arch_unmap_range(base_page: usize, count: usize) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::UNMAP_RANGE as u32,
            in("edx") base_page as u32,
            in("ecx") count as u32,
        );
    }
}

/// Free physical pages and restore identity-mapped read-only entries.
pub fn arch_free_range(base_page: usize, count: usize) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::FREE_RANGE as u32,
            in("edx") base_page as u32,
            in("ecx") count as u32,
        );
    }
}




/// Load LDT: write base+limit into GDT[12] and execute LLDT.
pub fn arch_load_ldt(base: u32, limit: u32) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::LOAD_LDT as u32,
            in("edx") base,
            in("ecx") limit,
        );
    }
}

/// Map a range of physical pages into user virtual space.
pub fn arch_map_phys_range(vpage_start: usize, num_pages: usize, ppage_start: u64, flags: u64) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::MAP_PHYS_RANGE as u32,
            in("edx") vpage_start as u32,
            in("ecx") num_pages as u32,
            in("ebx") ppage_start as u32,
            in("edi") flags as u32,
        );
    }
}

/// Set a per-thread TLS GDT entry. Returns the GDT index or -1 on error.
pub fn arch_set_tls_entry(index: i32, base: u32, limit: u32, limit_in_pages: bool) -> i32 {
    let result: u32;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("eax") crate::arch::arch_call::SET_TLS_ENTRY as u32 => result,
            in("edx") index as u32,
            in("ecx") base,
            in("ebx") limit,
            in("edi") limit_in_pages as u32,
        );
    }
    result as i32
}

/// Free user pages in current address space (arch CLEAN call).
pub fn arch_free_user_pages() {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::CLEAN as u32,
        );
    }
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

fn fw_cfg_present() -> bool {
    fw_cfg_select(FW_CFG_SIG);
    let mut sig = [0u8; 4];
    fw_cfg_read_bytes(&mut sig);
    &sig == b"QEMU"
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
