//! Kernel startup - filesystem mount and DN.COM loader

extern crate alloc;

extern crate ext4_view;

use alloc::vec;
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

    crate::kernel::stacktrace::init_from_tar();

    // Allocate console stdin pipe (keyboard → Linux stdin)
    let console_pipe = crate::kernel::kpipe::alloc().expect("Failed to allocate console pipe");
    crate::kernel::thread::set_console_pipe(console_pipe);

    let dn_path: &[u8] = if has_ext4 { b"tar/DN/DN.COM" } else { b"DN/DN.COM" };
    loop {
        println!("Starting DN...");
        run_dos_program(dn_path, b"");
    }
}

/// Load a DOS program (.COM or MZ .EXE) into a fresh VM86 thread and run the
/// event loop until it exits. `cmdline_tail` is written to PSP:0080h (without
/// the length byte or terminator; those are added automatically).
fn run_dos_program(path: &[u8], cmdline_tail: &[u8]) {
    use crate::kernel::dos;

    // Read binary via handle-based VFS access (no per-thread fd needed).
    let handle = vfs::open_to_handle(path);
    if handle < 0 { panic!("{} not found", core::str::from_utf8(path).unwrap_or("?")); }
    let size = vfs::file_size_by_handle(handle) as usize;
    let mut buf = vec![0u8; size];
    vfs::read_by_handle(handle, &mut buf);
    vfs::close_vfs_handle(handle);

    let t = thread::create_thread(None, crate::RootPageTable::empty(), true)
        .expect("Failed to create DOS thread");
    let tid = t.tid as usize;

    // Set up VM86 address space in the current (boot) page tables.
    // The thread's root stays empty — event_loop captures it on first switch-away.
    arch_map_low_mem();
    dos::setup_ivt();
    let is_exe = dos::is_mz_exe(&buf);
    let (cs, ip, ss, sp, end_seg) = if is_exe {
        dos::load_exe(&buf, path).expect("load_exe failed")
    } else {
        dos::load_com(&buf, path)
    };

    thread::init_process_thread_vm86(t, dos::COM_SEGMENT, cs, ip, ss, sp);
    let dos_state = t.dos_mut();
    dos_state.heap_seg = end_seg;
    dos_state.dta = (dos::COM_SEGMENT as u32) * 16 + 0x80;
    dos_state.cwd_len = 0;

    // Write command tail to PSP at 0x80: [len][bytes][0x0D].
    let psp_base = (dos::COM_SEGMENT as u32) << 4;
    let tail_len = cmdline_tail.len().min(126);
    unsafe {
        let psp = psp_base as *mut u8;
        *psp.add(0x80) = tail_len as u8;
        core::ptr::copy_nonoverlapping(cmdline_tail.as_ptr(), psp.add(0x81), tail_len);
        *psp.add(0x81 + tail_len) = 0x0D;
    }

    // Seed BDA cursor from kernel VGA cursor (one-time, before first DOS process).
    let (col, row) = crate::vga::vga().cursor_pos();
    unsafe {
        core::ptr::write_volatile(0x450 as *mut u8, col as u8);
        core::ptr::write_volatile(0x451 as *mut u8, row as u8);
    }
    unsafe { *(&raw mut crate::arch::REGS) = t.cpu_state; }
    event_loop(tid);
}

const ASSERT_ADDR_HASH: bool = true;

/// Verify that a thread's saved cpu_state still matches the hash recorded on
/// the last switch-out. Print a diff-style dump on mismatch.
/// `tag` is printed in the header ("switch-in" / "reblock" / ...).
fn verify_cpu_hash(t: &thread::Thread, tag: &str) {
    if t.cpu_hash == 0 { return; } // not yet tracked
    let actual = thread::hash_regs(&t.cpu_state);
    if actual == t.cpu_hash { return; }
    crate::println!(
        "\x1b[91mCPU STATE CORRUPTION [{}] tid={} expected={:#018x} actual={:#018x}\x1b[0m",
        tag, t.tid, t.cpu_hash, actual,
    );
    let r = &t.cpu_state;
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

    // REGS already set up by startup, page tables correct from boot
    loop {
        crate::kernel::stacktrace::set_debug_tid(tid);
        // Pre-execute: drain hardware events into OS personality
        {
            let thread = thread::get_thread(tid).expect("Invalid thread in event loop");
            let regs = unsafe { &mut *(&raw mut REGS) };
            match &mut thread.mode {
                thread::ThreadMode::Dos(dos) => {
                    let is_blocked = thread.state == thread::ThreadState::Blocked;
                    // Skip during DPMI real-mode simulation — injecting IRQs would corrupt the frame.
                    let dpmi_rm_call = dos.dpmi.as_ref().map_or(false, |d| d.rm_save.is_some());
                    if !dpmi_rm_call {
                        if regs.mode() == crate::UserMode::VM86 {
                            qemu_vga_workaround(regs);
                        }
                        let ticks = crate::arch::take_pending_ticks();
                        for _ in 0..ticks {
                            crate::kernel::machine::queue_irq(&mut dos.pc, crate::arch::Irq::Tick);
                        }
                        let dp = dos as *mut thread::DosState;
                        crate::arch::drain(|evt| {
                            if matches!(evt, crate::arch::Irq::Key(sc) if sc == F11_PRESS) {
                                thread::request_switch();
                            } else if matches!(evt, crate::arch::Irq::Key(sc) if sc == F12_PRESS) {
                                dump_interrupted_thread(regs, Some(unsafe { &*dp }));
                            } else if is_blocked {
                                // DOS parent is blocked waiting for child — route keys
                                // to console pipe so Linux children can read stdin
                                if let crate::arch::Irq::Key(sc) = evt {
                                    // Reuse Linux TTY path for echo + pipe write
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
                                    crate::kernel::machine::queue_irq(unsafe { &mut (*dp).pc }, evt);
                                }
                            }
                        });
                        if !is_blocked {
                            crate::kernel::machine::raise_pending(unsafe { &mut *dp }, regs);
                        }
                    }
                }
                thread::ThreadMode::Linux(linux) => {
                    let lp = linux as *mut thread::LinuxState;
                    crate::arch::drain(|evt| {
                        if let crate::arch::Irq::Key(sc) = evt {
                            if sc == F11_PRESS {
                                thread::request_switch();
                            } else if sc == F12_PRESS {
                                dump_interrupted_thread(regs, None);
                            } else {
                                unsafe { (*lp).process_key(sc); }
                            }
                        }
                    });
                }
            }
        }

        // Always check if blocked stdin readers can be woken (keyboard data may
        // have arrived during any thread's drain, including DOS threads).
        thread::wake_blocked_readers();

        // Complete pending stdin read if this thread was woken for it
        {
            let regs = unsafe { &mut *(&raw mut REGS) };
            match thread::complete_pending_read(tid, regs) {
                Some(true) => continue,  // Read done — resume userspace
                Some(false) => {
                    // Re-blocked (data gone) — schedule another thread
                    if let Some(next) = thread::schedule(tid) {
                        if next == 0 { return; }
                        if next != tid {
                            let (old, new) = thread::get_two_threads(tid, next);
                            verify_cpu_hash(new, "reblock switch-in");
                            arch_switch_to(&mut new.cpu_state, &mut new.root, core::ptr::null_mut());
                            old.cpu_state = unsafe { *(&raw const REGS) };
                            old.cpu_hash = thread::hash_regs(&old.cpu_state);
                            tid = next;
                        }
                    }
                    continue;
                }
                None => {}  // No pending read — normal execution
            }
        }

        let (event, extra) = do_arch_execute();

        let thread = thread::get_thread(tid).expect("Invalid thread in event loop");
        let regs = unsafe { &mut *(&raw mut REGS) };

        // signal_thread handles its own cleanup; wrap into KernelAction
        // TODO: 64-bit child exit corrupts 32-bit parent's FS/TLS — parent
        //       segfaults on TLS access (FS BASE=0) after resuming.
        if event == 14 {
            let rip = regs.frame.rip;
            crate::println!("  fault rip={:#x} addr={:#x} err={:#x}", rip, extra, regs.err_code);
            if let Some(next) = thread::signal_thread(thread, tid, extra as usize) {
                tid = next;
                if tid == 0 { return; }
                continue;
            } else {
                continue;
            }
        }

        let action = match event {
            32..=47 => thread::KernelAction::Done,

            _ => match &mut thread.mode {
                thread::ThreadMode::Dos(dos) => {
                    if regs.mode() == crate::UserMode::VM86 {
                        match event {
                            13 => crate::kernel::machine::vm86_monitor(dos, regs),
                            _ => {
                                let lin = (regs.code_seg() as u32) * 16 + regs.ip32() as u16 as u32;
                                let bytes = unsafe { core::slice::from_raw_parts(lin as *const u8, 8) };
                                crate::dbg_println!("VM86: unhandled event {} at {:04x}:{:04x} (lin={:#x}) bytes=[{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}] tid={}",
                                    event, regs.code_seg(), regs.ip32() as u16, lin,
                                    bytes[0], bytes[1], bytes[2], bytes[3],
                                    bytes[4], bytes[5], bytes[6], bytes[7], tid);
                                panic!("VM86: unhandled event {} at {:04x}:{:04x} (lin={:#x}) bytes=[{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}]",
                                    event, regs.code_seg(), regs.ip32() as u16, lin,
                                    bytes[0], bytes[1], bytes[2], bytes[3],
                                    bytes[4], bytes[5], bytes[6], bytes[7]);
                            }
                        }
                    } else if dos.dpmi.is_some() {
                        match event {
                            13 => crate::kernel::dpmi::dpmi_monitor(dos, regs),
                            0x31 => crate::kernel::dpmi::dpmi_int31(dos, regs),
                            0..=31 => crate::kernel::dpmi::dispatch_dpmi_exception(dos, regs, event),
                            0x30..=0xFF => crate::kernel::dpmi::dpmi_soft_int(dos, regs, event as u8),
                            _ => {
                                crate::println!("DPMI: unexpected event {} at CS:EIP={:#06x}:{:#x}",
                                    event, regs.frame.cs as u16, regs.ip32());
                                thread::KernelAction::Exit(-11)
                            }
                        }
                    } else {
                        thread::KernelAction::Done
                    }
                }
                thread::ThreadMode::Linux(_linux) => {
                    // Syscalls dispatch handles retval internally via regs.rax.
                    // switch_to is the only scheduling decision.
                    // TODO: migrate syscalls to KernelAction natively
                    match event {
                        0x80 => crate::kernel::syscalls::dispatch_action(tid, regs),
                        _ => thread::KernelAction::Done,
                    }
                }
            },
        };


        let new_tid: Option<usize> = match action {
            thread::KernelAction::Done => None,
            thread::KernelAction::Yield => thread::yield_thread(tid, regs),
            thread::KernelAction::Exit(code) => Some(thread::exit_thread(tid, code)),
            thread::KernelAction::Switch(next) => Some(next),
            thread::KernelAction::ForkExec { path, path_len, on_error, on_success } => {
                handle_fork_exec(tid, regs, &path[..path_len], on_error, on_success)
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

        // F11 hotkey: force round-robin thread cycle (only when action didn't already switch).
        // F11 is Ctrl-Z: the parent's waitpid returns early. If the current thread's
        // parent is blocked-in-waitpid, cancel the wait — unblock parent so it becomes
        // an independent peer. Child keeps running, VGA becomes fully independent.
        let new_tid = if new_tid.is_none() && thread::take_switch_request() {
            thread::cancel_parent_wait(tid);
            thread::cycle_next(tid)
        } else {
            new_tid
        };

        if let Some(new_tid) = new_tid {
            if new_tid == 0 { return; } // no threads left — respawn DN
            if new_tid != tid {
                let (old, new) = thread::get_two_threads(tid, new_tid);
                // Save/restore VGA state when switching between DOS threads.
                // Zombies already snapshotted in exit_thread (before arch_user_clean
                // unmaps 0xA0000); re-reading here would capture unmapped garbage.
                let old_dos = old.is_dos() && old.state != thread::ThreadState::Zombie;
                let new_dos = new.is_dos();
                if old_dos {
                    let dos = old.dos_mut();
                    dos.pc.vga.save_from_hardware();
                }
                verify_cpu_hash(new, "switch-in");
                let mut swap_regs = new.cpu_state;
                let mut swap_root = new.root;
                if ASSERT_ADDR_HASH {
                    let mut hash = new.addr_hash;
                    arch_switch_to(&mut swap_regs, &mut swap_root, &mut hash);
                    old.addr_hash = hash;
                } else {
                    arch_switch_to(&mut swap_regs, &mut swap_root, core::ptr::null_mut());
                }
                old.cpu_state = swap_regs;
                old.root = swap_root;
                old.cpu_hash = thread::hash_regs(&old.cpu_state);
                if new_dos {
                    let dos = new.dos_mut();
                    dos.pc.vga.restore_to_hardware();
                }
                tid = new_tid;
                // Reload LDT if switching to a DPMI thread, TLS if switching to a Linux thread
                let new_thread = thread::get_thread(tid).expect("Invalid thread");
                match &new_thread.mode {
                    thread::ThreadMode::Dos(dos) => {
                        if let Some(ref dpmi) = dos.dpmi {
                            let ldt_ptr = dpmi.ldt.as_ptr() as u32;
                            let ldt_limit = (256 * 8 - 1) as u32;
                            arch_load_ldt(ldt_ptr, ldt_limit);
                        }
                    }
                    thread::ThreadMode::Linux(linux) => {
                        if linux.tls_entry >= 0 {
                            arch_set_tls_entry(
                                linux.tls_entry, linux.tls_base,
                                linux.tls_limit, linux.tls_limit_in_pages,
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Fork the current process and exec a binary (DOS .COM/.EXE or ELF) in the child.
/// Blocks parent, returns child tid on success, None on error (caller stays on parent).
fn handle_fork_exec(
    parent_tid: usize,
    regs: &mut crate::Regs,
    path: &[u8],
    on_error: fn(&mut crate::Regs, i32),
    on_success: fn(&mut crate::Regs, i32),
) -> Option<usize> {
    use crate::kernel::dos;

    // Open file via handle-based VFS (no per-thread fd slot needed)
    let parent = thread::get_thread(parent_tid).expect("fork_exec: invalid parent");
    let (parent_cwd, parent_cwd_len) = match &parent.mode {
        thread::ThreadMode::Dos(d) => (d.cwd, d.cwd_len),
        thread::ThreadMode::Linux(l) => (l.cwd, l.cwd_len),
    };

    let handle = vfs::open_to_handle(path);
    if handle < 0 { on_error(regs, 2); return None; }
    let size = vfs::seek_by_handle(handle, 0, 2);
    if size <= 0 { vfs::close_vfs_handle(handle); on_error(regs, 2); return None; }
    vfs::seek_by_handle(handle, 0, 0);
    let mut buf = alloc::vec![0u8; size as usize];
    vfs::read_by_handle(handle, &mut buf);
    vfs::close_vfs_handle(handle);

    let is_elf = buf.len() >= 4 && buf[0..4] == [0x7F, b'E', b'L', b'F'];
    let is_exe = !is_elf && dos::is_mz_exe(&buf);
    crate::dbg_println!("handle_fork_exec: {:?} size={} elf={} exe={}", core::str::from_utf8(path), size, is_elf, is_exe);
    // Anything that isn't ELF or MZ is treated as a flat .COM image.
    // COMMAND.COM is responsible for never sending us non-executables (.BAT, etc).

    // COW-fork parent address space for child
    let mut child_root = crate::RootPageTable::empty();
    arch_user_fork(&mut child_root);

    let child = match thread::create_thread(Some(parent_tid), child_root, true) {
        Some(t) => t,
        None => { on_error(regs, 8); return None; }
    };
    let child_tid = child.tid as usize;

    // Switch into child address space to load binary
    arch_switch_to(&mut child.cpu_state, &mut child.root, core::ptr::null_mut());

    if is_elf {
        crate::dbg_println!("  fork done, loading ELF...");
        arch_free_user_pages();
        arch_flush_tlb();
        let loaded = match crate::kernel::elf::load_elf(&buf) {
            Ok(e) => e,
            Err(_) => {
                arch_switch_to(&mut child.cpu_state, &mut child.root, core::ptr::null_mut());
                thread::exit_thread(child_tid, 1);
                on_error(regs, 11);
                return None;
            }
        };
        crate::dbg_println!("  ELF loaded: entry={:#x} max_vaddr={:#x}", loaded.entry, loaded.max_vaddr);
        let want_64 = loaded.class == crate::kernel::elf::ElfClass::Elf64;
        let prog_arg = alloc::vec::Vec::from(path);
        let args = alloc::vec![prog_arg];
        let sp = crate::kernel::syscalls::setup_user_stack(&args, want_64);
        crate::dbg_println!("  stack={:#x} want_64={}", sp, want_64);
        let symbols = crate::kernel::stacktrace::SymbolData::new(buf.into_boxed_slice());

        arch_switch_to(&mut child.cpu_state, &mut child.root, core::ptr::null_mut());

        if want_64 {
            thread::init_process_thread_64(child, loaded.entry, sp as u64);
        } else {
            thread::init_process_thread(child, loaded.entry as u32, sp as u32);
        }
        match &mut child.mode {
            thread::ThreadMode::Linux(l) => {
                l.symbols = symbols;
                l.heap_base = loaded.max_vaddr;
                l.heap_end = loaded.max_vaddr;
                l.mmap_cursor = crate::kernel::elf::USER_STACK_TOP - 0x0100_0000;
                // Set up console fds for Linux process
                let cpipe = thread::console_pipe();
                l.fds[0] = thread::FdKind::PipeRead(cpipe);
                l.fds[1] = thread::FdKind::ConsoleOut;
                l.fds[2] = thread::FdKind::ConsoleOut;
                crate::kernel::kpipe::add_reader(cpipe);
            }
            thread::ThreadMode::Dos(d) => d.symbols = symbols,
        }
    } else {
        arch_user_clean();
        arch_map_low_mem();
        dos::setup_ivt();

        let (cs, ip, ss, sp, end_seg) = if is_exe {
            match dos::load_exe(&buf, path) {
                Some(t) => t,
                None => {
                    arch_switch_to(&mut child.cpu_state, &mut child.root, core::ptr::null_mut());
                    thread::exit_thread(child_tid, 1);
                    on_error(regs, 11);
                    return None;
                }
            }
        } else {
            dos::load_com(&buf, path)
        };

        arch_switch_to(&mut child.cpu_state, &mut child.root, core::ptr::null_mut());

        thread::init_process_thread_vm86(child, dos::COM_SEGMENT, cs, ip, ss, sp);
        let dos_state = child.dos_mut();
        dos_state.heap_seg = end_seg;
        dos_state.dta = (dos::COM_SEGMENT as u32) * 16 + 0x80;
        // Snapshot parent's current VGA hardware state into child so it
        // starts with the parent's screen (invariant: suspended thread's
        // VGA state is materialized in memory).
        dos_state.pc.vga.save_from_hardware();
        // Seed child's BDA cursor from CRTC hardware cursor so DOS/BIOS
        // output starts at the correct position (DN sets CRTC cursor via
        // INT 10h AH=02h but writes chars directly to B8000).
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

    // Propagate cwd from parent to child
    match &mut child.mode {
        thread::ThreadMode::Dos(d) => { d.cwd = parent_cwd; d.cwd_len = parent_cwd_len; }
        thread::ThreadMode::Linux(l) => { l.cwd = parent_cwd; l.cwd_len = parent_cwd_len; }
    }

    // Block parent, switch to child
    crate::dbg_println!("  child tid={}, blocking parent tid={}", child_tid, parent_tid);
    thread::block_thread(parent_tid);
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
        crate::dbg_println!("[DBG] PM EIP={:#010x} EFLAGS={:#010x} IF={}",
            regs.ip32(), fl, (fl >> 9) & 1);
        if let Some(d) = dos { dump_virtual_hw(d); }
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

/// QEMU VGA bug workaround: real VGA hardware forces Odd/Even read mode
/// (GC5 bit 4) in text modes. QEMU doesn't, so re-set it on each trap.
fn qemu_vga_workaround(regs: &crate::Regs) {
    unsafe {
        if regs.cs32() < 0xC000 {
            let mode = *(0x449 as *const u8);
            if mode <= 3 || mode == 7 {
                let saved_idx = crate::arch::inb(0x3CE);
                crate::arch::outb(0x3CE, 5);
                let gc5 = crate::arch::inb(0x3CF);
                if gc5 & 0x10 == 0 {
                    crate::arch::outb(0x3CF, gc5 | 0x10);
                }
                crate::arch::outb(0x3CE, saved_idx);
            }
        }
    }
}

/// Call arch execute() via INT 0x80.
/// Returns (event_number, extra). Extra = fault address for event 14.
#[inline(never)]
fn do_arch_execute() -> (u32, u32) {
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
    (event, extra)
}

/// Switch threads: swap live state with pointed-to state.
/// On entry: ptrs hold incoming state. On exit: ptrs hold saved outgoing state.
/// hash_ptr: null = no hashing. Non-null: on entry = expected hash (0=don't check),
/// on exit = old address space hash.
pub fn arch_switch_to(
    regs: &mut crate::Regs, root: &mut crate::RootPageTable,
    hash_ptr: *mut u64,
) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
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

/// Free a physical page.
pub fn arch_free_phys_page(phys: u64) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::FREE_PHYS_PAGE as u32,
            in("edx") phys as u32,
        );
    }
}



/// Toggle A20 gate for VM86 mode.
pub fn arch_set_a20(enabled: bool, hma: &mut [u64; crate::kernel::machine::HMA_PAGE_COUNT]) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::SET_A20 as u32,
            in("edx") enabled as u32,
            in("ecx") hma as *mut _ as u32,
        );
    }
}

/// Zero a physical page.
pub fn arch_zero_phys_page(phys: u64) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::ZERO_PHYS_PAGE as u32,
            in("edx") phys as u32,
        );
    }
}

/// Map/unmap an EMS page frame window.
pub fn arch_map_ems_window(base_page: usize, window: usize, phys_pages: Option<&[u64; 4]>) {
    let ptr = match phys_pages {
        Some(p) => p as *const _ as u32,
        None => 0u32,
    };
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::MAP_EMS_WINDOW as u32,
            in("edx") base_page as u32,
            in("ecx") window as u32,
            in("ebx") ptr,
        );
    }
}

/// Enable UMB region (clear page entries for demand paging).
pub fn arch_map_umb(base_page: usize, count: usize) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::MAP_UMB as u32,
            in("edx") base_page as u32,
            in("ecx") count as u32,
        );
    }
}

/// Disable UMB region (restore identity mapping).
pub fn arch_unmap_umb(base_page: usize, count: usize) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::UNMAP_UMB as u32,
            in("edx") base_page as u32,
            in("ecx") count as u32,
        );
    }
}

/// Get the temp-map reserved virtual address (heap must skip this page).
pub fn arch_temp_map_addr() -> usize {
    let addr: u32;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("eax") crate::arch::arch_call::GET_TEMP_MAP_ADDR as u32 => addr,
        );
    }
    addr as usize
}

/// Initialize HMA save area with zero-page entries.
pub fn arch_init_hma(hma: &mut [u64; crate::kernel::machine::HMA_PAGE_COUNT]) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::INIT_HMA as u32,
            in("edx") hma as *mut _ as u32,
        );
    }
}

/// Activate a root page table (switch CR3).
pub fn arch_activate_root(root: &crate::RootPageTable) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::ACTIVATE_ROOT as u32,
            in("edx") root as *const _ as u32,
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

/// Flush TLB.
pub fn arch_flush_tlb() {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch::arch_call::FLUSH_TLB as u32,
        );
    }
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
