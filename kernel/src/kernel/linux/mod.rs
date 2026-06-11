//! Linux personality — i386/x86_64 Linux syscall ABI.
//!
//! Sibling to the `dos` personality: the `dos` module implements the
//! DOS/DPMI personality, this one implements the Linux personality.
//! Linux `LinuxState` lives in `thread.rs` alongside `DosState` (mirroring
//! the DOS layout) and this module owns the syscall dispatch + handlers.
//!
//! INT 0x80, EAX = syscall number (Linux i386 numbering)
//! i386:   EBX=a0, ECX=a1, EDX=a2, ESI=a3, EDI=a4, EBP=a5
//! x86_64: RDI=a0, RSI=a1, RDX=a2, R10=a3, R8=a4, R9=a5
//! Return: EAX/RAX (negative = -errno)

const LINUX_TRACE: bool = false;

macro_rules! linux_trace {
    ($($arg:tt)*) => {
        if LINUX_TRACE {
            $crate::dbg_println!($($arg)*);
        }
    };
}

use arch_abi::GuestBytes;
use arch_abi::Arch; // `machine: &mut TheArch` trait methods (set_tls_entry, user_fork, …)
use crate::kernel::elf;
use crate::kernel::stacktrace::SymbolData;
use crate::kernel::thread;
use crate::kernel::thread::{FdKind, PendingRead, PendingPoll, MAX_FDS};
use crate::kernel::vfs;
use crate::vga;
use crate::Regs;
use crate::arch::Vcpu;
use crate::println;

// =============================================================================
// errno constants (positive values; returned as negative)
// =============================================================================

const ENOENT: i32 = 2;
const ESRCH: i32 = 3;
const ENOEXEC: i32 = 8;
const EBADF: i32 = 9;
const ECHILD: i32 = 10;
const ENOMEM: i32 = 12;
const EFAULT: i32 = 14;
const ENOTTY: i32 = 25;
const EINVAL: i32 = 22;
const ESPIPE: i32 = 29;
const EPIPE: i32 = 32;
const ENOSYS: i32 = 38;

// Shared TTY-style console VGA, owned by the Linux personality (not by any
// individual thread). All Linux threads write to the same screen, so the
// snapshot we save on switch-out belongs at the personality level. Lazily
// allocated on first save (VgaState's planes are a Vec).
static mut LINUX_CONSOLE_VGA: Option<crate::kernel::dos::VgaState> = None;

/// Snapshot the current hardware VGA into the Linux console buffer.
/// No-op on the interpreter backend, which has no VGA hardware (console output
/// goes to stdout, not a saved/restored framebuffer).
pub fn save_console_vga() {
    #[cfg(not(feature = "hosted"))]
    unsafe {
        if !crate::kernel::dos::vga_present() {
            return; // no card (UEFI metal): nothing to snapshot
        }
        let vga = (&raw mut LINUX_CONSOLE_VGA)
            .as_mut()
            .unwrap()
            .get_or_insert_with(crate::kernel::dos::VgaState::new);
        vga.save_from_hardware();
    }
}

/// Restore the Linux console buffer onto the hardware VGA. On first
/// activation (no snapshot yet) we clear the screen rather than inherit
/// the previous personality's framebuffer — keeps F11 into Linux
/// deterministic regardless of what was last drawn.
pub fn restore_console_vga() {
    #[cfg(not(feature = "hosted"))]
    unsafe {
        if !crate::kernel::dos::vga_present() {
            return;
        }
        if let Some(vga) = (&raw const LINUX_CONSOLE_VGA).as_ref().unwrap() {
            vga.restore_to_hardware();
        } else {
            crate::vga::vga().clear();
        }
    }
}

/// Linux-specific thread state
pub struct LinuxState {
    pub heap_base: usize,
    pub heap_end: usize,
    pub mmap_cursor: usize,
    pub tls_entry: i32,            // GDT index for TLS (13-15), -1 = none
    pub tls_base: u32,
    pub tls_limit: u32,
    pub tls_limit_in_pages: bool,
    pub pending_read: Option<PendingRead>,  // Blocked read on any fd kind
    pub pending_poll: Option<PendingPoll>,  // Blocked poll on a pollfd array
    pub wait_status_ptr: usize,            // Deferred wait4 status write
    pub wait_exit_code: i32,
    /// VFS-form cwd (lowercase, forward-slash, no leading/trailing slash).
    /// Linux personality stores cwd here; DOS personality stores it inside
    /// `DosState.dfs` in DOS-form (uppercase, backslash). KernelThread carries
    /// no cwd of its own — see CLAUDE notes on personality-owned state.
    pub cwd: [u8; 64],
    pub cwd_len: usize,
    /// Path this process's image was loaded from — what `/proc/self/exe`
    /// resolves to. Set on each successful exec; preserved across the
    /// in-place ELF execve. Lets self-re-exec'ing binaries (busybox standalone
    /// shell) find themselves without a real /proc or any hardcoded path.
    pub exec_path: [u8; 128],
    pub exec_path_len: usize,
}

impl LinuxState {
    pub fn new() -> Self {
        LinuxState {
            heap_base: 0,
            heap_end: 0,
            mmap_cursor: crate::kernel::elf::USER_STACK_TOP - 0x0100_0000,
            tls_entry: -1,
            tls_base: 0,
            tls_limit: 0,
            tls_limit_in_pages: false,
            pending_read: None,
            pending_poll: None,
            wait_status_ptr: 0,
            wait_exit_code: 0,
            cwd: [0; 64],
            cwd_len: 0,
            exec_path: [0; 128],
            exec_path_len: 0,
        }
    }

    pub fn cwd_str(&self) -> &[u8] { &self.cwd[..self.cwd_len] }

    /// Path the running image was loaded from (`/proc/self/exe` target).
    pub fn exec_path_str(&self) -> &[u8] { &self.exec_path[..self.exec_path_len] }

    /// Record the load path on exec (truncated to the buffer if absurdly long).
    pub fn set_exec_path(&mut self, path: &[u8]) {
        let n = path.len().min(self.exec_path.len());
        self.exec_path[..n].copy_from_slice(&path[..n]);
        self.exec_path_len = n;
    }

    /// Called when a Linux thread loses focus. Snapshots the shared Linux
    /// console framebuffer (TTY-style — all Linux threads share it).
    pub fn suspend(&mut self) {
        save_console_vga();
    }

    /// Called when a Linux thread regains focus. Repaints the shared
    /// console from the suspend snapshot. CPU-binding side effects (TLS,
    /// deferred wait_status writeout) live in `on_resume` and happen on
    /// every swap-in.
    pub fn materialize(&mut self) {
        restore_console_vga();
    }

    /// Called on every swap-in (whether or not we're refocusing): rebind
    /// per-thread CPU state and finalize a deferred wait4 status write.
    pub fn on_resume(&mut self, machine: &mut crate::TheArch) {
        if self.tls_entry >= 0 {
            machine.set_tls_entry(
                self.tls_entry, self.tls_base,
                self.tls_limit, self.tls_limit_in_pages,
            );
        }
        if self.wait_status_ptr != 0 {
            unsafe {
                *(self.wait_status_ptr as *mut i32) =
                    (self.wait_exit_code & 0xFF) << 8;
            }
            self.wait_status_ptr = 0;
        }
    }

    /// Process a raw PS/2 scancode — the Linux TTY line discipline.
    /// Updates key state, converts to ASCII, writes to stdin pipe.
    /// Echo is the userspace shell's responsibility (busybox-ash handles it
    /// itself based on its termios state); echoing in the kernel as well
    /// would produce doubled characters on screen.
    pub fn process_key(&self, fds: &[FdKind; MAX_FDS], scancode: u8) {
        if !crate::kernel::keyboard::update_key_state(scancode) { return; }
        let c = crate::kernel::keyboard::scancode_to_ascii(scancode);
        if c == 0 { return; }
        if let FdKind::PipeRead(idx) = fds[0] {
            crate::kernel::kpipe::write(idx, &[c]);
        }
    }
}

// =============================================================================
// Extracted syscall arguments (mode-independent)
// =============================================================================

struct Args {
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
}

/// Extract args from regs based on caller mode.
fn extract_args(regs: &Regs) -> Args {
    let is_64 = regs.mode() == crate::UserMode::Mode64;
    if is_64 {
        Args { a0: regs.rdi, a1: regs.rsi, a2: regs.rdx, a3: regs.r10, a4: regs.r8, a5: regs.r9 }
    } else {
        Args { a0: regs.rbx, a1: regs.rcx, a2: regs.rdx, a3: regs.rsi, a4: regs.rdi, a5: regs.rbp }
    }
}

// =============================================================================
// Dispatch
// =============================================================================

/// Syscall result: return value + optional switch target
pub struct SyscallResult {
    pub retval: i64,
    pub switch_to: Option<usize>,
}

impl SyscallResult {
    fn val(v: i32) -> Self { Self { retval: v as i64, switch_to: None } }
    fn val64(v: i64) -> Self { Self { retval: v, switch_to: None } }
}

/// Single entry point the event loop calls for the Linux personality.
/// Handles syscalls (INT 0x80) and treats other CPU events as fatal.
/// `PageFault` is excluded — the loop handles it inline.
pub fn handle_event(
    machine: &mut crate::TheArch,
    kt: &mut thread::KernelThread,
    linux: &mut LinuxState,
    regs: &mut Regs,
    kevent: crate::arch::monitor::KernelEvent,
) -> thread::KernelAction {
    use crate::arch::monitor::KernelEvent as KE;
    match kevent {
        KE::Irq => thread::KernelAction::Done,
        // 32-bit user uses INT 0x80 (lands as SoftInt); 64-bit user uses the
        // SYSCALL instruction (lands as Syscall). Both reach the same dispatch.
        KE::SoftInt(0x80) | KE::Syscall => dispatch_action(machine, kt, linux, regs),
        KE::PageFault { .. } => unreachable!("PageFault handled in event loop"),
        _ => {
            crate::dbg_println!("[LINUX] fatal {:?} at EIP={:#x} tid={}", kevent, regs.ip32(), kt.tid);
            thread::KernelAction::Exit(-11)
        }
    }
}

/// Dispatch returning KernelAction.
pub fn dispatch_action(machine: &mut crate::TheArch, kt: &mut thread::KernelThread, linux: &mut LinuxState, regs: &mut Regs) -> thread::KernelAction {
    let args = extract_args(regs);
    let nr = regs.rax as u32;

    linux_trace!("[LINUX] syscall {} a0={:#x} a1={:#x} a2={:#x} tid={}",
        nr, args.a0, args.a1, args.a2, kt.tid);

    let result = if regs.mode() == crate::UserMode::Mode64 {
        dispatch_nr_64(machine, kt, linux, nr, &args, regs)
    } else {
        dispatch_nr(machine, kt, linux, nr, &args, regs)
    };

    linux_trace!("[LINUX] syscall {} => {}", nr, result.retval);
    regs.rax = result.retval as u64;
    match result.switch_to {
        Some(next) => thread::KernelAction::Switch(next),
        None => thread::KernelAction::Done,
    }
}

fn dispatch_nr(machine: &mut crate::TheArch, kt: &mut thread::KernelThread, linux: &mut LinuxState, nr: u32, a: &Args, regs: &mut Regs) -> SyscallResult {
    let tid = kt.tid as usize;
    match nr {
        1   => sys_exit(machine, tid, a),
        2   => sys_fork(machine, kt, linux, a, regs),
        3   => sys_read(kt, linux, a, regs),
        7   => sys_wait4(kt, a, regs),
        4   => sys_write(kt, a),
        5   => sys_open(kt, linux, a),
        6   => sys_close(kt, a),
        11  => sys_execve(machine, kt, linux, a, regs),
        12  => sys_chdir(&mut kt.vcpu, linux, a),
        13  => sys_time(&mut kt.vcpu, a),
        19  => sys_lseek(kt, a),
        20  => SyscallResult::val(kt.tid),
        // getuid/geteuid/getgid/getegid (16-bit uid variants) — pretend root.
        24 | 49 | 47 | 50 => SyscallResult::val(0),
        // getppid: real parent if we have one, else 1 (init).
        64  => SyscallResult::val(kt.parent_tid.max(1)),
        // getuid32/getgid32/geteuid32/getegid32 — pretend root.
        199 | 200 | 201 | 202 => SyscallResult::val(0),
        // setuid32/setgid32/setreuid32/setregid32/setresuid32/setresgid32 —
        // single-user system, accept any change as a no-op.
        203 | 204 | 208 | 210 | 213 | 214 => SyscallResult::val(0),
        // setpgid(57)/getpgid(132)/setsid(66)/getpgrp(65)/getsid(147) —
        // single-process job model, return our tid as session/group.
        57 | 66 | 65 | 132 | 147 => SyscallResult::val(kt.tid),
        33  => sys_access(&mut kt.vcpu, linux, a),
        42  => sys_pipe(kt, a, false),
        45  => sys_brk(linux, a),
        54  => sys_ioctl(kt, a),
        55  => sys_fcntl(kt, a),
        63  => sys_dup2(kt, a),
        85  => sys_readlink(&mut kt.vcpu, a),
        // Old i386 struct stat — 64-byte layout. busybox/uclibc still uses
        // these and falls back from stat64; without them mode comes back
        // zero and access(X_OK) reports "Permission denied".
        106 => sys_stat_old(&mut kt.vcpu, linux, a),
        107 => sys_stat_old(&mut kt.vcpu, linux, a), // lstat — no symlinks, treat as stat
        108 => sys_fstat_old(kt, a),
        91  => sys_munmap(linux, a),
        114 => sys_wait4(kt, a, regs),
        120 => sys_clone(machine, kt, linux, a, regs),
        122 => sys_uname(&mut kt.vcpu, a),
        125 => SyscallResult::val(0),
        140 => sys_llseek(kt, a),
        146 => sys_writev(kt, a),
        158 => sys_sched_yield(kt, regs),
        162 => sys_nanosleep(),
        168 => sys_poll(kt, linux, a, regs),
        174 => SyscallResult::val(0),
        175 => SyscallResult::val(0),
        183 => sys_getcwd(&mut kt.vcpu, linux, a),
        186 => SyscallResult::val(0),
        192 => sys_mmap2(linux, a),
        195 => sys_stat64(&mut kt.vcpu, linux, a),
        196 => sys_stat64(&mut kt.vcpu, linux, a),
        197 => sys_fstat64(kt, a),
        220 => sys_getdents64(kt, linux, a),
        221 => sys_fcntl(kt, a),
        238 => sys_exit(machine, tid, a),
        240 => SyscallResult::val(0),
        243 => sys_set_thread_area(machine, kt, linux, a),
        252 => sys_exit(machine, tid, a),
        258 => SyscallResult::val(kt.tid),
        265 => sys_clock_gettime(machine, &mut kt.vcpu, a),
        270 => sys_exit(machine, tid, a),
        295 => sys_openat(kt, linux, a),
        300 => sys_fstatat64(&mut kt.vcpu, linux, a),
        305 => SyscallResult::val(-ENOENT),
        331 => sys_pipe(kt, a, true),
        340 => SyscallResult::val(0),
        355 => sys_getrandom(&mut kt.vcpu, a),
        _ => {
            println!("unimplemented syscall {}", nr);
            SyscallResult::val(-ENOSYS)
        }
    }
}

/// x86_64 syscall number table (different numbers, same implementations)
fn dispatch_nr_64(machine: &mut crate::TheArch, kt: &mut thread::KernelThread, linux: &mut LinuxState, nr: u32, a: &Args, regs: &mut Regs) -> SyscallResult {
    let tid = kt.tid as usize;
    match nr {
        0   => sys_read(kt, linux, a, regs),
        1   => sys_write(kt, a),
        2   => sys_open(kt, linux, a),
        3   => sys_close(kt, a),
        4   => sys_stat64(&mut kt.vcpu, linux, a),
        5   => sys_fstat64(kt, a),
        6   => sys_stat64(&mut kt.vcpu, linux, a),
        7   => sys_poll(kt, linux, a, regs),
        8   => sys_lseek(kt, a),
        9   => sys_mmap2(linux, a),
        10  => SyscallResult::val(0),
        11  => sys_munmap(linux, a),
        12  => sys_brk(linux, a),
        13  => SyscallResult::val(0),
        14  => SyscallResult::val(0),
        16  => sys_ioctl(kt, a),
        20  => sys_writev(kt, a),
        21  => sys_access(&mut kt.vcpu, linux, a),
        22  => sys_pipe(kt, a, false),
        24  => sys_sched_yield(kt, regs),
        33  => sys_dup2(kt, a),
        35  => sys_nanosleep(),
        39  => SyscallResult::val(kt.tid),
        56  => sys_clone(machine, kt, linux, a, regs),
        57  => sys_fork(machine, kt, linux, a, regs),
        59  => sys_execve(machine, kt, linux, a, regs),
        60  => sys_exit(machine, tid, a),
        61  => sys_wait4(kt, a, regs),
        72  => sys_fcntl(kt, a),
        79  => sys_getcwd(&mut kt.vcpu, linux, a),
        80  => sys_chdir(&mut kt.vcpu, linux, a),
        89  => SyscallResult::val(-ENOENT),
        96  => sys_clock_gettime(machine, &mut kt.vcpu, a),
        102 | 104 | 107 | 108 => SyscallResult::val(0),
        110 => SyscallResult::val(kt.tid),
        131 => SyscallResult::val(0),
        158 => sys_arch_prctl(kt, linux, a, regs),
        200 => sys_exit(machine, tid, a),
        202 => SyscallResult::val(0),
        217 => sys_getdents64(kt, linux, a),
        218 => SyscallResult::val(kt.tid),
        228 => sys_clock_gettime(machine, &mut kt.vcpu, a),
        231 => sys_exit(machine, tid, a),
        234 => sys_exit(machine, tid, a),
        257 => sys_openat(kt, linux, a),
        262 => sys_fstatat64(&mut kt.vcpu, linux, a),
        267 => SyscallResult::val(-ENOENT),
        293 => sys_pipe(kt, a, true),
        302 => SyscallResult::val(0),
        318 => sys_getrandom(&mut kt.vcpu, a),
        _ => {
            println!("unimplemented x86_64 syscall {}", nr);
            SyscallResult::val(-ENOSYS)
        }
    }
}

// =============================================================================
// Helpers: C string / path handling
// =============================================================================

/// Resolve a path (NUL-terminated user pointer) against cwd.
/// Leading `/` = absolute (strip it). Otherwise prepend cwd.
pub fn resolve_path<'a>(path: &[u8], cwd: &[u8], buf: &'a mut [u8; 164]) -> &'a [u8] {
    crate::kernel::exec::resolve_path(path, cwd, buf)
}

/// Change cwd. Validates directory exists. cwd/cwd_len are mutated in place.
pub fn do_chdir(path: &[u8], cwd: &mut [u8; 64], cwd_len: &mut usize) -> i32 {
    if path == b".." {
        let cur = &cwd[..*cwd_len];
        if cur.is_empty() { return 0; }
        let without_slash = &cur[..cur.len().saturating_sub(1)];
        let new_len = match without_slash.iter().rposition(|&b| b == b'/') {
            Some(pos) => pos + 1,
            None => 0,
        };
        *cwd_len = new_len;
        return 0;
    }
    if path.is_empty() || path == b"/" {
        *cwd_len = 0;
        return 0;
    }
    let mut new_cwd = [0u8; 64];
    let mut pos = 0;
    if path[0] == b'/' {
        for &b in &path[1..] {
            if pos < new_cwd.len() { new_cwd[pos] = b; pos += 1; }
        }
    } else {
        for &b in &cwd[..*cwd_len] {
            if pos < new_cwd.len() { new_cwd[pos] = b; pos += 1; }
        }
        for &b in path {
            if pos < new_cwd.len() { new_cwd[pos] = b; pos += 1; }
        }
    }
    if pos > 0 && new_cwd[pos - 1] != b'/' {
        if pos < new_cwd.len() { new_cwd[pos] = b'/'; pos += 1; }
    }
    let prefix = &new_cwd[..pos];
    if !vfs::dir_exists(prefix) { return -ENOENT; }
    let len = pos.min(cwd.len());
    cwd[..len].copy_from_slice(&new_cwd[..len]);
    *cwd_len = len;
    0
}

/// Check if path ends with ".EXT" (case-insensitive, 3-letter extension).
/// Read a C `char**` (NULL-terminated) from 32-bit user memory into Vec<Vec<u8>>.
fn read_c_argv(vcpu: &Vcpu, ptr: usize, wide: bool) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
    let mut args = alloc::vec::Vec::new();
    if ptr == 0 { return args; }
    let mut offset = 0usize;
    loop {
        let arg_ptr = if wide {
            vcpu.read::<u64>(ptr + offset) as usize
        } else {
            vcpu.read::<u32>(ptr + offset) as usize
        };
        if arg_ptr == 0 { break; }
        let mut arg_buf = alloc::vec![0u8; 4096];
        let arg_len = vcpu.copy_cstr(arg_ptr, &mut arg_buf);
        args.push(arg_buf[..arg_len].to_vec());
        offset += if wide { 8 } else { 4 };
    }
    args
}

// =============================================================================
// Linux-style user stack setup
// =============================================================================

/// Set up the initial user stack in the SysV-i386 layout:
///   [argc] [argv[0]..argv[N-1]] [NULL] [envp: NULL] [auxv...] [AT_NULL]
///   [16 random bytes] [string pool]
///
/// For 64-bit: same layout with 8-byte slots.
pub(crate) fn setup_user_stack(vcpu: &mut Vcpu, args: &[alloc::vec::Vec<u8>], want_64: bool) -> usize {
    // Write one machine word (4 or 8 bytes, per client bitness) to the stack.
    fn write_word(vcpu: &mut Vcpu, addr: usize, val: usize, want_64: bool) {
        if want_64 { vcpu.write::<u64>(addr, val as u64); }
        else { vcpu.write::<u32>(addr, val as u32); }
    }

    let stack_top = elf::USER_STACK_TOP;
    let word = if want_64 { 8usize } else { 4 };
    let mut sp = stack_top;

    // 1. Write NUL-terminated string data at top of stack
    // Environment strings first (they end up at higher addresses)
    let env_strings: &[&[u8]] = &[b"PATH=/bin:/"];
    let mut env_addrs: alloc::vec::Vec<usize> = alloc::vec::Vec::with_capacity(env_strings.len());
    for &env in env_strings.iter().rev() {
        sp -= env.len() + 1;
        vcpu.copy_to(sp, env);
        vcpu.write::<u8>(sp + env.len(), 0);
        env_addrs.push(sp);
    }
    env_addrs.reverse();

    // Argv strings
    let mut string_addrs: alloc::vec::Vec<usize> = alloc::vec::Vec::with_capacity(args.len());
    for arg in args.iter().rev() {
        sp -= arg.len() + 1; // +1 for NUL
        vcpu.copy_to(sp, arg);
        vcpu.write::<u8>(sp + arg.len(), 0); // NUL terminator
        string_addrs.push(sp);
    }
    string_addrs.reverse();

    // 2. Write 16 bytes of "random" data for AT_RANDOM
    sp &= !(word - 1); // align
    sp -= 16;
    let random_addr = sp;
    for i in 0..4 {
        vcpu.write::<u32>(sp + i * 4, thread::prng() as u32);
    }

    // 3. Compute total header size and align
    // Layout from sp downward: argc, argv[0..N], NULL, envp[0..M], NULL, auxv entries
    let auxv_count = 2; // AT_PAGESZ, AT_RANDOM (each is 2 words: type + value)
    let header_words = 1 /*argc*/ + args.len() + 1 /*NULL*/
        + env_addrs.len() + 1 /*envp NULL*/
        + auxv_count * 2 + 2 /*AT_NULL*/;
    sp -= header_words * word;
    sp &= !0xF; // 16-byte align

    let base = sp;
    let mut pos = base;

    // 4. Write argc
    write_word(vcpu, pos, args.len(), want_64);
    pos += word;

    // 5. Write argv[0..N-1] then the argv[N] = NULL terminator
    for &addr in &string_addrs {
        write_word(vcpu, pos, addr, want_64);
        pos += word;
    }
    write_word(vcpu, pos, 0, want_64);
    pos += word;

    // 6. envp[0..M-1] then the envp[M] = NULL terminator
    for &addr in &env_addrs {
        write_word(vcpu, pos, addr, want_64);
        pos += word;
    }
    write_word(vcpu, pos, 0, want_64);
    pos += word;

    // 7. Auxiliary vector: (AT_PAGESZ, 4096), (AT_RANDOM, ptr), (AT_NULL, 0)
    for (tag, val) in [(6usize, 4096usize), (25, random_addr), (0, 0)] {
        write_word(vcpu, pos, tag, want_64);
        write_word(vcpu, pos + word, val, want_64);
        pos += word * 2;
    }

    base // return sp
}

// =============================================================================
// ELF exec — called from kernel exec fan-out
// =============================================================================

/// Load an ELF binary into the current address space and initialize the thread.
/// Caller must have already cleaned/prepared the address space.
pub fn exec_elf_into(machine: &mut crate::TheArch, tid: usize, data: &[u8], path: &[u8], args: &[alloc::vec::Vec<u8>]) -> Result<(), i32> {
    let current = thread::get_thread(tid).unwrap();
    let loaded = elf::load_elf(machine, &mut current.kernel.vcpu, data).map_err(|_| 8)?; // ENOEXEC

    let want_64 = loaded.class == elf::ElfClass::Elf64;
    let symbols = SymbolData::new(alloc::vec::Vec::from(data).into_boxed_slice());

    let sp = setup_user_stack(&mut current.kernel.vcpu, args, want_64);
    if want_64 {
        thread::init_process_thread_64(current, loaded.entry, sp as u64);
    } else {
        thread::init_process_thread(current, loaded.entry as u32, sp as u32);
    }
    current.kernel.symbols = symbols;

    if let thread::Personality::Linux(l) = &mut current.personality {
        l.heap_base = loaded.max_vaddr;
        l.heap_end = loaded.max_vaddr;
        l.mmap_cursor = elf::USER_STACK_TOP - 0x0100_0000;
        l.set_exec_path(path);
    }

    Ok(())
}

// =============================================================================
// Syscall handlers
// =============================================================================

/// exit(1) / exit_group(252)
fn sys_exit(machine: &mut crate::TheArch, tid: usize, a: &Args) -> SyscallResult {
    let code = a.a0 as i32;
    SyscallResult { retval: 0, switch_to: Some(thread::exit_thread(machine, tid, code)) }
}

/// fork(2)
fn sys_fork(machine: &mut crate::TheArch, kt: &mut thread::KernelThread, linux: &mut LinuxState, _a: &Args, regs: &mut Regs) -> SyscallResult {
    let tid = kt.tid as usize;
    let mut child_root = crate::RootPageTable::empty();
    machine.user_fork(&mut child_root);

    let child = match thread::create_thread(machine, Some(tid), child_root, true) {
        Some(t) => t,
        None => return SyscallResult::val(-ENOMEM),
    };

    child.kernel.vcpu.regs = *regs;

    kt.dup_all_fds(&mut child.kernel);
    if let thread::Personality::Linux(cl) = &mut child.personality {
        cl.heap_base = linux.heap_base;
        cl.heap_end = linux.heap_end;
        cl.mmap_cursor = linux.mmap_cursor;
        cl.tls_entry = linux.tls_entry;
        cl.tls_base = linux.tls_base;
        cl.tls_limit = linux.tls_limit;
        cl.tls_limit_in_pages = linux.tls_limit_in_pages;
        cl.cwd = linux.cwd;
        cl.cwd_len = linux.cwd_len;
    }

    thread::set_return(child, 0);
    kt.state = thread::ThreadState::Ready;
    let child_tid = child.kernel.tid;
    SyscallResult { retval: child_tid as i64, switch_to: Some(child_tid as usize) }
}

/// clone(120) — always COW fork, with optional child_stack override.
fn sys_clone(machine: &mut crate::TheArch, kt: &mut thread::KernelThread, linux: &mut LinuxState, a: &Args, regs: &mut Regs) -> SyscallResult {
    let child_stack = a.a1 as usize;

    let result = sys_fork(machine, kt, linux, a, regs);

    if child_stack != 0 {
        if let Some(child_tid) = result.switch_to {
            if let Some(child) = thread::get_thread(child_tid) {
                child.kernel.vcpu.regs.frame.rsp = child_stack as u64;
            }
        }
    }

    result
}

/// read(3)
fn sys_read(kt: &mut thread::KernelThread, linux: &mut LinuxState, a: &Args, regs: &mut Regs) -> SyscallResult {
    let fd = a.a0 as usize;
    let buf = a.a1 as usize;
    let len = a.a2 as usize;

    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    let fd_kind = kt.fds[fd];

    match fd_kind {
        thread::FdKind::PipeRead(idx) => {
            let mut tmp = alloc::vec![0u8; len];
            let n = crate::kernel::kpipe::read(idx, &mut tmp);
            if n > 0 {
                kt.vcpu.copy_to(buf, &tmp[..n as usize]);
                return SyscallResult::val(n as i32);
            }
            // No data — check if writers exist
            if !crate::kernel::kpipe::has_writers(idx) {
                return SyscallResult::val(0); // EOF
            }
            // Block in place. The console keystroke source (process_key in
            // the event-loop pre-execute step) only feeds the *currently
            // running* thread's pipe — yielding here would hand keys to
            // whoever the scheduler picks instead of us, and we'd never
            // unblock. Keep the thread as the running tid; the Blocked
            // drain at the top of event_loop satisfies the read as soon as
            // bytes show up.
            kt.vcpu.regs = *regs;
            kt.state = thread::ThreadState::Blocked;
            linux.pending_read = Some(thread::PendingRead {
                fd_kind,
                buf_ptr: buf,
                buf_len: len,
            });
            SyscallResult { retval: 0, switch_to: None }
        }
        thread::FdKind::Vfs(handle) => {
            let mut tmp = alloc::vec![0u8; len];
            let n = vfs::read_by_handle(handle, &mut tmp);
            if n > 0 { kt.vcpu.copy_to(buf, &tmp[..n as usize]); }
            SyscallResult::val(n)
        }
        thread::FdKind::ConsoleOut | thread::FdKind::PipeWrite(_) | thread::FdKind::Dir(_) => {
            SyscallResult::val(-EBADF)
        }
        thread::FdKind::None => SyscallResult::val(-EBADF),
    }
}

/// write(4)
fn sys_write(kt: &mut thread::KernelThread, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    let buf = a.a1 as usize;
    let len = a.a2 as usize;

    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    let fd_kind = kt.fds[fd];

    match fd_kind {
        thread::FdKind::ConsoleOut => {
            let mut tmp = alloc::vec![0u8; len];
            kt.vcpu.copy_from(buf, &mut tmp);
            for &b in &tmp {
                vga::putchar(b);
            }
            SyscallResult::val(len as i32)
        }
        thread::FdKind::PipeWrite(idx) => {
            let mut tmp = alloc::vec![0u8; len];
            kt.vcpu.copy_from(buf, &mut tmp);
            let r = crate::kernel::kpipe::write(idx, &tmp);
            if r < 0 {
                SyscallResult::val(-EPIPE)
            } else {
                SyscallResult::val(r)
            }
        }
        thread::FdKind::Vfs(handle) => {
            let mut tmp = alloc::vec![0u8; len];
            kt.vcpu.copy_from(buf, &mut tmp);
            SyscallResult::val(vfs::write_by_handle(handle, &tmp))
        }
        thread::FdKind::PipeRead(_) | thread::FdKind::None | thread::FdKind::Dir(_) => {
            SyscallResult::val(-EBADF)
        }
    }
}

/// open(5)
fn sys_open(kt: &mut thread::KernelThread, linux: &LinuxState, a: &Args) -> SyscallResult {
    let path_ptr = a.a0 as usize;
    let mut path_buf = [0u8; 256];
    let path_len = kt.vcpu.copy_cstr(path_ptr, &mut path_buf);
    let path = &path_buf[..path_len];

    let mut buf = [0u8; 164];
    let resolved = resolve_path(path, linux.cwd_str(), &mut buf);

    // Directories: hand out a placeholder fd so opendir() succeeds; the
    // getdents64 syscall reads against the thread's cwd anyway.
    if vfs::dir_exists(resolved) {
        return match kt.alloc_fd(3) {
            Some(fd) => {
                kt.fds[fd] = thread::FdKind::Dir(0);
                SyscallResult::val(fd as i32)
            }
            None => SyscallResult::val(-24), // EMFILE
        };
    }

    let handle = vfs::open_to_handle(resolved);
    if handle < 0 { return SyscallResult::val(handle); }

    match kt.alloc_fd(3) {
        Some(fd) => {
            kt.fds[fd] = thread::FdKind::Vfs(handle);
            SyscallResult::val(fd as i32)
        }
        None => {
            vfs::close_vfs_handle(handle);
            SyscallResult::val(-24) // EMFILE
        }
    }
}

/// close(6)
fn sys_close(kt: &mut thread::KernelThread, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    if kt.fds[fd].is_none() { return SyscallResult::val(-EBADF); }
    kt.close_fd(fd);
    SyscallResult::val(0)
}

/// execve(11)
fn sys_execve(machine: &mut crate::TheArch, kt: &mut thread::KernelThread, linux: &mut LinuxState, a: &Args, regs: &mut Regs) -> SyscallResult {
    use crate::kernel::exec;

    let tid = kt.tid as usize;
    let path_ptr = a.a0 as usize;
    let argv_ptr = a.a1 as usize;
    let _envp_ptr = a.a2 as usize;

    let mut raw_path_buf = [0u8; 256];
    let raw_path_len = kt.vcpu.copy_cstr(path_ptr, &mut raw_path_buf);
    let raw_path = &raw_path_buf[..raw_path_len];
    // Resolve /proc/self/exe to this process's own load path (tracked in
    // LinuxState.exec_path, set on every exec) — busybox's standalone-shell
    // mode re-execs itself that way, and we have no real /proc. Copy to the
    // kernel heap: `raw_path` borrows user memory that arch_user_clean() below
    // unmaps, and we use `path` after that (format detection + init_thread).
    let path: alloc::vec::Vec<u8> = if raw_path == b"/proc/self/exe" {
        linux.exec_path_str().to_vec()
    } else {
        raw_path.to_vec()
    };

    // Read argv from caller's address space before we free it. Preserve the
    // caller's argv[0] — POSIX lets it differ from the load path, and busybox
    // launches as /bin/busybox with argv[0] = the applet name (sh/ls/…) to
    // select the applet. Format detection uses `path` (handed to init_thread)
    // rather than argv[0]; only synthesize argv[0] from the path if the caller
    // passed an empty argv.
    let wide = regs.mode() == crate::UserMode::Mode64;
    let mut args = read_c_argv(&kt.vcpu, argv_ptr, wide);
    if args.is_empty() { args.push(path.clone()); }

    // Snapshot cwd up front — execve preserves it across the address-space
    // teardown, but `linux` borrows from the thread we're about to clobber.
    let cwd_snapshot: alloc::vec::Vec<u8> = linux.cwd_str().into();

    // Load file (resolves path against cwd)
    let buffer = match exec::load_file(&path, &cwd_snapshot) {
        Ok(b) => b,
        Err(_) => return SyscallResult::val(-ENOENT),
    };

    // Point of no return — close CLOEXEC fds and drop symbols
    kt.symbols = None;
    kt.close_cloexec();

    let format = exec::detect_format(&buffer, &path);

    // ELF address space prep (DOS handles its own inside exec_dos_into)
    if matches!(format, exec::BinaryFormat::Elf) {
        machine.free_user_pages();
    }

    if let Err(_) = exec::init_thread(machine, tid, buffer, &path, args, alloc::vec::Vec::new(), alloc::vec::Vec::new(), cwd_snapshot) {
        return SyscallResult { retval: 0, switch_to: Some(thread::exit_thread(machine, tid, -ENOEXEC)) };
    }

    // Reload regs from thread (init_thread sets them via get_thread)
    *regs = thread::get_thread(tid).unwrap().kernel.vcpu.regs;
    SyscallResult { retval: 0, switch_to: Some(tid) }
}


/// chdir(12)
fn sys_chdir(vcpu: &mut Vcpu, linux: &mut LinuxState, a: &Args) -> SyscallResult {
    let mut path_buf = [0u8; 256];
    let path_len = vcpu.copy_cstr(a.a0 as usize, &mut path_buf);
    let path = &path_buf[..path_len];
    SyscallResult::val(do_chdir(path, &mut linux.cwd, &mut linux.cwd_len))
}

/// time(13) — stub
fn sys_time(vcpu: &mut Vcpu, a: &Args) -> SyscallResult {
    let ptr = a.a0 as usize;
    if ptr != 0 {
        vcpu.write::<u32>(ptr, 0);
    }
    SyscallResult::val(0)
}

/// lseek(19)
fn sys_lseek(kt: &mut thread::KernelThread, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    let offset = a.a1 as i32;
    let whence = a.a2 as i32;
    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    match kt.fds[fd] {
        thread::FdKind::Vfs(handle) => SyscallResult::val(vfs::seek_by_handle(handle, offset, whence)),
        thread::FdKind::PipeRead(_) | thread::FdKind::PipeWrite(_) => SyscallResult::val(-ESPIPE),
        _ => SyscallResult::val(-EBADF),
    }
}

/// ioctl(54 i386 / 16 x86_64) — minimal TTY support so isatty() returns
/// true on console fds, otherwise sh drops into silent non-interactive
/// mode (no prompt). We only implement enough for ash to consider stdin a
/// terminal: TCGETS returns a zeroed termios on stdin/stdout/stderr,
/// everything else returns ENOTTY.
fn sys_ioctl(kt: &mut thread::KernelThread, a: &Args) -> SyscallResult {
    const TCGETS: u32 = 0x5401;
    const TCSETS: u32 = 0x5402;
    const TIOCGWINSZ: u32 = 0x5413;
    const TIOCSWINSZ: u32 = 0x5414;
    const TIOCGPGRP: u32 = 0x540F;
    const TIOCSPGRP: u32 = 0x5410;

    let fd = a.a0 as usize;
    let cmd = a.a1 as u32;
    let arg = a.a2 as usize;

    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    let kind = kt.fds[fd];

    // Only console-attached fds are "ttys" for our purposes.
    let is_tty = matches!(kind,
        thread::FdKind::ConsoleOut
        | thread::FdKind::PipeRead(_)
        | thread::FdKind::PipeWrite(_));
    if !is_tty { return SyscallResult::val(-ENOTTY); }

    match cmd {
        TCGETS => {
            // struct termios is ~36 bytes on i386. Zero is fine — what
            // matters for isatty() is just that the call succeeds.
            if arg != 0 {
                kt.vcpu.zero(arg, 36);
            }
            SyscallResult::val(0)
        }
        TCSETS | TIOCSWINSZ | TIOCSPGRP => SyscallResult::val(0), // accept and discard
        TIOCGWINSZ => {
            // struct winsize: ws_row, ws_col, ws_xpixel, ws_ypixel — 4×u16.
            if arg != 0 {
                kt.vcpu.write::<u16>(arg, 25);       // ws_row
                kt.vcpu.write::<u16>(arg + 2, 80);   // ws_col
                kt.vcpu.write::<u16>(arg + 4, 0);
                kt.vcpu.write::<u16>(arg + 6, 0);
            }
            SyscallResult::val(0)
        }
        TIOCGPGRP => {
            if arg != 0 {
                let tid = kt.tid;
                kt.vcpu.write::<i32>(arg, tid);
            }
            SyscallResult::val(0)
        }
        _ => SyscallResult::val(-ENOTTY),
    }
}

/// readlink(85) — minimal stub: only resolves /proc/self/exe (used by
/// static-busybox to find its own re-exec path). Everything else returns
/// EINVAL since we have no symlinks.
fn sys_readlink(vcpu: &mut Vcpu, a: &Args) -> SyscallResult {
    let buf = a.a1 as usize;
    let bufsz = a.a2 as usize;
    let mut self_exe_buf = [0u8; 256];
    let self_exe_len = vcpu.copy_cstr(a.a0 as usize, &mut self_exe_buf);
    let is_self_exe = &self_exe_buf[..self_exe_len] == b"/proc/self/exe";
    if is_self_exe {
        let target: &[u8] = b"/bin/busybox";
        let n = target.len().min(bufsz);
        vcpu.copy_to(buf, &target[..n]);
        return SyscallResult::val(n as i32);
    }
    SyscallResult::val(-EINVAL)
}

/// access(33) — check file existence via VFS stat
fn sys_access(vcpu: &mut Vcpu, linux: &LinuxState, a: &Args) -> SyscallResult {
    let mut path_buf = [0u8; 256];
    let path_len = vcpu.copy_cstr(a.a0 as usize, &mut path_buf);
    let path = &path_buf[..path_len];
    let mut buf = [0u8; 164];
    let resolved = resolve_path(path, linux.cwd_str(), &mut buf);
    let handle = vfs::open_to_handle(resolved);
    if handle < 0 {
        return SyscallResult::val(-ENOENT);
    }
    vfs::close_vfs_handle(handle);
    SyscallResult::val(0)
}

/// brk(45)
fn sys_brk(linux: &mut LinuxState, a: &Args) -> SyscallResult {
    let addr = a.a0 as usize;

    if addr == 0 {
        // Query current brk
        return SyscallResult::val64(linux.heap_end as i64);
    }

    let new_end = addr.max(linux.heap_base).min(linux.mmap_cursor);
    linux.heap_end = new_end;
    SyscallResult::val64(linux.heap_end as i64)
}

/// fcntl(55) / fcntl64(221)
fn sys_fcntl(kt: &mut thread::KernelThread, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    let cmd = a.a1 as i32;
    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    if kt.fds[fd].is_none() { return SyscallResult::val(-EBADF); }

    const F_GETFD: i32 = 1;
    const F_SETFD: i32 = 2;
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;
    const FD_CLOEXEC: i32 = 1;

    match cmd {
        F_GETFD => {
            let cloexec = if kt.cloexec & (1 << fd) != 0 { FD_CLOEXEC } else { 0 };
            SyscallResult::val(cloexec)
        }
        F_SETFD => {
            let arg = a.a2 as i32;
            if arg & FD_CLOEXEC != 0 {
                kt.cloexec |= 1 << fd;
            } else {
                kt.cloexec &= !(1 << fd);
            }
            SyscallResult::val(0)
        }
        F_GETFL | F_SETFL => SyscallResult::val(0), // stub
        _ => SyscallResult::val(-EINVAL),
    }
}

/// munmap(91)
fn sys_munmap(_linux: &mut LinuxState, a: &Args) -> SyscallResult {
    let addr = a.a0 as usize;
    let length = a.a1 as usize;
    if addr & 0xFFF != 0 { return SyscallResult::val(-EINVAL); }
    let num_pages = (length + 0xFFF) / 0x1000;
    let start_page = addr / 0x1000;
    // Clear page table entries — pages get freed via refcount
    for i in 0..num_pages {
        let vpage = start_page + i;
        // Use arch_set_page_flags to mark not-present (flags=0 doesn't help — we need real unmap)
        // For now: zero out the page table entry by mapping to zero page read-only then freeing
        // This is approximate — full unmap needs an arch call
        // TODO: add arch_unmap_user_range call
        let _ = vpage;
    }
    SyscallResult::val(0)
}

/// wait4(114)
fn sys_wait4(kt: &mut thread::KernelThread, a: &Args, regs: &mut Regs) -> SyscallResult {
    let tid = kt.tid as usize;
    let pid = a.a0 as i32;
    let status_ptr = a.a1 as usize;
    let _options = a.a2 as i32;

    let (child_tid, exit_code) = thread::waitpid(tid, pid);

    if child_tid >= 0 {
        if status_ptr != 0 {
            kt.vcpu.write::<i32>(status_ptr, (exit_code & 0xFF) << 8);
        }
        return SyscallResult::val(child_tid);
    }

    if child_tid == -10 {
        return SyscallResult::val(-ECHILD);
    }

    // EAGAIN — children exist but none exited. Block and yield.
    // Save status_ptr now (we know the ABI); exit_thread will set exit_code.
    if let thread::Personality::Linux(linux) = &mut thread::get_thread(tid).unwrap().personality {
        linux.wait_status_ptr = status_ptr;
    }
    kt.vcpu.regs = *regs;
    kt.state = thread::ThreadState::Blocked;
    let next = thread::schedule(tid).unwrap_or(0);
    SyscallResult { retval: 0, switch_to: Some(next) }
}

/// uname(122)
fn sys_uname(vcpu: &mut Vcpu, a: &Args) -> SyscallResult {
    let buf = a.a0 as usize;
    if buf == 0 { return SyscallResult::val(-EFAULT); }

    // Linux struct old_utsname: 6 fields, 65 bytes each
    vcpu.zero(buf, 65 * 6);
    let fields: [&[u8]; 6] = [b"Linux", b"retroos", b"5.0.0", b"#1", b"i686", b"(none)"];
    for (i, s) in fields.iter().enumerate() {
        let n = s.len().min(64);
        vcpu.copy_to(buf + i * 65, &s[..n]);
    }
    SyscallResult::val(0)
}

/// _llseek(140) — 64-bit lseek
fn sys_llseek(kt: &mut thread::KernelThread, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    let offset_hi = a.a1 as u32;
    let offset_lo = a.a2 as u32;
    let result_ptr = a.a3 as usize;
    let whence = a.a4 as i32;

    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    let handle = match kt.fds[fd] {
        thread::FdKind::Vfs(h) => h,
        thread::FdKind::PipeRead(_) | thread::FdKind::PipeWrite(_) => return SyscallResult::val(-ESPIPE),
        _ => return SyscallResult::val(-EBADF),
    };

    let offset = ((offset_hi as i64) << 32) | (offset_lo as i64);
    let r = vfs::seek_by_handle(handle, offset as i32, whence);
    if r < 0 { return SyscallResult::val(r); }

    if result_ptr != 0 {
        kt.vcpu.write::<i64>(result_ptr, r as i64);
    }
    SyscallResult::val(0)
}

/// writev(146)
fn sys_writev(kt: &mut thread::KernelThread, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    let iov_ptr = a.a1 as usize;
    let iovcnt = a.a2 as usize;

    if iovcnt > 1024 { return SyscallResult::val(-EINVAL); }
    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    let fd_kind = kt.fds[fd];

    let mut total = 0i32;

    for i in 0..iovcnt {
        // struct iovec { void *iov_base; size_t iov_len; } — 8 bytes on i386
        let base_addr = iov_ptr + i * 8;
        let iov_base = kt.vcpu.read::<u32>(base_addr) as usize;
        let iov_len = kt.vcpu.read::<u32>(base_addr + 4) as usize;

        if iov_len == 0 { continue; }

        let mut iov = alloc::vec![0u8; iov_len];
        kt.vcpu.copy_from(iov_base, &mut iov);
        match fd_kind {
            thread::FdKind::ConsoleOut => {
                for &b in &iov {
                    vga::putchar(b);
                }
                total += iov_len as i32;
            }
            thread::FdKind::PipeWrite(idx) => {
                let r = crate::kernel::kpipe::write(idx, &iov);
                if r < 0 { return SyscallResult::val(-EPIPE); }
                total += r;
            }
            thread::FdKind::Vfs(handle) => {
                let r = vfs::write_by_handle(handle, &iov);
                if r < 0 { return SyscallResult::val(r); }
                total += r;
            }
            _ => return SyscallResult::val(-EBADF),
        }
    }

    SyscallResult::val(total)
}

/// sched_yield(158)
fn sys_sched_yield(kt: &mut thread::KernelThread, regs: &mut Regs) -> SyscallResult {
    let tid = kt.tid as usize;
    kt.vcpu.regs = *regs;
    kt.vcpu.regs.rax = 0;
    kt.state = thread::ThreadState::Ready;
    SyscallResult { retval: 0, switch_to: thread::schedule(tid) }
}

/// nanosleep(162) — stub: yield once
fn sys_nanosleep() -> SyscallResult {
    SyscallResult::val(0)
}

/// Evaluate a pollfd[] array once, writing revents and returning the
/// number of fds with non-zero revents. Used by both sys_poll's first try
/// and the event-loop's pending-poll retry.
pub(crate) fn run_poll(kt: &mut thread::KernelThread, fds_ptr: usize, nfds: usize) -> i32 {
    const POLLIN: i16 = 1;
    const POLLOUT: i16 = 4;
    let mut ready = 0i32;
    for i in 0..nfds {
        let base = fds_ptr + i * 8;
        let fd = kt.vcpu.read::<i32>(base) as usize;
        let events = kt.vcpu.read::<i16>(base + 4);
        let mut revents: i16 = 0;
        if fd < thread::MAX_FDS {
            match kt.fds[fd] {
                thread::FdKind::PipeRead(idx) => {
                    if (events & POLLIN) != 0 && crate::kernel::kpipe::has_data(idx) {
                        revents |= POLLIN;
                    }
                }
                thread::FdKind::ConsoleOut => {
                    if (events & POLLOUT) != 0 { revents |= POLLOUT; }
                }
                thread::FdKind::PipeWrite(_idx) => {
                    if (events & POLLOUT) != 0 { revents |= POLLOUT; }
                }
                thread::FdKind::Vfs(_) | thread::FdKind::Dir(_) => {
                    if (events & POLLIN) != 0 { revents |= POLLIN; }
                    if (events & POLLOUT) != 0 { revents |= POLLOUT; }
                }
                thread::FdKind::None => {}
            }
        }
        kt.vcpu.write::<i16>(base + 6, revents);
        if revents != 0 { ready += 1; }
    }
    ready
}

/// poll(168) — block until at least one monitored fd is ready (or timeout).
fn sys_poll(kt: &mut thread::KernelThread, linux: &mut LinuxState, a: &Args, regs: &mut Regs) -> SyscallResult {
    let fds_ptr = a.a0 as usize;
    let nfds = a.a1 as usize;
    let timeout = a.a2 as i32;

    let ready = run_poll(kt, fds_ptr, nfds);
    if ready > 0 || timeout == 0 {
        return SyscallResult::val(ready);
    }

    // Block in place. The event-loop blocked-drain re-runs run_poll once
    // bytes show up on the watched pipe(s). Same focus rules as sys_read:
    // don't yield, since console keystrokes only land in the focused
    // thread's pipe.
    kt.vcpu.regs = *regs;
    kt.state = thread::ThreadState::Blocked;
    linux.pending_poll = Some(thread::PendingPoll { fds_ptr, nfds, timeout_ms: timeout });
    SyscallResult { retval: 0, switch_to: None }
}

/// getcwd(183)
fn sys_getcwd(vcpu: &mut Vcpu, linux: &LinuxState, a: &Args) -> SyscallResult {
    let ptr = a.a0 as usize;
    let size = a.a1 as usize;
    let cwd = linux.cwd_str();
    // Linux getcwd returns absolute path with leading /
    if size < cwd.len() + 2 { return SyscallResult::val(-EINVAL); }
    vcpu.write::<u8>(ptr, b'/');
    vcpu.copy_to(ptr + 1, cwd);
    vcpu.write::<u8>(ptr + 1 + cwd.len(), 0); // NUL
    SyscallResult::val((cwd.len() + 2) as i32)
}

/// mmap2(192) — anonymous private only
fn sys_mmap2(linux: &mut LinuxState, a: &Args) -> SyscallResult {
    let addr_hint = a.a0 as usize;
    let length = a.a1 as usize;
    let _prot = a.a2 as u32;
    let flags = a.a3 as u32;
    let fd = a.a4 as i32;
    let _offset_pages = a.a5 as u32;

    const MAP_ANONYMOUS: u32 = 0x20;
    const MAP_FIXED: u32 = 0x10;

    // Only support MAP_ANONYMOUS | MAP_PRIVATE
    if flags & MAP_ANONYMOUS == 0 {
        return SyscallResult::val64(-ENOSYS as i64);
    }
    if fd != -1i32 as i32 && flags & MAP_ANONYMOUS != 0 {
        // Some callers pass fd=-1 with MAP_ANONYMOUS — that's fine
    }

    let num_pages = (length + 0xFFF) / 0x1000;
    if num_pages == 0 { return SyscallResult::val(-EINVAL); }

    // Pick address: grow mmap_cursor downward
    let alloc_size = num_pages * 0x1000;
    if linux.mmap_cursor < linux.heap_end + alloc_size {
        return SyscallResult::val64(-ENOMEM as i64);
    }
    let base = if flags & MAP_FIXED != 0 && addr_hint != 0 {
        addr_hint & !0xFFF
    } else {
        linux.mmap_cursor -= alloc_size;
        linux.mmap_cursor
    };

    // Pages are demand-paged: existing page fault handler allocates on access.
    // No need to pre-allocate. The zero page fill on first touch gives
    // MAP_ANONYMOUS semantics (contents initialized to zero).

    SyscallResult::val64(base as i64)
}

/// stat64(195) / lstat64(196)
fn sys_stat64(vcpu: &mut Vcpu, linux: &LinuxState, a: &Args) -> SyscallResult {
    let path_ptr = a.a0 as usize;
    let stat_buf = a.a1 as usize;
    let mut path_buf = [0u8; 256];
    let path_len = vcpu.copy_cstr(path_ptr, &mut path_buf);
    let path = &path_buf[..path_len];

    let mut pbuf = [0u8; 164];
    let resolved = resolve_path(path, linux.cwd_str(), &mut pbuf);

    // Check if it's a directory
    if vfs::dir_exists(resolved) {
        write_stat64(vcpu, stat_buf, 0o40755, 0);
        return SyscallResult::val(0);
    }

    let handle = vfs::open_to_handle(resolved);
    if handle < 0 { return SyscallResult::val(-ENOENT); }
    let size = vfs::file_size_by_handle(handle);
    let posix_mode = vfs::file_mode_by_handle(handle);
    vfs::close_vfs_handle(handle);
    write_stat64(vcpu, stat_buf, 0o100000 | posix_mode as u32, size);
    SyscallResult::val(0)
}

/// fstat64(197)
fn sys_fstat64(kt: &mut thread::KernelThread, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    let stat_buf = a.a1 as usize;

    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    match kt.fds[fd] {
        thread::FdKind::ConsoleOut | thread::FdKind::PipeRead(_) | thread::FdKind::PipeWrite(_) => {
            // stdin/stdout/stderr / pipes — character device / pipe
            write_stat64(&mut kt.vcpu, stat_buf, 0o20666, 0); // S_IFCHR
            SyscallResult::val(0)
        }
        thread::FdKind::Vfs(handle) => {
            let size = vfs::file_size_by_handle(handle);
            let mode = vfs::file_mode_by_handle(handle);
            write_stat64(&mut kt.vcpu, stat_buf, 0o100000 | mode as u32, size);
            SyscallResult::val(0)
        }
        thread::FdKind::Dir(_) => {
            write_stat64(&mut kt.vcpu, stat_buf, 0o40755, 0); // S_IFDIR
            SyscallResult::val(0)
        }
        thread::FdKind::None => SyscallResult::val(-EBADF),
    }
}

/// fstatat64(300)
fn sys_fstatat64(vcpu: &mut Vcpu, linux: &LinuxState, a: &Args) -> SyscallResult {
    let _dirfd = a.a0 as i32;
    // Treat as stat64 on the path (a.a1 = path, a.a2 = stat buf)
    let shifted = Args { a0: a.a1, a1: a.a2, a2: a.a3, a3: a.a4, a4: a.a5, a5: 0 };
    sys_stat64(vcpu, linux, &shifted)
}

/// Write a minimal Linux stat64 struct to user memory.
/// struct stat64 on i386 is 96 bytes. We fill mode, size, blksize.
fn write_stat64(vcpu: &mut Vcpu, buf: usize, mode: u32, size: u32) {
    vcpu.zero(buf, 96);
    vcpu.write::<u32>(buf + 16, mode);                          // st_mode
    vcpu.write::<u64>(buf + 44, size as u64);                   // st_size (u64 on stat64)
    vcpu.write::<u32>(buf + 56, 4096);                          // st_blksize
    vcpu.write::<u64>(buf + 64, ((size as u64) + 511) / 512);   // st_blocks
}

/// Write the old (pre-LFS) Linux i386 `struct stat` (newstat layout, 64 bytes).
/// Used by syscalls 106/107/108. uclibc's busybox falls back to these for
/// access/exec checks; without correct mode bits we get spurious EACCES.
fn write_stat_old(vcpu: &mut Vcpu, buf: usize, mode: u32, size: u32) {
    vcpu.zero(buf, 64);
    vcpu.write::<u16>(buf + 0x08, mode as u16);          // st_mode
    vcpu.write::<u16>(buf + 0x0a, 1);                    // st_nlink
    vcpu.write::<u32>(buf + 0x14, size);                 // st_size
    vcpu.write::<u32>(buf + 0x18, 4096);                 // st_blksize
    vcpu.write::<u32>(buf + 0x1c, (size + 511) / 512);   // st_blocks
}

/// stat(106) / lstat(107) — old struct stat layout. We have no symlinks so
/// lstat falls through to stat.
fn sys_stat_old(vcpu: &mut Vcpu, linux: &LinuxState, a: &Args) -> SyscallResult {
    let mut path_buf = [0u8; 256];
    let path_len = vcpu.copy_cstr(a.a0 as usize, &mut path_buf);
    let path = &path_buf[..path_len];
    let stat_buf = a.a1 as usize;
    let mut pbuf = [0u8; 164];
    let resolved = resolve_path(path, linux.cwd_str(), &mut pbuf);
    if vfs::dir_exists(resolved) {
        write_stat_old(vcpu, stat_buf, 0o40755, 0);
        return SyscallResult::val(0);
    }
    let handle = vfs::open_to_handle(resolved);
    if handle < 0 { return SyscallResult::val(-ENOENT); }
    let size = vfs::file_size_by_handle(handle);
    let mode = vfs::file_mode_by_handle(handle);
    vfs::close_vfs_handle(handle);
    write_stat_old(vcpu, stat_buf, 0o100000 | mode as u32, size);
    SyscallResult::val(0)
}

/// fstat(108) — old struct stat layout.
fn sys_fstat_old(kt: &mut thread::KernelThread, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    let stat_buf = a.a1 as usize;
    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    match kt.fds[fd] {
        thread::FdKind::ConsoleOut | thread::FdKind::PipeRead(_) | thread::FdKind::PipeWrite(_) => {
            write_stat_old(&mut kt.vcpu, stat_buf, 0o20666, 0); // S_IFCHR
            SyscallResult::val(0)
        }
        thread::FdKind::Vfs(handle) => {
            let size = vfs::file_size_by_handle(handle);
            let mode = vfs::file_mode_by_handle(handle);
            write_stat_old(&mut kt.vcpu, stat_buf, 0o100000 | mode as u32, size);
            SyscallResult::val(0)
        }
        thread::FdKind::Dir(_) => {
            write_stat_old(&mut kt.vcpu, stat_buf, 0o40755, 0);
            SyscallResult::val(0)
        }
        _ => SyscallResult::val(-EBADF),
    }
}

/// getdents64(220)
fn sys_getdents64(kt: &mut thread::KernelThread, linux: &LinuxState, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    let dirp = a.a1 as usize;
    let count = a.a2 as usize;

    // The fd carries a per-fd cursor (FdKind::Dir(idx)). Without it, every
    // call would replay from index 0 and the caller would loop forever.
    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    let mut index = match kt.fds[fd] {
        thread::FdKind::Dir(i) => i as usize,
        _ => 0,  // Tolerate fd=0 / non-Dir fd: read against cwd from start.
    };

    // No directory fd → use cwd. (Real fix would track the path on the fd,
    // but for now the only opener is `opendir(".")` which equals cwd.)
    let cwd = linux.cwd_str();

    let mut offset = 0usize;
    loop {
        let entry = match vfs::readdir(cwd, index) {
            Some(e) => e,
            None => break,
        };
        index += 1;

        let name = &entry.name[..entry.name_len];
        // struct linux_dirent64: d_ino(8) + d_off(8) + d_reclen(2) + d_type(1) + d_name[...]
        let reclen = (19 + name.len() + 1 + 7) & !7; // 8-byte align
        if offset + reclen > count {
            // Doesn't fit — back off this entry and stop.
            index -= 1;
            break;
        }

        let base = dirp + offset;
        kt.vcpu.zero(base, reclen);
        kt.vcpu.write::<u64>(base, index as u64);         // d_ino
        kt.vcpu.write::<u64>(base + 8, index as u64);     // d_off
        kt.vcpu.write::<u16>(base + 16, reclen as u16);   // d_reclen
        kt.vcpu.write::<u8>(base + 18, if entry.is_dir { 4 } else { 8 }); // d_type: DT_DIR/DT_REG
        kt.vcpu.copy_to(base + 19, name);
        offset += reclen;
    }

    if let thread::FdKind::Dir(_) = kt.fds[fd] {
        kt.fds[fd] = thread::FdKind::Dir(index as u32);
    }
    SyscallResult::val(offset as i32)
}

/// set_thread_area(243) — parse user_desc struct, set GDT TLS entry, save to LinuxState
fn sys_set_thread_area(machine: &mut crate::TheArch, kt: &mut thread::KernelThread, linux: &mut LinuxState, a: &Args) -> SyscallResult {
    let u_info = a.a0 as usize;
    if u_info == 0 { return SyscallResult::val(-EFAULT); }

    // struct user_desc { entry_number: i32, base_addr: u32, limit: u32, flags: u32 }
    let entry_number = kt.vcpu.read::<i32>(u_info);
    let base_addr = kt.vcpu.read::<u32>(u_info + 4);
    let limit = kt.vcpu.read::<u32>(u_info + 8);
    let flags = kt.vcpu.read::<u32>(u_info + 12);
    let limit_in_pages = flags & (1 << 4) != 0;

    let idx = machine.set_tls_entry(entry_number, base_addr, limit, limit_in_pages);
    if idx < 0 { return SyscallResult::val(-ESRCH); }

    // Write back the allocated entry number
    kt.vcpu.write::<i32>(u_info, idx);

    // Save TLS state for context-switch restore
    linux.tls_entry = idx;
    linux.tls_base = base_addr;
    linux.tls_limit = limit;
    linux.tls_limit_in_pages = limit_in_pages;

    SyscallResult::val(0)
}

/// arch_prctl(158) — x86_64 TLS via FS/GS base.
/// Stores the base in regs.fs/gs — arch layer writes MSR on return to user.
fn sys_arch_prctl(kt: &mut thread::KernelThread, _linux: &mut LinuxState, a: &Args, regs: &mut Regs) -> SyscallResult {
    const ARCH_SET_GS: u64 = 0x1001;
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;
    const ARCH_GET_GS: u64 = 0x1004;

    match a.a0 {
        ARCH_SET_FS => { regs.fs = a.a1; SyscallResult::val(0) }
        ARCH_SET_GS => { regs.gs = a.a1; SyscallResult::val(0) }
        ARCH_GET_FS => {
            let ptr = a.a1 as usize;
            if ptr != 0 { kt.vcpu.write::<u64>(ptr, regs.fs); }
            SyscallResult::val(0)
        }
        ARCH_GET_GS => {
            let ptr = a.a1 as usize;
            if ptr != 0 { kt.vcpu.write::<u64>(ptr, regs.gs); }
            SyscallResult::val(0)
        }
        _ => SyscallResult::val(-EINVAL),
    }
}

/// clock_gettime(265) — monotonic from tick counter
fn sys_clock_gettime(machine: &mut crate::TheArch, vcpu: &mut Vcpu, a: &Args) -> SyscallResult {
    let _clock_id = a.a0 as u32;
    let tp = a.a1 as usize;
    if tp != 0 {
        let ticks = machine.get_ticks() as u64;
        // PIT ticks at ~1193182 Hz, timer IRQ at ~100 Hz (div=11932)
        let secs = ticks / 100;
        let nsecs = (ticks % 100) * 10_000_000;
        vcpu.write::<u32>(tp, secs as u32);        // tv_sec
        vcpu.write::<u32>(tp + 4, nsecs as u32);   // tv_nsec
    }
    SyscallResult::val(0)
}

/// openat(295) — treat AT_FDCWD as cwd-relative, else EBADF
fn sys_openat(kt: &mut thread::KernelThread, linux: &LinuxState, a: &Args) -> SyscallResult {
    let dirfd = a.a0 as i32;
    const AT_FDCWD: i32 = -100;
    if dirfd != AT_FDCWD && dirfd < 0 {
        return SyscallResult::val(-EBADF);
    }
    let shifted = Args { a0: a.a1, a1: a.a2, a2: a.a3, a3: 0, a4: 0, a5: 0 };
    sys_open(kt, linux, &shifted)
}

/// getrandom(355) — stub: fill with PRNG output
fn sys_getrandom(vcpu: &mut Vcpu, a: &Args) -> SyscallResult {
    let buf = a.a0 as usize;
    let buflen = a.a1 as usize;
    let mut tmp = alloc::vec![0u8; buflen];
    for b in tmp.iter_mut() {
        *b = thread::prng() as u8;
    }
    vcpu.copy_to(buf, &tmp);
    SyscallResult::val(buflen as i32)
}

/// pipe(42) / pipe2(359)
fn sys_pipe(kt: &mut thread::KernelThread, a: &Args, is_pipe2: bool) -> SyscallResult {
    let pipefd_ptr = a.a0 as usize;
    let flags = if is_pipe2 { a.a1 as u32 } else { 0 };
    const O_CLOEXEC: u32 = 0o2000000;

    let pipe_idx = match crate::kernel::kpipe::alloc() {
        Some(idx) => idx,
        None => return SyscallResult::val(-24), // EMFILE
    };

    let read_fd = match kt.alloc_fd(0) {
        Some(fd) => fd,
        None => {
            crate::kernel::kpipe::close_reader(pipe_idx);
            crate::kernel::kpipe::close_writer(pipe_idx);
            return SyscallResult::val(-24);
        }
    };
    kt.fds[read_fd] = thread::FdKind::PipeRead(pipe_idx);

    let write_fd = match kt.alloc_fd(0) {
        Some(fd) => fd,
        None => {
            kt.close_fd(read_fd);
            crate::kernel::kpipe::close_writer(pipe_idx);
            return SyscallResult::val(-24);
        }
    };
    kt.fds[write_fd] = thread::FdKind::PipeWrite(pipe_idx);

    if flags & O_CLOEXEC != 0 {
        kt.cloexec |= (1 << read_fd) | (1 << write_fd);
    }

    kt.vcpu.write::<i32>(pipefd_ptr, read_fd as i32);
    kt.vcpu.write::<i32>(pipefd_ptr + 4, write_fd as i32);
    SyscallResult::val(0)
}

/// dup2(63)
fn sys_dup2(kt: &mut thread::KernelThread, a: &Args) -> SyscallResult {
    let oldfd = a.a0 as usize;
    let newfd = a.a1 as usize;

    if oldfd >= thread::MAX_FDS || newfd >= thread::MAX_FDS {
        return SyscallResult::val(-EBADF);
    }

    if kt.fds[oldfd].is_none() { return SyscallResult::val(-EBADF); }

    if oldfd == newfd { return SyscallResult::val(newfd as i32); }

    if !kt.fds[newfd].is_none() {
        kt.close_fd(newfd);
    }

    let kind = kt.fds[oldfd];
    match kind {
        thread::FdKind::Vfs(handle) => vfs::add_vfs_ref(handle),
        thread::FdKind::PipeRead(idx) => crate::kernel::kpipe::add_reader(idx),
        thread::FdKind::PipeWrite(idx) => crate::kernel::kpipe::add_writer(idx),
        thread::FdKind::ConsoleOut | thread::FdKind::None | thread::FdKind::Dir(_) => {}
    }
    kt.fds[newfd] = kind;
    kt.cloexec &= !(1 << newfd);

    SyscallResult::val(newfd as i32)
}
