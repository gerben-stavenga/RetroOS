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

use crate::kernel::elf;
use crate::kernel::stacktrace::SymbolData;
use crate::kernel::thread;
use crate::kernel::thread::{FdKind, PendingRead, PendingPoll, MAX_FDS};
use crate::kernel::vfs;
use crate::vga;
use crate::Regs;
use crate::println;

// =============================================================================
// errno constants (positive values; returned as negative)
// =============================================================================

const ENOENT: i32 = 2;
const ESRCH: i32 = 3;
const ENOEXEC: i32 = 8;
const EBADF: i32 = 9;
const ENOTSOCK: i32 = 88;
const EMFILE: i32 = 24;
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
/// Gated on `vga_present()`: a no-op when there is no passthrough VGA card —
/// the interpreter backend (console goes to stdout) and UEFI-class metal alike.
pub fn save_console_vga() {
    unsafe {
        if !crate::kernel::dos::vga_present() {
            return; // no card (interp / UEFI metal): nothing to snapshot
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

impl Default for LinuxState {
    fn default() -> Self {
        Self::new()
    }
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
    pub fn suspend<A: crate::Arch>(&mut self, _machine: &mut A) {
        save_console_vga();
    }

    /// Called when a Linux thread regains focus. Repaints the shared
    /// console from the suspend snapshot. CPU-binding side effects (TLS,
    /// deferred wait_status writeout) live in `on_resume` and happen on
    /// every swap-in.
    pub fn materialize<A: crate::Arch>(&mut self, _machine: &mut A) {
        restore_console_vga();
    }

    /// Called on every swap-in (whether or not we're refocusing): rebind
    /// per-thread CPU state and finalize a deferred wait4 status write.
    pub fn on_resume<A: crate::Arch>(&mut self, machine: &mut A) {
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
    pub fn process_key<A: crate::Arch>(&self, _machine: &mut A, fds: &[FdKind; MAX_FDS], scancode: u8) {
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

/// Syscall result: return value + optional switch target.
///
/// `action`, when set, is a lifecycle action (fork/exec/wait/yield/exit) the
/// loop's executor runs *after* this handler's `kt` borrow is released — so a
/// handler never mutates the thread table under its own borrow. It takes
/// precedence over `switch_to`. This brings the Linux dispatch up to the same
/// expressiveness the DOS handlers already have (they return `KernelAction`
/// directly).
pub struct SyscallResult {
    pub retval: i64,
    pub switch_to: Option<usize>,
    pub action: Option<thread::KernelAction>,
}

impl SyscallResult {
    fn val(v: i32) -> Self { Self { retval: v as i64, switch_to: None, action: None } }
    fn val64(v: i64) -> Self { Self { retval: v, switch_to: None, action: None } }
    /// Return `retval` and hand the loop a lifecycle action to execute.
    fn act(retval: i64, action: thread::KernelAction) -> Self {
        Self { retval, switch_to: None, action: Some(action) }
    }
}

/// Single entry point the event loop calls for the Linux personality.
/// Handles syscalls (INT 0x80) and treats other CPU events as fatal.
/// `PageFault` is excluded — the loop handles it inline.
pub fn handle_event<A: crate::Arch>(
    machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    linux: &mut LinuxState,
    regs: &mut Regs,
    kevent: crate::KernelEvent,
) -> thread::KernelAction {
    use crate::KernelEvent as KE;
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

/// Complete a blocked thread's pending pipe read or poll, making it Ready
/// when data arrived. Called from the event loop slice (the thread is not
/// running; `regs` is its live frame).
pub fn complete_pending_io<A: crate::Arch>(machine: &mut A, 
    kt: &mut thread::KernelThread<A>,
    linux: &mut LinuxState,
    regs: &mut Regs,
) {
    if let Some(ref pr) = linux.pending_read {
        if let thread::FdKind::PipeRead(idx) = pr.fd_kind {
            let (buf_ptr, buf_len) = (pr.buf_ptr, pr.buf_len);
            // buf_ptr is a GUEST virtual address — write through the
            // guest-memory API (the blocked thread stayed the running tid, so
            // its space is the active one). Deref'ing it as a host pointer
            // worked on metal (ring-1 shares the space) but scribbled the
            // host heap on the hosted backends — dash, which blocks inside
            // read() (busybox polls first), was the reproducer.
            let mut tmp = alloc::vec![0u8; buf_len];
            let n = crate::kernel::kpipe::read(idx, &mut tmp);
            if n > 0 {
                machine.copy_to(buf_ptr, &tmp[..n]);
                regs.rax = n as u64;
                linux.pending_read = None;
                kt.state = thread::ThreadState::Ready;
            }
        }
    } else if let Some(ref pp) = linux.pending_poll {
        let ready = run_poll(machine, kt, pp.fds_ptr, pp.nfds);
        if ready > 0 {
            regs.rax = ready as u64;
            linux.pending_poll = None;
            kt.state = thread::ThreadState::Ready;
        }
    }
}

/// Dispatch returning KernelAction.
pub fn dispatch_action<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, linux: &mut LinuxState, regs: &mut Regs) -> thread::KernelAction {
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
    // A lifecycle action (if the handler asked for one) is executed by the loop
    // after this borrow releases; it wins over a plain switch.
    if let Some(action) = result.action {
        return action;
    }
    match result.switch_to {
        Some(next) => thread::KernelAction::Switch(next),
        None => thread::KernelAction::Done,
    }
}

fn dispatch_nr<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, linux: &mut LinuxState, nr: u32, a: &Args, regs: &mut Regs) -> SyscallResult {
    let tid = kt.tid as usize;
    match nr {
        1   => sys_exit(machine, tid, a),
        2   => sys_fork(machine, kt, linux, a, regs),
        3   => sys_read(machine, kt, linux, a, regs),
        7   => sys_wait4(machine, kt, a, regs),
        4   => sys_write(machine, kt, a),
        5   => sys_open(machine, kt, linux, a),
        6   => sys_close(kt, a),
        11  => sys_execve(machine, kt, linux, a, regs),
        12  => sys_chdir(machine, &mut kt.vcpu, linux, a),
        13  => sys_time(machine, &mut kt.vcpu, a),
        19  => sys_lseek(kt, a),
        20  => SyscallResult::val(kt.tid),
        // getuid/geteuid/getgid/getegid (16-bit uid variants) — pretend root.
        24 | 49 | 47 | 50 => SyscallResult::val(0),
        // getppid: real parent if we have one, else 1 (init).
        64  => SyscallResult::val(kt.parent_tid.max(1)),
        // getuid32/getgid32/geteuid32/getegid32 — pretend root.
        199..=201 => SyscallResult::val(0),
        202 => sys_futex(machine, kt, a),
        // setuid32/setgid32/setreuid32/setregid32/setresuid32/setresgid32 —
        // single-user system, accept any change as a no-op.
        203 | 204 | 208 | 210 | 213 | 214 => SyscallResult::val(0),
        // setpgid(57)/getpgid(132)/setsid(66)/getpgrp(65)/getsid(147) —
        // single-process job model, return our tid as session/group.
        57 | 66 | 65 | 132 | 147 => SyscallResult::val(kt.tid),
        33  => sys_access(machine, &mut kt.vcpu, linux, a),
        42  => sys_pipe(machine, kt, a, false),
        45  => sys_brk(linux, a),
        54  => sys_ioctl(machine, kt, a),
        180 => sys_pread64(machine, kt, a),
        55  => sys_fcntl(kt, a),
        63  => sys_dup2(kt, a),
        85  => sys_readlink(machine, &mut kt.vcpu, a),
        // Old i386 struct stat — 64-byte layout. busybox/uclibc still uses
        // these and falls back from stat64; without them mode comes back
        // zero and access(X_OK) reports "Permission denied".
        106 => sys_stat_old(machine, &mut kt.vcpu, linux, a),
        107 => sys_stat_old(machine, &mut kt.vcpu, linux, a), // lstat — no symlinks, treat as stat
        108 => sys_fstat_old(machine, kt, a),
        91  => sys_munmap(linux, a),
        114 => sys_wait4(machine, kt, a, regs),
        120 => sys_clone(machine, kt, linux, a, regs),
        190 => sys_fork(machine, kt, linux, a, regs), // vfork → COW fork
        122 => sys_uname(machine, &mut kt.vcpu, a, false),
        125 => SyscallResult::val(0),
        140 => sys_llseek(machine, kt, a),
        146 => sys_writev(machine, kt, a, false),
        158 => sys_sched_yield(kt, regs),
        162 => sys_nanosleep(),
        168 => sys_poll(machine, kt, linux, a, regs),
        174 => SyscallResult::val(0),
        175 => SyscallResult::val(0),
        183 => sys_getcwd(machine, &mut kt.vcpu, linux, a),
        186 => SyscallResult::val(0),
        192 => sys_mmap2(machine, kt, linux, a, (a.a5 as usize) << 12), // mmap2: offset in 4K pages
        195 => sys_stat64(machine, &mut kt.vcpu, linux, a, false),
        196 => sys_stat64(machine, &mut kt.vcpu, linux, a, false),
        197 => sys_fstat64(machine, kt, a, false),
        220 => sys_getdents64(machine, kt, linux, a),
        221 => sys_fcntl(kt, a),
        238 => sys_exit(machine, tid, a),
        240 => SyscallResult::val(0),
        243 => sys_set_thread_area(machine, kt, linux, a),
        252 => sys_exit(machine, tid, a),
        258 => SyscallResult::val(kt.tid),
        265 => sys_clock_gettime(machine, &mut kt.vcpu, a),
        270 => sys_exit(machine, tid, a),
        295 => sys_openat(machine, kt, linux, a),
        300 => sys_fstatat64(machine, kt, linux, a, false),
        305 => SyscallResult::val(-ENOENT),
        331 => sys_pipe(machine, kt, a, true),
        340 => SyscallResult::val(0),
        355 => sys_getrandom(machine, &mut kt.vcpu, a),
        102 => sys_socketcall(machine, kt, a),
        _ => {
            println!("unimplemented syscall {}", nr);
            SyscallResult::val(-ENOSYS)
        }
    }
}

/// x86_64 syscall number table (different numbers, same implementations)
fn dispatch_nr_64<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, linux: &mut LinuxState, nr: u32, a: &Args, regs: &mut Regs) -> SyscallResult {
    let tid = kt.tid as usize;
    match nr {
        0   => sys_read(machine, kt, linux, a, regs),
        1   => sys_write(machine, kt, a),
        2   => sys_open(machine, kt, linux, a),
        3   => sys_close(kt, a),
        4   => sys_stat64(machine, &mut kt.vcpu, linux, a, true),
        5   => sys_fstat64(machine, kt, a, true),
        6   => sys_stat64(machine, &mut kt.vcpu, linux, a, true),
        7   => sys_poll(machine, kt, linux, a, regs),
        8   => sys_lseek(kt, a),
        9   => sys_mmap2(machine, kt, linux, a, a.a5 as usize), // mmap: offset in bytes
        10  => SyscallResult::val(0),
        11  => sys_munmap(linux, a),
        12  => sys_brk(linux, a),
        13  => SyscallResult::val(0),
        14  => SyscallResult::val(0),
        16  => sys_ioctl(machine, kt, a),
        17  => sys_pread64(machine, kt, a),
        20  => sys_writev(machine, kt, a, true),
        21  => sys_access(machine, &mut kt.vcpu, linux, a),
        22  => sys_pipe(machine, kt, a, false),
        24  => sys_sched_yield(kt, regs),
        25  => sys_mremap(machine, linux, a),
        // statfs(137): -ENOSYS — callers fall back. fadvise64(221): advisory.
        137 => SyscallResult::val(-ENOSYS),
        332 => sys_statx(machine, kt, linux, a),
        221 => SyscallResult::val(0),
        33  => sys_dup2(kt, a),
        35  => sys_nanosleep(),
        39  => SyscallResult::val(kt.tid),
        56  => sys_clone(machine, kt, linux, a, regs),
        57  => sys_fork(machine, kt, linux, a, regs),
        // vfork: alias to a COW fork. Real vfork suspends the parent and shares
        // memory until the child execs/exits, but the child execs immediately
        // (dash's vfork+execve+waitpid), so a plain fork is observably the same.
        58  => sys_fork(machine, kt, linux, a, regs),
        59  => sys_execve(machine, kt, linux, a, regs),
        60  => sys_exit(machine, tid, a),
        61  => sys_wait4(machine, kt, a, regs),
        63  => sys_uname(machine, &mut kt.vcpu, a, true),
        72  => sys_fcntl(kt, a),
        79  => sys_getcwd(machine, &mut kt.vcpu, linux, a),
        80  => sys_chdir(machine, &mut kt.vcpu, linux, a),
        89  => SyscallResult::val(-ENOENT),
        96  => sys_clock_gettime(machine, &mut kt.vcpu, a),
        102 | 104 | 107 | 108 => SyscallResult::val(0),
        110 => SyscallResult::val(kt.tid),
        // setpgid(109)/getpgrp(111)/setsid(112)/getpgid(121)/getsid(124):
        // single-process job model — return our tid as group/session (mirrors
        // the i386 path) so dash's job-control setup converges (getpgrp ==
        // tcgetpgrp) instead of spinning on getpgrp/kill.
        109 | 111 | 112 | 121 | 124 => SyscallResult::val(kt.tid),
        62  => SyscallResult::val(0), // kill — no-op (no real job control)
        131 => SyscallResult::val(0),
        158 => sys_arch_prctl(machine, kt, linux, a, regs),
        200 => sys_exit(machine, tid, a),
        201 => sys_time(machine, &mut kt.vcpu, a),
        202 => sys_futex(machine, kt, a),
        217 => sys_getdents64(machine, kt, linux, a),
        218 => SyscallResult::val(kt.tid),
        228 => sys_clock_gettime(machine, &mut kt.vcpu, a),
        231 => sys_exit(machine, tid, a),
        234 => sys_exit(machine, tid, a),
        257 => sys_openat(machine, kt, linux, a),
        262 => sys_fstatat64(machine, kt, linux, a, true),
        267 => SyscallResult::val(-ENOENT),
        269 => sys_faccessat(machine, linux, a),
        273 => SyscallResult::val(0),       // set_robust_list — no threads share
        293 => sys_pipe(machine, kt, a, true),
        334 => SyscallResult::val(-ENOSYS), // rseq — glibc falls back cleanly
        439 => sys_faccessat(machine, linux, a),
        302 => SyscallResult::val(0),
        318 => sys_getrandom(machine, &mut kt.vcpu, a),
        // Sockets (x86-64 direct numbering).
        41  => sys_socket(kt, a.a0, a.a1, a.a2),
        42  => sys_connect(machine, kt, a.a0, a.a1 as usize, a.a2 as usize),
        43  => sys_accept(machine, kt, a.a0, a.a1 as usize, a.a2 as usize),
        44  => sys_sendto(machine, kt, a.a0, a.a1 as usize, a.a2 as usize, a.a3, a.a4 as usize, a.a5 as usize),
        45  => sys_recvfrom(machine, kt, a.a0, a.a1 as usize, a.a2 as usize, a.a3, a.a4 as usize, a.a5 as usize),
        48  => sys_shutdown(kt, a.a0, a.a1),
        49  => sys_bind(machine, kt, a.a0, a.a1 as usize, a.a2 as usize),
        50  => sys_listen(kt, a.a0, a.a1),
        51  => sys_getsockname(machine, kt, a.a0, a.a1 as usize, a.a2 as usize, false),
        52  => sys_getsockname(machine, kt, a.a0, a.a1 as usize, a.a2 as usize, true),
        54  => sys_setsockopt(machine, kt, a.a0, a.a1, a.a2, a.a3 as usize, a.a4 as usize),
        55  => SyscallResult::val(0), // getsockopt — report success (SO_ERROR = 0)
        288 => sys_accept(machine, kt, a.a0, a.a1 as usize, a.a2 as usize), // accept4
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
    if pos > 0 && new_cwd[pos - 1] != b'/'
        && pos < new_cwd.len() { new_cwd[pos] = b'/'; pos += 1; }
    let prefix = &new_cwd[..pos];
    if !vfs::dir_exists(prefix) { return -ENOENT; }
    let len = pos.min(cwd.len());
    cwd[..len].copy_from_slice(&new_cwd[..len]);
    *cwd_len = len;
    0
}

/// Check if path ends with ".EXT" (case-insensitive, 3-letter extension).
/// Read a C `char**` (NULL-terminated) from 32-bit user memory into Vec<Vec<u8>>.
fn read_c_argv<A: crate::Arch>(machine: &mut A, ptr: usize, wide: bool) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
    let mut args = alloc::vec::Vec::new();
    if ptr == 0 { return args; }
    let mut offset = 0usize;
    loop {
        let arg_ptr = if wide {
            machine.read::<u64>(ptr + offset) as usize
        } else {
            machine.read::<u32>(ptr + offset) as usize
        };
        if arg_ptr == 0 { break; }
        let mut arg_buf = alloc::vec![0u8; 4096];
        let arg_len = machine.copy_cstr(arg_ptr, &mut arg_buf);
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
pub(crate) fn setup_user_stack<A: crate::Arch>(machine: &mut A, _vcpu: &mut Regs, args: &[alloc::vec::Vec<u8>], want_64: bool, extra_auxv: &[(usize, usize)]) -> usize {
    // Write one machine word (4 or 8 bytes, per client bitness) to the stack.
    fn write_word<A: crate::Arch>(machine: &mut A, addr: usize, val: usize, want_64: bool) {
        if want_64 { machine.write::<u64>(addr, val as u64); }
        else { machine.write::<u32>(addr, val as u32); }
    }

    let stack_top = elf::USER_STACK_TOP;
    let word = if want_64 { 8usize } else { 4 };
    let mut sp = stack_top;

    // 1. Write NUL-terminated string data at top of stack
    // Environment strings first (they end up at higher addresses)
    let env_strings: &[&[u8]] = &[b"PATH=/usr/bin:/bin:/usr/sbin:/sbin", b"HOME=/", b"TERM=linux"];
    let mut env_addrs: alloc::vec::Vec<usize> = alloc::vec::Vec::with_capacity(env_strings.len());
    for &env in env_strings.iter().rev() {
        sp -= env.len() + 1;
        machine.copy_to(sp, env);
        machine.write::<u8>(sp + env.len(), 0);
        env_addrs.push(sp);
    }
    env_addrs.reverse();

    // Argv strings
    let mut string_addrs: alloc::vec::Vec<usize> = alloc::vec::Vec::with_capacity(args.len());
    for arg in args.iter().rev() {
        sp -= arg.len() + 1; // +1 for NUL
        machine.copy_to(sp, arg);
        machine.write::<u8>(sp + arg.len(), 0); // NUL terminator
        string_addrs.push(sp);
    }
    string_addrs.reverse();

    // 2. Write 16 bytes of "random" data for AT_RANDOM
    sp &= !(word - 1); // align
    sp -= 16;
    let random_addr = sp;
    for i in 0..4 {
        machine.write::<u32>(sp + i * 4, thread::prng() as u32);
    }

    // 3. Build the auxiliary vector. The caller supplies the dynamic-linker
    // entries (AT_PHDR/PHENT/PHNUM/BASE/ENTRY + the id/cap tags) in
    // `extra_auxv`; we append the ones needing stack-internal addresses
    // (AT_PAGESZ, AT_RANDOM, AT_EXECFN) and the AT_NULL terminator. A static
    // exec passes `&[]`, preserving the minimal PAGESZ/RANDOM vector.
    let mut auxv: alloc::vec::Vec<(usize, usize)> = alloc::vec::Vec::new();
    auxv.extend_from_slice(extra_auxv);
    auxv.push((6, 4096));         // AT_PAGESZ
    auxv.push((25, random_addr)); // AT_RANDOM
    if let Some(&a0) = string_addrs.first() {
        auxv.push((31, a0));      // AT_EXECFN — argv[0] string
    }
    auxv.push((0, 0));            // AT_NULL terminator

    // 4. Compute total header size and align.
    // Layout from sp downward: argc, argv[0..N], NULL, envp[0..M], NULL, auxv.
    let header_words = 1 /*argc*/ + args.len() + 1 /*NULL*/
        + env_addrs.len() + 1 /*envp NULL*/
        + auxv.len() * 2;
    sp -= header_words * word;
    sp &= !0xF; // 16-byte align

    let base = sp;
    let mut pos = base;

    // argc
    write_word(machine, pos, args.len(), want_64);
    pos += word;
    // argv[0..N-1], NULL
    for &addr in &string_addrs {
        write_word(machine, pos, addr, want_64);
        pos += word;
    }
    write_word(machine, pos, 0, want_64);
    pos += word;
    // envp[0..M-1], NULL
    for &addr in &env_addrs {
        write_word(machine, pos, addr, want_64);
        pos += word;
    }
    write_word(machine, pos, 0, want_64);
    pos += word;
    // auxv (terminated by the AT_NULL already pushed)
    for (tag, val) in auxv {
        write_word(machine, pos, tag, want_64);
        write_word(machine, pos + word, val, want_64);
        pos += word * 2;
    }

    base // return sp
}

// =============================================================================
// ELF exec — called from kernel exec fan-out
// =============================================================================

/// Load an ELF binary into the current address space and initialize the thread.
/// Caller must have already cleaned/prepared the address space.
pub fn exec_elf_into<A: crate::Arch>(machine: &mut A, threads: &mut [thread::Thread<A>], tid: usize, data: &[u8], path: &[u8], args: &[alloc::vec::Vec<u8>]) -> Result<(), i32> {
    // PIE main + dynamic linker load bases. Kept in the low user region
    // (< USER_STACK_TOP) so they don't need the high 64-bit VA range; ld.so
    // mmaps the shared libraries between these and the stack.
    const PIE_BASE: usize = 0x0800_0000;     // 128 MiB — main PIE load bias
    const INTERP_BASE: usize = 0x4000_0000;  // 1 GiB — dynamic-linker load bias

    // Refuse a 64-bit image the backend can't execute (ENOEXEC) — running
    // x86-64 code misdecoded as i386 is never useful. execve pre-checks this
    // before its point of no return; this catches direct/boot launches.
    if elf::is_class64(data) && !machine.user_64_supported() {
        return Err(ENOEXEC);
    }

    // Peek dynamic info before loading so we know whether to apply a bias and
    // whether to bring in the interpreter.
    let (is_pie, interp_path) = elf::dyn_info(data).map_err(|_| 8)?;

    let current = thread::get_thread(threads, tid).unwrap();

    // Dynamically-linked PIE → load at PIE_BASE; fixed ET_EXEC (and static
    // ET_DYN, which we keep at bias 0 as before) → no bias.
    let main_bias = if is_pie && interp_path.is_some() { PIE_BASE } else { 0 };
    let loaded = elf::load_elf(machine, data, main_bias).map_err(|_| 8)?;
    let want_64 = loaded.class == elf::ElfClass::Elf64;

    // Dynamic: load the interpreter (ld.so) at INTERP_BASE and build the full
    // auxv so it can self-relocate, relocate the program, and load its libs.
    // ld.so runs first, so the CPU entry is the interpreter's. Static: jump
    // straight to the program entry with a minimal auxv.
    let (cpu_entry, extra_auxv): (u64, alloc::vec::Vec<(usize, usize)>) = if let Some(ip) = &interp_path {
        // PT_INTERP is an absolute path in the (unified) root filesystem, e.g.
        // "/lib64/ld-linux-x86-64.so.2" → VFS "lib64/ld-linux-x86-64.so.2".
        let mut s: &[u8] = ip;
        while s.first() == Some(&b'/') { s = &s[1..]; }
        let interp_data = crate::kernel::exec::load_file_resolved(s).map_err(|_| 8)?;
        let interp_loaded = elf::load_elf(machine, &interp_data, INTERP_BASE).map_err(|_| 8)?;
        let aux = alloc::vec![
            (3usize, loaded.phdr_vaddr),  // AT_PHDR
            (4, loaded.phentsize),        // AT_PHENT
            (5, loaded.phnum),            // AT_PHNUM
            (7, INTERP_BASE),             // AT_BASE — dynamic-linker load base
            (9, loaded.entry as usize),   // AT_ENTRY — program entry (biased)
            (16, 0),                      // AT_HWCAP
            (17, 100),                    // AT_CLKTCK
            (23, 0),                      // AT_SECURE
            (11, 0), (12, 0), (13, 0), (14, 0), // AT_UID/EUID/GID/EGID
        ];
        (interp_loaded.entry, aux)
    } else {
        (loaded.entry, alloc::vec::Vec::new())
    };

    let symbols = SymbolData::new(alloc::vec::Vec::from(data).into_boxed_slice());

    let sp = setup_user_stack(machine, &mut current.kernel.vcpu, args, want_64, &extra_auxv);
    if want_64 {
        thread::init_process_thread_64(current, cpu_entry, sp as u64);
    } else {
        thread::init_process_thread(current, cpu_entry as u32, sp as u32);
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
fn sys_exit<A: crate::Arch>(_machine: &mut A, _tid: usize, a: &Args) -> SyscallResult {
    let code = a.a0 as i32;
    // exit_thread (zombie slot + parent wake + cleanup) runs in the executor's
    // Exit arm, after the kt borrow releases — not inline under it.
    SyscallResult::act(0, thread::KernelAction::Exit(code))
}

/// fork(2) — return a Fork action; `handle_fork` does the COW clone in the
/// executor after the kt borrow releases.
fn sys_fork<A: crate::Arch>(_machine: &mut A, _kt: &mut thread::KernelThread<A>, _linux: &mut LinuxState, _a: &Args, _regs: &mut Regs) -> SyscallResult {
    SyscallResult::act(0, thread::KernelAction::Fork { on_done: fork_set_retval, child_stack: 0 })
}

/// clone(120) — always COW fork, with optional child_stack override (a.a1).
fn sys_clone<A: crate::Arch>(_machine: &mut A, _kt: &mut thread::KernelThread<A>, _linux: &mut LinuxState, a: &Args, _regs: &mut Regs) -> SyscallResult {
    SyscallResult::act(0, thread::KernelAction::Fork { on_done: fork_set_retval, child_stack: a.a1 as usize })
}

/// Write a fork/clone return value (child tid, or -errno) into the parent's
/// live frame — the `Fork` action's `on_done` callback.
fn fork_set_retval(regs: &mut Regs, ret: i32) {
    regs.rax = ret as i64 as u64;
}

/// Executor for `KernelAction::Fork`: COW-clone the current process. Runs in
/// the event loop after the handler's `kt`/`linux` borrow released, so it can
/// hold both the parent and the new child slot at once. `vcpu` is the live
/// (parent) frame. Returns the child tid to switch to (child runs first), or
/// None on failure (stay on the parent).
pub(crate) fn handle_fork<A: crate::Arch>(
    machine: &mut A,
    threads: &mut [thread::Thread<A>],
    vcpu: &mut Regs,
    parent_tid: usize,
    child_stack: usize,
    on_done: fn(&mut Regs, i32),
) -> Option<usize> {
    let mut child_root = A::PageTable::default();
    machine.user_fork(&mut child_root);

    let child_tid = match thread::create_thread(threads, machine, Some(parent_tid), child_root, true) {
        Some(t) => t.kernel.tid as usize,
        None => { on_done(vcpu, -ENOMEM); return None; }
    };

    let (parent, child) = thread::get_two_threads(threads, parent_tid, child_tid);

    // Child resumes at the parent's fork() call site, returning 0.
    child.kernel.vcpu.regs = *vcpu;
    child.kernel.vcpu.regs.rax = 0;
    if child_stack != 0 {
        child.kernel.vcpu.regs.frame.rsp = child_stack as u64;
    }

    parent.kernel.dup_all_fds(&mut child.kernel);
    if let (thread::Personality::Linux(pl), thread::Personality::Linux(cl)) =
        (&parent.personality, &mut child.personality)
    {
        cl.heap_base = pl.heap_base;
        cl.heap_end = pl.heap_end;
        cl.mmap_cursor = pl.mmap_cursor;
        cl.tls_entry = pl.tls_entry;
        cl.tls_base = pl.tls_base;
        cl.tls_limit = pl.tls_limit;
        cl.tls_limit_in_pages = pl.tls_limit_in_pages;
        cl.cwd = pl.cwd;
        cl.cwd_len = pl.cwd_len;
    }

    parent.kernel.state = thread::ThreadState::Ready;
    on_done(vcpu, child_tid as i32);
    Some(child_tid)
}

/// read(3)
fn sys_read<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, linux: &mut LinuxState, a: &Args, regs: &mut Regs) -> SyscallResult {
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
                machine.copy_to(buf, &tmp[..n as usize]);
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
            SyscallResult { retval: 0, switch_to: None, action: None }
        }
        thread::FdKind::Vfs(handle) => {
            let mut tmp = alloc::vec![0u8; len];
            let n = vfs::read_by_handle(handle, &mut tmp);
            if n > 0 { machine.copy_to(buf, &tmp[..n as usize]); }
            SyscallResult::val(n)
        }
        thread::FdKind::Socket(h) => {
            // read() on a socket == recv() with no flags. Blocking (host
            // socket blocks the kernel thread) — fine for a single client.
            let mut tmp = alloc::vec![0u8; len];
            let n = crate::kernel::net::recvfrom(h, &mut tmp, 0, &mut []);
            if n > 0 { machine.copy_to(buf, &tmp[..n as usize]); }
            SyscallResult::val(n)
        }
        thread::FdKind::ConsoleOut | thread::FdKind::PipeWrite(_) | thread::FdKind::Dir { .. } => {
            SyscallResult::val(-EBADF)
        }
        thread::FdKind::None => SyscallResult::val(-EBADF),
    }
}

/// write(4)
fn sys_write<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    let buf = a.a1 as usize;
    let len = a.a2 as usize;

    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    let fd_kind = kt.fds[fd];

    match fd_kind {
        thread::FdKind::ConsoleOut => {
            let mut tmp = alloc::vec![0u8; len];
            machine.copy_from(buf, &mut tmp);
            for &b in &tmp {
                vga::putchar(b);
            }
            SyscallResult::val(len as i32)
        }
        thread::FdKind::PipeWrite(idx) => {
            let mut tmp = alloc::vec![0u8; len];
            machine.copy_from(buf, &mut tmp);
            let r = crate::kernel::kpipe::write(idx, &tmp);
            if r < 0 {
                SyscallResult::val(-EPIPE)
            } else {
                SyscallResult::val(r)
            }
        }
        thread::FdKind::Vfs(handle) => {
            let mut tmp = alloc::vec![0u8; len];
            machine.copy_from(buf, &mut tmp);
            SyscallResult::val(vfs::write_by_handle(machine, handle, &tmp))
        }
        thread::FdKind::Socket(h) => {
            // write() on a socket == send() with no flags.
            let mut tmp = alloc::vec![0u8; len];
            machine.copy_from(buf, &mut tmp);
            SyscallResult::val(crate::kernel::net::sendto(h, &tmp, 0, &[]))
        }
        thread::FdKind::PipeRead(_) | thread::FdKind::None | thread::FdKind::Dir { .. } => {
            SyscallResult::val(-EBADF)
        }
    }
}

/// open(5)
fn sys_open<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, linux: &LinuxState, a: &Args) -> SyscallResult {
    let path_ptr = a.a0 as usize;
    let mut path_buf = [0u8; 256];
    let path_len = machine.copy_cstr(path_ptr, &mut path_buf);
    let path = &path_buf[..path_len];

    let mut buf = [0u8; 164];
    let resolved = resolve_path(path, linux.cwd_str(), &mut buf);

    // Directories: the fd records WHICH directory was opened (dir-handle
    // table) so getdents64 lists it — `ls /path` opens an fd on /path.
    if vfs::dir_exists(resolved) {
        return match kt.alloc_fd(3) {
            Some(fd) => {
                let handle = vfs::open_dir_handle(resolved);
                if handle < 0 {
                    return SyscallResult::val(handle); // EMFILE
                }
                kt.fds[fd] = thread::FdKind::Dir { handle, next: 0 };
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
fn sys_close<A: crate::Arch>(kt: &mut thread::KernelThread<A>, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    if kt.fds[fd].is_none() { return SyscallResult::val(-EBADF); }
    kt.close_fd(fd);
    SyscallResult::val(0)
}

// =============================================================================
// Sockets — the injected socket layer (hosted std::net punch-through).
//
// Blocking is acceptable for this slice: a host socket call blocks the kernel
// thread, which is fine for a single-threaded client (wget/curl). TODO:
// non-blocking + integrate with the event loop's PendingPoll so concurrent
// guests don't stall each other.
// =============================================================================

use crate::kernel::net;

/// The i386 `socketcall(2)` multiplexer (nr 102): `a0` = subcall, `a1` = a
/// pointer to a packed array of native-word (32-bit here) arguments. x86-64
/// reaches the same shared handlers via direct syscalls.
fn sys_socketcall<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, a: &Args) -> SyscallResult {
    let call = a.a0 as u32;
    let argp = a.a1 as usize;
    let mut raw = [0u8; 24]; // up to 6 u32 args
    machine.copy_from(argp, &mut raw);
    let g = |i: usize| u32::from_le_bytes([raw[i*4], raw[i*4+1], raw[i*4+2], raw[i*4+3]]) as u64;
    match call {
        1  => sys_socket(kt, g(0), g(1), g(2)),
        2  => sys_bind(machine, kt, g(0), g(1) as usize, g(2) as usize),
        3  => sys_connect(machine, kt, g(0), g(1) as usize, g(2) as usize),
        4  => sys_listen(kt, g(0), g(1)),
        5  => sys_accept(machine, kt, g(0), g(1) as usize, g(2) as usize),
        6  => sys_getsockname(machine, kt, g(0), g(1) as usize, g(2) as usize, false),
        7  => sys_getsockname(machine, kt, g(0), g(1) as usize, g(2) as usize, true),
        9  => sys_sendto(machine, kt, g(0), g(1) as usize, g(2) as usize, g(3), 0, 0),
        10 => sys_recvfrom(machine, kt, g(0), g(1) as usize, g(2) as usize, g(3), 0, 0),
        11 => sys_sendto(machine, kt, g(0), g(1) as usize, g(2) as usize, g(3), g(4) as usize, g(5) as usize),
        12 => sys_recvfrom(machine, kt, g(0), g(1) as usize, g(2) as usize, g(3), g(4) as usize, g(5) as usize),
        13 => sys_shutdown(kt, g(0), g(1)),
        14 => sys_setsockopt(machine, kt, g(0), g(1), g(2), g(3) as usize, g(4) as usize),
        15 => SyscallResult::val(0), // getsockopt — report success (SO_ERROR = 0)
        18 => sys_accept(machine, kt, g(0), g(1) as usize, g(2) as usize), // accept4
        _  => SyscallResult::val(-ENOSYS),
    }
}

/// Resolve an fd to its backend socket handle.
fn sock_handle<A: crate::Arch>(kt: &thread::KernelThread<A>, fd: u64) -> Result<i32, i32> {
    let fd = fd as usize;
    if fd >= thread::MAX_FDS { return Err(-EBADF); }
    match kt.fds[fd] {
        thread::FdKind::Socket(h) => Ok(h),
        thread::FdKind::None => Err(-EBADF),
        _ => Err(-ENOTSOCK),
    }
}

/// Copy a `sockaddr` of `len` bytes from guest memory (capped).
fn read_sockaddr<A: crate::Arch>(machine: &mut A, ptr: usize, len: usize) -> ([u8; 128], usize) {
    let n = len.min(128);
    let mut addr = [0u8; 128];
    if ptr != 0 && n > 0 { machine.copy_from(ptr, &mut addr[..n]); }
    (addr, n)
}

fn sys_socket<A: crate::Arch>(kt: &mut thread::KernelThread<A>, domain: u64, ty: u64, proto: u64) -> SyscallResult {
    let h = net::socket(domain as i32, ty as i32, proto as i32);
    if h < 0 { return SyscallResult::val(h); }
    match kt.alloc_fd(3) {
        Some(fd) => { kt.fds[fd] = thread::FdKind::Socket(h); SyscallResult::val(fd as i32) }
        None => { net::close(h); SyscallResult::val(-EMFILE) }
    }
}

fn sys_connect<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, fd: u64, addr_ptr: usize, addr_len: usize) -> SyscallResult {
    let h = match sock_handle(kt, fd) { Ok(h) => h, Err(e) => return SyscallResult::val(e) };
    let (addr, n) = read_sockaddr(machine, addr_ptr, addr_len);
    SyscallResult::val(net::connect(h, &addr[..n]))
}

fn sys_bind<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, fd: u64, addr_ptr: usize, addr_len: usize) -> SyscallResult {
    let h = match sock_handle(kt, fd) { Ok(h) => h, Err(e) => return SyscallResult::val(e) };
    let (addr, n) = read_sockaddr(machine, addr_ptr, addr_len);
    SyscallResult::val(net::bind(h, &addr[..n]))
}

fn sys_listen<A: crate::Arch>(kt: &mut thread::KernelThread<A>, fd: u64, backlog: u64) -> SyscallResult {
    let h = match sock_handle(kt, fd) { Ok(h) => h, Err(e) => return SyscallResult::val(e) };
    SyscallResult::val(net::listen(h, backlog as i32))
}

fn sys_accept<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, fd: u64, addr_ptr: usize, addrlen_ptr: usize) -> SyscallResult {
    let h = match sock_handle(kt, fd) { Ok(h) => h, Err(e) => return SyscallResult::val(e) };
    let mut addr = [0u8; 16];
    let nh = net::accept(h, &mut addr);
    if nh < 0 { return SyscallResult::val(nh); }
    write_sockaddr_out(machine, addr_ptr, addrlen_ptr, &addr);
    match kt.alloc_fd(3) {
        Some(newfd) => { kt.fds[newfd] = thread::FdKind::Socket(nh); SyscallResult::val(newfd as i32) }
        None => { net::close(nh); SyscallResult::val(-EMFILE) }
    }
}

#[allow(clippy::too_many_arguments)]
fn sys_sendto<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, fd: u64, buf_ptr: usize, len: usize, flags: u64, addr_ptr: usize, addr_len: usize) -> SyscallResult {
    let h = match sock_handle(kt, fd) { Ok(h) => h, Err(e) => return SyscallResult::val(e) };
    let mut data = alloc::vec![0u8; len];
    machine.copy_from(buf_ptr, &mut data);
    let (addr, n) = read_sockaddr(machine, addr_ptr, addr_len);
    SyscallResult::val(net::sendto(h, &data, flags as i32, &addr[..n]))
}

#[allow(clippy::too_many_arguments)]
fn sys_recvfrom<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, fd: u64, buf_ptr: usize, len: usize, flags: u64, addr_ptr: usize, addrlen_ptr: usize) -> SyscallResult {
    let h = match sock_handle(kt, fd) { Ok(h) => h, Err(e) => return SyscallResult::val(e) };
    let mut data = alloc::vec![0u8; len];
    let mut addr = [0u8; 16];
    let n = net::recvfrom(h, &mut data, flags as i32, &mut addr);
    if n < 0 { return SyscallResult::val(n); }
    machine.copy_to(buf_ptr, &data[..n as usize]);
    write_sockaddr_out(machine, addr_ptr, addrlen_ptr, &addr);
    SyscallResult::val(n)
}

fn sys_setsockopt<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, fd: u64, level: u64, optname: u64, opt_ptr: usize, opt_len: usize) -> SyscallResult {
    let h = match sock_handle(kt, fd) { Ok(h) => h, Err(e) => return SyscallResult::val(e) };
    let (opt, n) = read_sockaddr(machine, opt_ptr, opt_len);
    SyscallResult::val(net::setsockopt(h, level as i32, optname as i32, &opt[..n]))
}

/// `getsockname` (peer=false) / `getpeername` (peer=true).
fn sys_getsockname<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, fd: u64, addr_ptr: usize, addrlen_ptr: usize, peer: bool) -> SyscallResult {
    let h = match sock_handle(kt, fd) { Ok(h) => h, Err(e) => return SyscallResult::val(e) };
    let mut addr = [0u8; 16];
    let r = if peer { net::getpeername(h, &mut addr) } else { net::getsockname(h, &mut addr) };
    if r < 0 { return SyscallResult::val(r); }
    write_sockaddr_out(machine, addr_ptr, addrlen_ptr, &addr);
    SyscallResult::val(0)
}

fn sys_shutdown<A: crate::Arch>(kt: &mut thread::KernelThread<A>, fd: u64, how: u64) -> SyscallResult {
    let h = match sock_handle(kt, fd) { Ok(h) => h, Err(e) => return SyscallResult::val(e) };
    SyscallResult::val(net::shutdown(h, how as i32))
}

/// Write a 16-byte `sockaddr_in` back to the caller's `addr`/`addrlen`
/// out-params (both may be null). `addrlen` is `socklen_t` (32-bit).
fn write_sockaddr_out<A: crate::Arch>(machine: &mut A, addr_ptr: usize, addrlen_ptr: usize, addr: &[u8; 16]) {
    if addr_ptr == 0 || addrlen_ptr == 0 { return; }
    let mut cap = [0u8; 4];
    machine.copy_from(addrlen_ptr, &mut cap);
    let cap = u32::from_le_bytes(cap) as usize;
    let n = cap.min(16);
    machine.copy_to(addr_ptr, &addr[..n]);
    machine.copy_to(addrlen_ptr, &16u32.to_le_bytes());
}

/// execve(11)
fn sys_execve<A: crate::Arch>(machine: &mut A, _kt: &mut thread::KernelThread<A>, linux: &mut LinuxState, a: &Args, regs: &mut Regs) -> SyscallResult {
    use crate::kernel::exec;

    let path_ptr = a.a0 as usize;
    let argv_ptr = a.a1 as usize;
    let _envp_ptr = a.a2 as usize;

    let mut raw_path_buf = [0u8; 256];
    let raw_path_len = machine.copy_cstr(path_ptr, &mut raw_path_buf);
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
    let mut args = read_c_argv(machine, argv_ptr, wide);
    if args.is_empty() { args.push(path.clone()); }

    // Snapshot cwd up front — execve preserves it across the address-space
    // teardown, but `linux` borrows from the thread we're about to clobber.
    let cwd_snapshot: alloc::vec::Vec<u8> = linux.cwd_str().into();

    // Load file (resolves path against cwd)
    let buffer = match exec::load_file(&path, &cwd_snapshot) {
        Ok(b) => b,
        Err(_) => return SyscallResult::val(-ENOENT),
    };

    // A 64-bit ELF on a backend without 64-bit user execution must fail HERE,
    // before the point of no return, so the caller survives and can fall back
    // (shell.elf tries /bin/busybox after /bin/sh).
    if matches!(exec::detect_format(&buffer, &path), exec::BinaryFormat::Elf)
        && crate::kernel::elf::is_class64(&buffer)
        && !machine.user_64_supported()
    {
        return SyscallResult::val(-ENOEXEC);
    }

    // File loaded — hand teardown + rebuild to the executor (`handle_exec`),
    // which runs off this handler's borrow so its in-place
    // init_thread/exit_thread/reg-reload don't alias `kt`. The point of no
    // return (drop symbols, close CLOEXEC, free pages, re-image) is the
    // executor's; until then execve still fails cleanly (the -ENOENT above).
    SyscallResult::act(0, thread::KernelAction::Exec {
        buffer, path, args, cwd: cwd_snapshot,
    })
}

/// Executor for `KernelAction::Exec`: re-image the current process in place.
/// Runs after the syscall handler's borrow releases, so its `get_thread`/
/// `init_thread`/`exit_thread` on `tid` are clean. Returns `None` (stay on the
/// re-imaged thread) or the next tid if the load fails and the thread exits.
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_exec<A: crate::Arch>(
    machine: &mut A,
    threads: &mut [thread::Thread<A>],
    vcpu: &mut Regs,
    tid: usize,
    buffer: alloc::vec::Vec<u8>,
    path: alloc::vec::Vec<u8>,
    args: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    cwd: alloc::vec::Vec<u8>,
) -> Option<usize> {
    use crate::kernel::exec;
    let format = exec::detect_format(&buffer, &path);

    // Point of no return — drop symbols + close CLOEXEC fds.
    {
        let cur = thread::get_thread(threads, tid).unwrap();
        cur.kernel.symbols = None;
        cur.kernel.close_cloexec();
    }

    // ELF address-space prep (DOS handles its own inside exec_dos_into).
    if matches!(format, exec::BinaryFormat::Elf) {
        machine.free_user_pages();
    }

    if exec::init_thread(machine, threads, tid, buffer, &path, args, alloc::vec::Vec::new(), alloc::vec::Vec::new(), cwd, None, 1).is_err() {
        return Some(thread::exit_thread(threads, machine, tid, -ENOEXEC));
    }

    // Reload the live frame from the rebuilt stored frame; stay on this thread.
    (*vcpu) = thread::get_thread(threads, tid).unwrap().kernel.vcpu.regs;
    None
}


/// chdir(12)
fn sys_chdir<A: crate::Arch>(machine: &mut A, _vcpu: &mut Regs, linux: &mut LinuxState, a: &Args) -> SyscallResult {
    let mut path_buf = [0u8; 256];
    let path_len = machine.copy_cstr(a.a0 as usize, &mut path_buf);
    let path = &path_buf[..path_len];
    SyscallResult::val(do_chdir(path, &mut linux.cwd, &mut linux.cwd_len))
}

/// time(13) — stub
fn sys_time<A: crate::Arch>(machine: &mut A, _vcpu: &mut Regs, a: &Args) -> SyscallResult {
    let ptr = a.a0 as usize;
    if ptr != 0 {
        machine.write::<u32>(ptr, 0);
    }
    SyscallResult::val(0)
}

/// lseek(19)
fn sys_lseek<A: crate::Arch>(kt: &mut thread::KernelThread<A>, a: &Args) -> SyscallResult {
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
fn sys_ioctl<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, a: &Args) -> SyscallResult {
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
                machine.zero(arg, 36);
            }
            SyscallResult::val(0)
        }
        TCSETS | TIOCSWINSZ | TIOCSPGRP => SyscallResult::val(0), // accept and discard
        TIOCGWINSZ => {
            // struct winsize: ws_row, ws_col, ws_xpixel, ws_ypixel — 4×u16.
            if arg != 0 {
                machine.write::<u16>(arg, 25);       // ws_row
                machine.write::<u16>(arg + 2, 80);   // ws_col
                machine.write::<u16>(arg + 4, 0);
                machine.write::<u16>(arg + 6, 0);
            }
            SyscallResult::val(0)
        }
        TIOCGPGRP => {
            if arg != 0 {
                let tid = kt.tid;
                machine.write::<i32>(arg, tid);
            }
            SyscallResult::val(0)
        }
        _ => SyscallResult::val(-ENOTTY),
    }
}

/// readlink(85) — minimal stub: only resolves /proc/self/exe (used by
/// static-busybox to find its own re-exec path). Everything else returns
/// EINVAL since we have no symlinks.
fn sys_readlink<A: crate::Arch>(machine: &mut A, _vcpu: &mut Regs, a: &Args) -> SyscallResult {
    let buf = a.a1 as usize;
    let bufsz = a.a2 as usize;
    let mut self_exe_buf = [0u8; 256];
    let self_exe_len = machine.copy_cstr(a.a0 as usize, &mut self_exe_buf);
    let is_self_exe = &self_exe_buf[..self_exe_len] == b"/proc/self/exe";
    if is_self_exe {
        let target: &[u8] = b"/bin/busybox";
        let n = target.len().min(bufsz);
        machine.copy_to(buf, &target[..n]);
        return SyscallResult::val(n as i32);
    }
    SyscallResult::val(-EINVAL)
}

/// access(33) — check file existence via VFS stat
fn sys_access<A: crate::Arch>(machine: &mut A, _vcpu: &mut Regs, linux: &LinuxState, a: &Args) -> SyscallResult {
    access_at(machine, linux, a.a0 as usize)
}

/// faccessat(269) / faccessat2(439) — path at a.a1; only AT_FDCWD dirfds are
/// honored (path resolves against cwd, which is faccessat's AT_FDCWD meaning).
/// Mode/flags are ignored like sys_access: existence = permission (single-user).
fn sys_faccessat<A: crate::Arch>(machine: &mut A, linux: &LinuxState, a: &Args) -> SyscallResult {
    const AT_FDCWD: i32 = -100;
    if a.a0 as i32 != AT_FDCWD {
        return SyscallResult::val(-EBADF);
    }
    access_at(machine, linux, a.a1 as usize)
}

/// Existence check behind access/faccessat: open + close through the VFS.
fn access_at<A: crate::Arch>(machine: &mut A, linux: &LinuxState, path_ptr: usize) -> SyscallResult {
    let mut path_buf = [0u8; 256];
    let path_len = machine.copy_cstr(path_ptr, &mut path_buf);
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
fn sys_fcntl<A: crate::Arch>(kt: &mut thread::KernelThread<A>, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    let cmd = a.a1 as i32;
    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    if kt.fds[fd].is_none() { return SyscallResult::val(-EBADF); }

    const F_DUPFD: i32 = 0;
    const F_GETFD: i32 = 1;
    const F_SETFD: i32 = 2;
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;
    const F_DUPFD_CLOEXEC: i32 = 1030;
    const FD_CLOEXEC: i32 = 1;

    match cmd {
        // Duplicate `fd` to the lowest free fd >= arg. dash saves its std fds
        // to 10+ this way at startup; without it dash bailed ("sh: 0: …").
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let minfd = a.a2 as usize;
            let newfd = match kt.alloc_fd(minfd.min(thread::MAX_FDS)) {
                Some(n) => n,
                None => return SyscallResult::val(-24), // EMFILE
            };
            let kind = kt.fds[fd];
            match kind {
                thread::FdKind::Vfs(handle) => vfs::add_vfs_ref(handle),
                thread::FdKind::PipeRead(idx) => crate::kernel::kpipe::add_reader(idx),
                thread::FdKind::PipeWrite(idx) => crate::kernel::kpipe::add_writer(idx),
                thread::FdKind::Socket(_) => {} // TODO: socket dup refcount
                thread::FdKind::ConsoleOut | thread::FdKind::None | thread::FdKind::Dir { .. } => {}
            }
            kt.fds[newfd] = kind;
            if cmd == F_DUPFD_CLOEXEC {
                kt.cloexec |= 1 << newfd;
            } else {
                kt.cloexec &= !(1 << newfd);
            }
            SyscallResult::val(newfd as i32)
        }
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
    let num_pages = length.div_ceil(0x1000);
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

/// wait4(114) — return a Wait action; `handle_wait` does the child scan/reap
/// (or block) in the executor, off the parent's borrow.
fn sys_wait4<A: crate::Arch>(_machine: &mut A, _kt: &mut thread::KernelThread<A>, a: &Args, _regs: &mut Regs) -> SyscallResult {
    let pid = a.a0 as i32;
    let status_ptr = a.a1 as usize;
    let _options = a.a2 as i32;
    SyscallResult::act(0, thread::KernelAction::Wait { pid, status_ptr })
}

/// Executor for `KernelAction::Wait`. Runs after the handler's borrow released,
/// so it can scan/reap other threads. `vcpu` is the live (parent) frame.
///   - zombie ready: reap, write status to user mem, rax = child tid, stay.
///   - no children (-ECHILD): rax = -ECHILD, stay.
///   - children but none exited (EAGAIN): record the deferred status pointer,
///     block the parent, reschedule (woken when a child exits; `on_resume`
///     finalizes the status write + return value, as before).
pub(crate) fn handle_wait<A: crate::Arch>(
    machine: &mut A,
    threads: &mut [thread::Thread<A>],
    vcpu: &mut Regs,
    tid: usize,
    pid: i32,
    status_ptr: usize,
) -> Option<usize> {
    let (child_tid, exit_code) = thread::waitpid(threads, machine, tid, pid);

    if child_tid >= 0 {
        if status_ptr != 0 {
            machine.write::<i32>(status_ptr, (exit_code & 0xFF) << 8);
        }
        vcpu.rax = child_tid as i64 as u64;
        return None;
    }

    if child_tid == -10 {
        vcpu.rax = (-ECHILD) as i64 as u64;
        return None;
    }

    // EAGAIN — children exist but none exited. Record the deferred status
    // pointer, block, and reschedule.
    if let thread::Personality::Linux(linux) = &mut thread::get_thread(threads, tid).unwrap().personality {
        linux.wait_status_ptr = status_ptr;
    }
    thread::block_thread(threads, tid);
    Some(thread::schedule(threads, tid).unwrap_or(0))
}

/// uname(122 / x86-64 63)
fn sys_uname<A: crate::Arch>(machine: &mut A, _vcpu: &mut Regs, a: &Args, want_64: bool) -> SyscallResult {
    let buf = a.a0 as usize;
    if buf == 0 { return SyscallResult::val(-EFAULT); }

    // Linux struct old_utsname: 6 fields, 65 bytes each
    machine.zero(buf, 65 * 6);
    let machine_name: &[u8] = if want_64 { b"x86_64" } else { b"i686" };
    let fields: [&[u8]; 6] = [b"Linux", b"retroos", b"5.0.0", b"#1", machine_name, b"(none)"];
    for (i, s) in fields.iter().enumerate() {
        let n = s.len().min(64);
        machine.copy_to(buf + i * 65, &s[..n]);
    }
    SyscallResult::val(0)
}

/// _llseek(140) — 64-bit lseek
fn sys_llseek<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, a: &Args) -> SyscallResult {
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
        machine.write::<i64>(result_ptr, r as i64);
    }
    SyscallResult::val(0)
}

/// writev(146)
fn sys_writev<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, a: &Args, want_64: bool) -> SyscallResult {
    let fd = a.a0 as usize;
    let iov_ptr = a.a1 as usize;
    let iovcnt = a.a2 as usize;

    if iovcnt > 1024 { return SyscallResult::val(-EINVAL); }
    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    let fd_kind = kt.fds[fd];

    let mut total = 0i32;

    // struct iovec { void *iov_base; size_t iov_len; } — 8 bytes on i386,
    // 16 bytes (two u64) on x86-64. Reading it at the wrong width drops the
    // length (reads it from the high half of the pointer) → writes nothing.
    let stride = if want_64 { 16 } else { 8 };
    for i in 0..iovcnt {
        let base_addr = iov_ptr + i * stride;
        let (iov_base, iov_len) = if want_64 {
            (machine.read::<u64>(base_addr) as usize, machine.read::<u64>(base_addr + 8) as usize)
        } else {
            (machine.read::<u32>(base_addr) as usize, machine.read::<u32>(base_addr + 4) as usize)
        };

        if iov_len == 0 { continue; }

        let mut iov = alloc::vec![0u8; iov_len];
        machine.copy_from(iov_base, &mut iov);
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
                let r = vfs::write_by_handle(machine, handle, &iov);
                if r < 0 { return SyscallResult::val(r); }
                total += r;
            }
            _ => return SyscallResult::val(-EBADF),
        }
    }

    SyscallResult::val(total)
}

/// sched_yield(158)
fn sys_sched_yield<A: crate::Arch>(_kt: &mut thread::KernelThread<A>, _regs: &mut Regs) -> SyscallResult {
    // Pure: just ask the loop to reschedule. The executor's `Yield` arm marks
    // this thread Ready, materializes the live frame, and picks the next thread
    // (`thread::yield_thread`) — none of which can run under the `kt` borrow.
    // The manual `kt.vcpu.regs = *regs` save the old body did was dead: the live
    // `ctx.regs` is authoritative and `switch_to` materializes it on the way out.
    SyscallResult::act(0, thread::KernelAction::Yield)
}

/// nanosleep(162) — stub: yield once
fn sys_nanosleep() -> SyscallResult {
    SyscallResult::val(0)
}

/// Evaluate a pollfd[] array once, writing revents and returning the
/// number of fds with non-zero revents. Used by both sys_poll's first try
/// and the event-loop's pending-poll retry.
pub(crate) fn run_poll<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, fds_ptr: usize, nfds: usize) -> i32 {
    const POLLIN: i16 = 1;
    const POLLOUT: i16 = 4;
    let mut ready = 0i32;
    for i in 0..nfds {
        let base = fds_ptr + i * 8;
        let fd = machine.read::<i32>(base) as usize;
        let events = machine.read::<i16>(base + 4);
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
                thread::FdKind::Vfs(_) | thread::FdKind::Dir { .. } => {
                    if (events & POLLIN) != 0 { revents |= POLLIN; }
                    if (events & POLLOUT) != 0 { revents |= POLLOUT; }
                }
                // Sockets: optimistically report ready for whatever was asked.
                // Host sockets are blocking, so a following recv/send blocks
                // until it actually completes. TODO: real readiness via a
                // non-blocking poll on the host socket.
                thread::FdKind::Socket(_) => {
                    revents |= events & (POLLIN | POLLOUT);
                }
                thread::FdKind::None => {}
            }
        }
        machine.write::<i16>(base + 6, revents);
        if revents != 0 { ready += 1; }
    }
    ready
}

/// poll(168) — block until at least one monitored fd is ready (or timeout).
fn sys_poll<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, linux: &mut LinuxState, a: &Args, regs: &mut Regs) -> SyscallResult {
    let fds_ptr = a.a0 as usize;
    let nfds = a.a1 as usize;
    let timeout = a.a2 as i32;

    let ready = run_poll(machine, kt, fds_ptr, nfds);
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
    SyscallResult { retval: 0, switch_to: None, action: None }
}

/// getcwd(183)
fn sys_getcwd<A: crate::Arch>(machine: &mut A, _vcpu: &mut Regs, linux: &LinuxState, a: &Args) -> SyscallResult {
    let ptr = a.a0 as usize;
    let size = a.a1 as usize;
    let cwd = linux.cwd_str();
    // Linux getcwd returns absolute path with leading /
    if size < cwd.len() + 2 { return SyscallResult::val(-EINVAL); }
    machine.write::<u8>(ptr, b'/');
    machine.copy_to(ptr + 1, cwd);
    machine.write::<u8>(ptr + 1 + cwd.len(), 0); // NUL
    SyscallResult::val((cwd.len() + 2) as i32)
}

/// mmap2(192) — anonymous private only
/// pread64(17 / i386 180) — positioned read; does not advance the fd offset
/// as far as the caller is concerned (each call re-seeks). ld.so reads ELF
/// headers/sections of shared libraries this way.
fn sys_pread64<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    let buf = a.a1 as usize;
    let len = a.a2 as usize;
    let offset = a.a3 as i64;
    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    match kt.fds[fd] {
        thread::FdKind::Vfs(handle) => {
            vfs::seek_by_handle(handle, offset as i32, 0 /*SEEK_SET*/);
            let mut tmp = alloc::vec![0u8; len];
            let n = vfs::read_by_handle(handle, &mut tmp);
            if n > 0 { machine.copy_to(buf, &tmp[..n as usize]); }
            SyscallResult::val(n)
        }
        _ => SyscallResult::val(-EBADF),
    }
}

/// futex(202) — minimal. Single-threaded clients only reach WAIT when a lock is
/// already held; correct behavior is EAGAIN when the word no longer matches.
fn sys_futex<A: crate::Arch>(machine: &mut A, _kt: &mut thread::KernelThread<A>, a: &Args) -> SyscallResult {
    let uaddr = a.a0 as usize;
    let op = a.a1 as u32 & 0x7f; // strip FUTEX_PRIVATE_FLAG / CLOCK_REALTIME
    let val = a.a2 as u32;
    const FUTEX_WAIT: u32 = 0;
    const FUTEX_WAKE: u32 = 1;
    let cur = machine.read::<u32>(uaddr);
    match op {
        FUTEX_WAIT => if cur != val { SyscallResult::val(-11) } else { SyscallResult::val(0) }, // EAGAIN
        FUTEX_WAKE => SyscallResult::val(0),
        _ => SyscallResult::val(0),
    }
}

fn sys_mmap2<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, linux: &mut LinuxState, a: &Args, offset_bytes: usize) -> SyscallResult {
    let addr_hint = a.a0 as usize;
    let length = a.a1 as usize;
    let _prot = a.a2 as u32;
    let flags = a.a3 as u32;
    let fd = a.a4 as i32;

    const MAP_ANONYMOUS: u32 = 0x20;
    const MAP_FIXED: u32 = 0x10;

    let num_pages = length.div_ceil(0x1000);
    if num_pages == 0 { return SyscallResult::val(-EINVAL); }
    let alloc_size = num_pages * 0x1000;

    // Pick the base address: MAP_FIXED honors the hint; otherwise grow the
    // mmap region downward.
    let base = if flags & MAP_FIXED != 0 && addr_hint != 0 {
        addr_hint & !0xFFF
    } else {
        if linux.mmap_cursor < linux.heap_end + alloc_size {
            return SyscallResult::val64(-ENOMEM as i64);
        }
        linux.mmap_cursor -= alloc_size;
        linux.mmap_cursor
    };

    // File-backed mapping: read the file region into the (demand-allocated)
    // pages so the dynamic linker can map libc et al. Anonymous mappings stay
    // demand-zero (page-fault handler zero-fills on first touch). MAP_PRIVATE
    // file maps are treated as eager copies — fine since we never write back.
    if flags & MAP_ANONYMOUS == 0 {
        if fd < 0 || fd as usize >= thread::MAX_FDS {
            return SyscallResult::val64(-EBADF as i64);
        }
        match kt.fds[fd as usize] {
            thread::FdKind::Vfs(handle) => {
                vfs::seek_by_handle(handle, offset_bytes as i32, 0 /*SEEK_SET*/);
                let mut tmp = alloc::vec![0u8; length];
                let n = vfs::read_by_handle(handle, &mut tmp);
                if n > 0 { machine.copy_to(base, &tmp[..n as usize]); }
            }
            _ => return SyscallResult::val64(-EBADF as i64),
        }
    } else {
        // MAP_ANONYMOUS must read as zero. Eager-zero the range — demand-zero
        // alone left libc's BSS (its lock words) holding garbage, which sent
        // glibc into a futex spin on a "held" lock.
        machine.zero(base, alloc_size);
    }

    SyscallResult::val64(base as i64)
}

/// mremap(i386 163 / x86-64 25) — glibc realloc's grow path for large chunks.
/// The mmap model is a bare downward bump with no per-mapping bookkeeping, so
/// growing is always a move: fresh anonymous region + content copy (requires
/// MREMAP_MAYMOVE, which glibc always passes). Shrinks keep the mapping —
/// over-mapped tails are harmless here.
fn sys_mremap<A: crate::Arch>(machine: &mut A, linux: &mut LinuxState, a: &Args) -> SyscallResult {
    const MREMAP_MAYMOVE: u32 = 1;
    let old_addr = a.a0 as usize;
    let old_len = a.a1 as usize;
    let new_len = a.a2 as usize;
    let flags = a.a3 as u32;
    if old_addr & 0xFFF != 0 || new_len == 0 {
        return SyscallResult::val(-EINVAL);
    }
    if new_len <= old_len {
        return SyscallResult::val64(old_addr as i64);
    }
    if flags & MREMAP_MAYMOVE == 0 {
        return SyscallResult::val64(-ENOMEM as i64);
    }
    let alloc_size = new_len.div_ceil(0x1000) * 0x1000;
    if linux.mmap_cursor < linux.heap_end + alloc_size {
        return SyscallResult::val64(-ENOMEM as i64);
    }
    linux.mmap_cursor -= alloc_size;
    let base = linux.mmap_cursor;
    machine.zero(base, alloc_size);
    machine.copy_within(old_addr, base, old_len);
    SyscallResult::val64(base as i64)
}

/// stat data (full st_mode incl. file type, size, ino) for a resolved VFS
/// path — the lookup shared by stat/fstatat/statx.
fn stat_lookup(resolved: &[u8]) -> Option<(u32, u32, u64)> {
    if vfs::dir_exists(resolved) {
        return Some((0o40755, 0, 0));
    }
    let handle = vfs::open_to_handle(resolved);
    if handle < 0 {
        return None;
    }
    let size = vfs::file_size_by_handle(handle);
    let mode = vfs::file_mode_by_handle(handle);
    let ino = vfs::file_ino_by_handle(handle);
    vfs::close_vfs_handle(handle);
    Some((0o100000 | mode as u32, size, ino))
}

/// Base directory for `*at()` path resolution: a dirfd naming a directory
/// (via the dir-handle table) wins; AT_FDCWD / anything else = cwd.
fn at_base<'a, A: crate::Arch>(
    kt: &thread::KernelThread<A>,
    linux: &'a LinuxState,
    dirfd: i32,
    buf: &'a mut [u8; vfs::DIR_PATH_MAX],
) -> &'a [u8] {
    if dirfd >= 0 && (dirfd as usize) < thread::MAX_FDS {
        if let thread::FdKind::Dir { handle, .. } = kt.fds[dirfd as usize] {
            let n = vfs::dir_handle_path(handle, buf);
            if n > 0 {
                return &buf[..n];
            }
        }
    }
    linux.cwd_str()
}

/// stat64(195) / lstat64(196)
fn sys_stat64<A: crate::Arch>(machine: &mut A, _vcpu: &mut Regs, linux: &LinuxState, a: &Args, want_64: bool) -> SyscallResult {
    let path_ptr = a.a0 as usize;
    let stat_buf = a.a1 as usize;
    let mut path_buf = [0u8; 256];
    let path_len = machine.copy_cstr(path_ptr, &mut path_buf);
    let path = &path_buf[..path_len];

    let mut pbuf = [0u8; 164];
    let resolved = resolve_path(path, linux.cwd_str(), &mut pbuf);

    match stat_lookup(resolved) {
        Some((mode, size, ino)) => {
            write_stat64(machine, stat_buf, mode, size, ino, want_64);
            SyscallResult::val(0)
        }
        None => SyscallResult::val(-ENOENT),
    }
}

/// statx(x86-64 332 / i386 383) — the modern stat coreutils tries first.
/// Fills the basic-stats set from the same lookup as stat64.
fn sys_statx<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, linux: &LinuxState, a: &Args) -> SyscallResult {
    let dirfd = a.a0 as i32;
    let path_ptr = a.a1 as usize;
    let statx_buf = a.a4 as usize;
    let mut path_buf = [0u8; 256];
    let path_len = machine.copy_cstr(path_ptr, &mut path_buf);
    let path = &path_buf[..path_len];

    // Empty path (AT_EMPTY_PATH): stat the fd itself.
    if path.is_empty() {
        let fd = dirfd as usize;
        if dirfd < 0 || fd >= thread::MAX_FDS {
            return SyscallResult::val(-EBADF);
        }
        let (mode, size, ino) = match kt.fds[fd] {
            thread::FdKind::Vfs(h) => (
                0o100000 | vfs::file_mode_by_handle(h) as u32,
                vfs::file_size_by_handle(h),
                vfs::file_ino_by_handle(h),
            ),
            thread::FdKind::Dir { .. } => (0o40755, 0, 0),
            thread::FdKind::None => return SyscallResult::val(-EBADF),
            _ => (0o20666, 0, 0), // console / pipe / socket: char-dev-ish
        };
        write_statx(machine, statx_buf, mode, size, ino);
        return SyscallResult::val(0);
    }

    let mut dbuf = [0u8; vfs::DIR_PATH_MAX];
    let base = at_base(kt, linux, dirfd, &mut dbuf);
    let mut pbuf = [0u8; 164];
    let resolved = resolve_path(path, base, &mut pbuf);
    match stat_lookup(resolved) {
        Some((mode, size, ino)) => {
            write_statx(machine, statx_buf, mode, size, ino);
            SyscallResult::val(0)
        }
        None => SyscallResult::val(-ENOENT),
    }
}

/// Write a Linux `struct statx` (256 bytes) covering STATX_BASIC_STATS.
fn write_statx<A: crate::Arch>(machine: &mut A, buf: usize, mode: u32, size: u32, ino: u64) {
    machine.zero(buf, 256);
    machine.write::<u32>(buf, 0x7FF); // stx_mask = STATX_BASIC_STATS
    machine.write::<u32>(buf + 4, 4096); // stx_blksize
    machine.write::<u32>(buf + 16, 1); // stx_nlink
    machine.write::<u16>(buf + 28, mode as u16); // stx_mode
    machine.write::<u64>(buf + 32, ino); // stx_ino
    machine.write::<u64>(buf + 40, size as u64); // stx_size
    machine.write::<u64>(buf + 48, (size as u64).div_ceil(512)); // stx_blocks
}

/// fstat64(197)
fn sys_fstat64<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, a: &Args, want_64: bool) -> SyscallResult {
    let fd = a.a0 as usize;
    let stat_buf = a.a1 as usize;

    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    match kt.fds[fd] {
        thread::FdKind::ConsoleOut | thread::FdKind::PipeRead(_) | thread::FdKind::PipeWrite(_) => {
            // stdin/stdout/stderr / pipes — character device / pipe
            write_stat64(machine, stat_buf, 0o20666, 0, 0, want_64); // S_IFCHR
            SyscallResult::val(0)
        }
        thread::FdKind::Vfs(handle) => {
            let size = vfs::file_size_by_handle(handle);
            let mode = vfs::file_mode_by_handle(handle);
            let ino = vfs::file_ino_by_handle(handle);
            write_stat64(machine, stat_buf, 0o100000 | mode as u32, size, ino, want_64);
            SyscallResult::val(0)
        }
        thread::FdKind::Dir { .. } => {
            write_stat64(machine, stat_buf, 0o40755, 0, 0, want_64); // S_IFDIR
            SyscallResult::val(0)
        }
        thread::FdKind::Socket(_) => {
            write_stat64(machine, stat_buf, 0o140000 | 0o777, 0, 0, want_64); // S_IFSOCK
            SyscallResult::val(0)
        }
        thread::FdKind::None => SyscallResult::val(-EBADF),
    }
}

/// fstatat64(300 / x86-64 262)
fn sys_fstatat64<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, linux: &LinuxState, a: &Args, want_64: bool) -> SyscallResult {
    let dirfd = a.a0 as i32;
    let path_ptr = a.a1 as usize;
    let stat_buf = a.a2 as usize;
    let mut path_buf = [0u8; 256];
    let path_len = machine.copy_cstr(path_ptr, &mut path_buf);
    let path = &path_buf[..path_len];

    // Resolve relative to the dirfd's directory (dir-handle table) — ls does
    // fstatat(dirfd_of_dir, entry_name) for every listing entry.
    let mut dbuf = [0u8; vfs::DIR_PATH_MAX];
    let base = at_base(kt, linux, dirfd, &mut dbuf);
    let mut pbuf = [0u8; 164];
    let resolved = resolve_path(path, base, &mut pbuf);
    match stat_lookup(resolved) {
        Some((mode, size, ino)) => {
            write_stat64(machine, stat_buf, mode, size, ino, want_64);
            SyscallResult::val(0)
        }
        None => SyscallResult::val(-ENOENT),
    }
}

/// Write a minimal Linux stat struct to user memory. The layout differs by
/// client bitness: i386 `struct stat64` (96 bytes, st_mode@16, st_size@44) vs
/// x86-64 `struct stat` (144 bytes, st_mode@24, st_size@48). Getting this wrong
/// for a 64-bit client makes ld.so read st_mode/st_size from the wrong offsets
/// and reject a shared library as non-regular — so libc never maps.
fn write_stat64<A: crate::Arch>(machine: &mut A, buf: usize, mode: u32, size: u32, ino: u64, want_64: bool) {
    if want_64 {
        machine.zero(buf, 144);
        machine.write::<u64>(buf, 1);                              // st_dev
        machine.write::<u64>(buf + 8, ino);                            // st_ino
        machine.write::<u64>(buf + 16, 1);                             // st_nlink
        machine.write::<u32>(buf + 24, mode);                          // st_mode
        machine.write::<u64>(buf + 48, size as u64);                   // st_size
        machine.write::<u64>(buf + 56, 4096);                          // st_blksize
        machine.write::<u64>(buf + 64, (size as u64).div_ceil(512));   // st_blocks
    } else {
        machine.zero(buf, 96);
        machine.write::<u64>(buf, 1);                              // st_dev
        machine.write::<u32>(buf + 12, ino as u32);                    // __st_ino (32-bit)
        machine.write::<u32>(buf + 16, mode);                          // st_mode
        machine.write::<u64>(buf + 44, size as u64);                   // st_size (u64 on stat64)
        machine.write::<u32>(buf + 56, 4096);                          // st_blksize
        machine.write::<u64>(buf + 64, (size as u64).div_ceil(512));   // st_blocks
        machine.write::<u64>(buf + 88, ino);                           // st_ino (64-bit)
    }
}

/// Write the old (pre-LFS) Linux i386 `struct stat` (newstat layout, 64 bytes).
/// Used by syscalls 106/107/108. uclibc's busybox falls back to these for
/// access/exec checks; without correct mode bits we get spurious EACCES.
fn write_stat_old<A: crate::Arch>(machine: &mut A, buf: usize, mode: u32, size: u32) {
    machine.zero(buf, 64);
    machine.write::<u16>(buf + 0x08, mode as u16);          // st_mode
    machine.write::<u16>(buf + 0x0a, 1);                    // st_nlink
    machine.write::<u32>(buf + 0x14, size);                 // st_size
    machine.write::<u32>(buf + 0x18, 4096);                 // st_blksize
    machine.write::<u32>(buf + 0x1c, size.div_ceil(512));   // st_blocks
}

/// stat(106) / lstat(107) — old struct stat layout. We have no symlinks so
/// lstat falls through to stat.
fn sys_stat_old<A: crate::Arch>(machine: &mut A, _vcpu: &mut Regs, linux: &LinuxState, a: &Args) -> SyscallResult {
    let mut path_buf = [0u8; 256];
    let path_len = machine.copy_cstr(a.a0 as usize, &mut path_buf);
    let path = &path_buf[..path_len];
    let stat_buf = a.a1 as usize;
    let mut pbuf = [0u8; 164];
    let resolved = resolve_path(path, linux.cwd_str(), &mut pbuf);
    if vfs::dir_exists(resolved) {
        write_stat_old(machine, stat_buf, 0o40755, 0);
        return SyscallResult::val(0);
    }
    let handle = vfs::open_to_handle(resolved);
    if handle < 0 { return SyscallResult::val(-ENOENT); }
    let size = vfs::file_size_by_handle(handle);
    let mode = vfs::file_mode_by_handle(handle);
    vfs::close_vfs_handle(handle);
    write_stat_old(machine, stat_buf, 0o100000 | mode as u32, size);
    SyscallResult::val(0)
}

/// fstat(108) — old struct stat layout.
fn sys_fstat_old<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    let stat_buf = a.a1 as usize;
    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    match kt.fds[fd] {
        thread::FdKind::ConsoleOut | thread::FdKind::PipeRead(_) | thread::FdKind::PipeWrite(_) => {
            write_stat_old(machine, stat_buf, 0o20666, 0); // S_IFCHR
            SyscallResult::val(0)
        }
        thread::FdKind::Vfs(handle) => {
            let size = vfs::file_size_by_handle(handle);
            let mode = vfs::file_mode_by_handle(handle);
            write_stat_old(machine, stat_buf, 0o100000 | mode as u32, size);
            SyscallResult::val(0)
        }
        thread::FdKind::Dir { .. } => {
            write_stat_old(machine, stat_buf, 0o40755, 0);
            SyscallResult::val(0)
        }
        _ => SyscallResult::val(-EBADF),
    }
}

/// getdents64(220)
fn sys_getdents64<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, linux: &LinuxState, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    let dirp = a.a1 as usize;
    let count = a.a2 as usize;

    // The fd carries the directory identity (dir-handle table) and a per-fd
    // cursor. Without the cursor, every call would replay from index 0 and
    // the caller would loop forever.
    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    let (handle, mut index) = match kt.fds[fd] {
        thread::FdKind::Dir { handle, next } => (handle, next as usize),
        _ => (-1, 0), // Tolerate fd=0 / non-Dir fd: read against cwd from start.
    };

    // The fd's recorded directory; a dead/unknown handle falls back to cwd
    // (the pre-table behavior for opendir(".")).
    let mut dir_buf = [0u8; vfs::DIR_PATH_MAX];
    let dir_len = vfs::dir_handle_path(handle, &mut dir_buf);
    let cwd: &[u8] = if dir_len > 0 { &dir_buf[..dir_len] } else { linux.cwd_str() };

    let mut offset = 0usize;
    while let Some(entry) = vfs::readdir(cwd, index) {
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
        machine.zero(base, reclen);
        machine.write::<u64>(base, index as u64);         // d_ino
        machine.write::<u64>(base + 8, index as u64);     // d_off
        machine.write::<u16>(base + 16, reclen as u16);   // d_reclen
        machine.write::<u8>(base + 18, if entry.is_dir { 4 } else { 8 }); // d_type: DT_DIR/DT_REG
        machine.copy_to(base + 19, name);
        offset += reclen;
    }

    if let thread::FdKind::Dir { handle, .. } = kt.fds[fd] {
        kt.fds[fd] = thread::FdKind::Dir { handle, next: index as u32 };
    }
    SyscallResult::val(offset as i32)
}

/// set_thread_area(243) — parse user_desc struct, set GDT TLS entry, save to LinuxState
fn sys_set_thread_area<A: crate::Arch>(machine: &mut A, _kt: &mut thread::KernelThread<A>, linux: &mut LinuxState, a: &Args) -> SyscallResult {
    let u_info = a.a0 as usize;
    if u_info == 0 { return SyscallResult::val(-EFAULT); }

    // struct user_desc { entry_number: i32, base_addr: u32, limit: u32, flags: u32 }
    let entry_number = machine.read::<i32>(u_info);
    let base_addr = machine.read::<u32>(u_info + 4);
    let limit = machine.read::<u32>(u_info + 8);
    let flags = machine.read::<u32>(u_info + 12);
    let limit_in_pages = flags & (1 << 4) != 0;

    let idx = machine.set_tls_entry(entry_number, base_addr, limit, limit_in_pages);
    if idx < 0 { return SyscallResult::val(-ESRCH); }

    // Write back the allocated entry number
    machine.write::<i32>(u_info, idx);

    // Save TLS state for context-switch restore
    linux.tls_entry = idx;
    linux.tls_base = base_addr;
    linux.tls_limit = limit;
    linux.tls_limit_in_pages = limit_in_pages;

    SyscallResult::val(0)
}

/// arch_prctl(158) — x86_64 TLS via FS/GS base.
/// Stores the base in regs.fs/gs — arch layer writes MSR on return to user.
fn sys_arch_prctl<A: crate::Arch>(machine: &mut A, _kt: &mut thread::KernelThread<A>, _linux: &mut LinuxState, a: &Args, regs: &mut Regs) -> SyscallResult {
    const ARCH_SET_GS: u64 = 0x1001;
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;
    const ARCH_GET_GS: u64 = 0x1004;

    match a.a0 {
        ARCH_SET_FS => { regs.fs = a.a1; SyscallResult::val(0) }
        ARCH_SET_GS => { regs.gs = a.a1; SyscallResult::val(0) }
        ARCH_GET_FS => {
            let ptr = a.a1 as usize;
            if ptr != 0 { machine.write::<u64>(ptr, regs.fs); }
            SyscallResult::val(0)
        }
        ARCH_GET_GS => {
            let ptr = a.a1 as usize;
            if ptr != 0 { machine.write::<u64>(ptr, regs.gs); }
            SyscallResult::val(0)
        }
        _ => SyscallResult::val(-EINVAL),
    }
}

/// clock_gettime(265) — monotonic from tick counter
fn sys_clock_gettime<A: crate::Arch>(machine: &mut A, _vcpu: &mut Regs, a: &Args) -> SyscallResult {
    let _clock_id = a.a0 as u32;
    let tp = a.a1 as usize;
    if tp != 0 {
        let ticks = machine.get_ticks();
        // PIT ticks at ~1193182 Hz, timer IRQ at ~100 Hz (div=11932)
        let secs = ticks / 100;
        let nsecs = (ticks % 100) * 10_000_000;
        machine.write::<u32>(tp, secs as u32);        // tv_sec
        machine.write::<u32>(tp + 4, nsecs as u32);   // tv_nsec
    }
    SyscallResult::val(0)
}

/// openat(295) — treat AT_FDCWD as cwd-relative, else EBADF
fn sys_openat<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, linux: &LinuxState, a: &Args) -> SyscallResult {
    let dirfd = a.a0 as i32;
    const AT_FDCWD: i32 = -100;
    if dirfd != AT_FDCWD && dirfd < 0 {
        return SyscallResult::val(-EBADF);
    }
    let shifted = Args { a0: a.a1, a1: a.a2, a2: a.a3, a3: 0, a4: 0, a5: 0 };
    sys_open(machine, kt, linux, &shifted)
}

/// getrandom(355) — stub: fill with PRNG output
fn sys_getrandom<A: crate::Arch>(machine: &mut A, _vcpu: &mut Regs, a: &Args) -> SyscallResult {
    let buf = a.a0 as usize;
    let buflen = a.a1 as usize;
    let mut tmp = alloc::vec![0u8; buflen];
    for b in tmp.iter_mut() {
        *b = thread::prng() as u8;
    }
    machine.copy_to(buf, &tmp);
    SyscallResult::val(buflen as i32)
}

/// pipe(42) / pipe2(359)
fn sys_pipe<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, a: &Args, is_pipe2: bool) -> SyscallResult {
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

    machine.write::<i32>(pipefd_ptr, read_fd as i32);
    machine.write::<i32>(pipefd_ptr + 4, write_fd as i32);
    SyscallResult::val(0)
}

/// dup2(63)
fn sys_dup2<A: crate::Arch>(kt: &mut thread::KernelThread<A>, a: &Args) -> SyscallResult {
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
        thread::FdKind::Socket(_) => {} // TODO: socket dup refcount
        thread::FdKind::ConsoleOut | thread::FdKind::None | thread::FdKind::Dir { .. } => {}
    }
    kt.fds[newfd] = kind;
    kt.cloexec &= !(1 << newfd);

    SyscallResult::val(newfd as i32)
}
