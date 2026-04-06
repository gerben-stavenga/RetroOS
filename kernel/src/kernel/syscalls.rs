//! Linux i386 syscall interface
//!
//! INT 0x80, EAX = syscall number (Linux i386 numbering)
//! i386:   EBX=a0, ECX=a1, EDX=a2, ESI=a3, EDI=a4, EBP=a5
//! x86_64: RDI=a0, RSI=a1, RDX=a2, R10=a3, R8=a4, R9=a5
//! Return: EAX/RAX (negative = -errno)

use crate::kernel::elf;
use crate::kernel::stacktrace::SymbolData;
use crate::kernel::startup;
use crate::kernel::thread;
use crate::kernel::vfs;
use crate::vga;
use crate::Regs;
use crate::{print, println};

// =============================================================================
// errno constants (positive values; returned as negative)
// =============================================================================

const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const ESRCH: i32 = 3;
const EINTR: i32 = 4;
const EIO: i32 = 5;
const ENOEXEC: i32 = 8;
const EBADF: i32 = 9;
const ECHILD: i32 = 10;
const EAGAIN: i32 = 11;
const ENOMEM: i32 = 12;
const EACCES: i32 = 13;
const EFAULT: i32 = 14;
const ENOTTY: i32 = 25;
const EINVAL: i32 = 22;
const ESPIPE: i32 = 29;
const EPIPE: i32 = 32;
const ENOSYS: i32 = 38;
const ENODATA: i32 = 61;

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
    fn switch(next: Option<usize>) -> Self { Self { retval: 0, switch_to: next } }
}

/// Dispatch returning KernelAction.
pub fn dispatch_action(tid: usize, regs: &mut Regs) -> thread::KernelAction {
    let args = extract_args(regs);
    let nr = regs.rax as u32;

    let result = dispatch_nr(tid, nr, &args, regs);

    regs.rax = result.retval as u64;
    match result.switch_to {
        Some(next) => thread::KernelAction::Switch(next),
        None => thread::KernelAction::Done,
    }
}

fn dispatch_nr(tid: usize, nr: u32, a: &Args, regs: &mut Regs) -> SyscallResult {
    match nr {
        // Tier 0: startup
        1   => sys_exit(tid, a),
        2   => sys_fork(tid, a, regs),
        3   => sys_read(tid, a, regs),
        4   => sys_write(tid, a),
        5   => sys_open(tid, a),
        6   => sys_close(tid, a),
        11  => sys_execve(tid, a, regs),
        12  => sys_chdir(tid, a),
        13  => sys_time(a),
        19  => sys_lseek(tid, a),
        20  => sys_getpid(tid),
        24 | 49 | 47 | 50 => SyscallResult::val(0), // get{u,eu,g,eg}id
        33  => sys_access(tid, a),
        42  => sys_pipe(tid, a, false),
        45  => sys_brk(tid, a),
        54  => SyscallResult::val(-ENOTTY), // ioctl
        55  => sys_fcntl(tid, a),
        63  => sys_dup2(tid, a),
        85  => SyscallResult::val(-ENOENT), // readlink
        91  => sys_munmap(tid, a),
        114 => sys_wait4(tid, a, regs),
        120 => sys_clone(tid, a, regs),
        122 => sys_uname(a),
        125 => SyscallResult::val(0), // mprotect
        140 => sys_llseek(tid, a),
        146 => sys_writev(tid, a),
        158 => sys_sched_yield(tid, regs),
        162 => sys_nanosleep(),
        168 => sys_poll(tid, a),
        174 => SyscallResult::val(0), // rt_sigaction
        175 => SyscallResult::val(0), // rt_sigprocmask
        183 => sys_getcwd(tid, a),
        186 => SyscallResult::val(0), // sigaltstack
        192 => sys_mmap2(tid, a),
        195 => sys_stat64(tid, a),
        196 => sys_stat64(tid, a), // lstat64 = stat64 (no symlinks)
        197 => sys_fstat64(tid, a),
        220 => sys_getdents64(tid, a),
        221 => sys_fcntl(tid, a), // fcntl64
        238 => sys_exit(tid, a), // tkill → exit
        240 => SyscallResult::val(0), // futex
        243 => sys_set_thread_area_with_tid(tid, a),
        252 => sys_exit(tid, a), // exit_group
        258 => sys_set_tid_address(tid),
        265 => sys_clock_gettime(a),
        270 => sys_exit(tid, a), // tgkill → exit
        295 => sys_openat(tid, a),
        300 => sys_fstatat64(tid, a),
        305 => SyscallResult::val(-ENOENT), // readlinkat
        331 => sys_pipe(tid, a, true),  // pipe2
        340 => SyscallResult::val(0), // prlimit64
        355 => sys_getrandom(a),
        _ => {
            println!("unimplemented syscall {}", nr);
            SyscallResult::val(-ENOSYS)
        }
    }
}

// =============================================================================
// Helpers: C string / path handling
// =============================================================================

/// Read a NUL-terminated C string from user memory. Returns slice excluding NUL.
unsafe fn read_c_str(ptr: usize, max: usize) -> &'static [u8] {
    let p = ptr as *const u8;
    let mut len = 0;
    while len < max && *p.add(len) != 0 { len += 1; }
    core::slice::from_raw_parts(p, len)
}

/// Resolve a path (NUL-terminated user pointer) against cwd.
/// Leading `/` = absolute (strip it). Otherwise prepend cwd.
pub fn resolve_path<'a>(path: &[u8], cwd: &[u8], buf: &'a mut [u8; 164]) -> &'a [u8] {
    let mut pos = 0;
    if !path.is_empty() && path[0] == b'/' {
        let trimmed = &path[path.iter().position(|&b| b != b'/').unwrap_or(path.len())..];
        for &b in trimmed {
            if pos < buf.len() { buf[pos] = b; pos += 1; }
        }
    } else {
        for &b in cwd {
            if pos < buf.len() { buf[pos] = b; pos += 1; }
        }
        for &b in path {
            if pos < buf.len() { buf[pos] = b; pos += 1; }
        }
    }
    &buf[..pos]
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

/// Get mutable reference to LinuxState for a thread (panics if not Linux).
fn linux_state(tid: usize) -> &'static mut thread::LinuxState {
    let t = thread::get_thread(tid).unwrap();
    match &mut t.mode {
        thread::ThreadMode::Linux(l) => l,
        _ => panic!("linux_state on non-Linux thread"),
    }
}

/// Get cwd slice for the thread.
fn thread_cwd(tid: usize) -> &'static [u8] {
    let t = thread::get_thread(tid).unwrap();
    match &t.mode {
        thread::ThreadMode::Dos(d) => d.cwd_str(),
        thread::ThreadMode::Linux(l) => l.cwd_str(),
    }
}

/// Check if path ends with ".EXT" (case-insensitive, 3-letter extension).
fn has_ext(path: &[u8], ext: &[u8; 3]) -> bool {
    path.len() >= 4 && path[path.len() - 4] == b'.'
        && path[path.len() - 3].to_ascii_uppercase() == ext[0]
        && path[path.len() - 2].to_ascii_uppercase() == ext[1]
        && path[path.len() - 1].to_ascii_uppercase() == ext[2]
}

/// Read a C `char**` (NULL-terminated) from 32-bit user memory into Vec<Vec<u8>>.
fn read_c_argv32(ptr: usize) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
    let mut args = alloc::vec::Vec::new();
    if ptr == 0 { return args; }
    let mut p = ptr as *const u32;
    unsafe {
        loop {
            let arg_ptr = *p as usize;
            if arg_ptr == 0 { break; }
            let s = read_c_str(arg_ptr, 4096);
            args.push(s.to_vec());
            p = p.add(1);
        }
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
pub(crate) fn setup_user_stack(args: &[alloc::vec::Vec<u8>], want_64: bool) -> usize {
    let stack_top = elf::USER_STACK_TOP;
    let word = if want_64 { 8usize } else { 4 };
    let mut sp = stack_top;

    // 1. Write NUL-terminated string data at top of stack
    // Environment strings first (they end up at higher addresses)
    let env_strings: &[&[u8]] = &[b"PATH=/"];
    let mut env_addrs: alloc::vec::Vec<usize> = alloc::vec::Vec::with_capacity(env_strings.len());
    for &env in env_strings.iter().rev() {
        sp -= env.len() + 1;
        unsafe {
            core::ptr::copy_nonoverlapping(env.as_ptr(), sp as *mut u8, env.len());
            *((sp + env.len()) as *mut u8) = 0;
        }
        env_addrs.push(sp);
    }
    env_addrs.reverse();

    // Argv strings
    let mut string_addrs: alloc::vec::Vec<usize> = alloc::vec::Vec::with_capacity(args.len());
    for arg in args.iter().rev() {
        sp -= arg.len() + 1; // +1 for NUL
        unsafe {
            core::ptr::copy_nonoverlapping(arg.as_ptr(), sp as *mut u8, arg.len());
            *((sp + arg.len()) as *mut u8) = 0; // NUL terminator
        }
        string_addrs.push(sp);
    }
    string_addrs.reverse();

    // 2. Write 16 bytes of "random" data for AT_RANDOM
    sp &= !(word - 1); // align
    sp -= 16;
    let random_addr = sp;
    // Fill with PRNG output
    unsafe {
        let rnd = sp as *mut u32;
        for i in 0..4 {
            *rnd.add(i) = thread::prng() as u32;
        }
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
    if want_64 {
        unsafe { *(pos as *mut u64) = args.len() as u64; }
    } else {
        unsafe { *(pos as *mut u32) = args.len() as u32; }
    }
    pos += word;

    // 5. Write argv[0..N-1]
    for &addr in &string_addrs {
        if want_64 {
            unsafe { *(pos as *mut u64) = addr as u64; }
        } else {
            unsafe { *(pos as *mut u32) = addr as u32; }
        }
        pos += word;
    }
    // argv[N] = NULL
    if want_64 {
        unsafe { *(pos as *mut u64) = 0; }
    } else {
        unsafe { *(pos as *mut u32) = 0; }
    }
    pos += word;

    // 6. envp[0..M-1]
    for &addr in &env_addrs {
        if want_64 {
            unsafe { *(pos as *mut u64) = addr as u64; }
        } else {
            unsafe { *(pos as *mut u32) = addr as u32; }
        }
        pos += word;
    }
    // envp[M] = NULL
    if want_64 {
        unsafe { *(pos as *mut u64) = 0; }
    } else {
        unsafe { *(pos as *mut u32) = 0; }
    }
    pos += word;

    // 7. Auxiliary vector
    let write_auxv = |p: &mut usize, tag: usize, val: usize| {
        if want_64 {
            unsafe {
                *(*p as *mut u64) = tag as u64;
                *((*p + 8) as *mut u64) = val as u64;
            }
        } else {
            unsafe {
                *(*p as *mut u32) = tag as u32;
                *((*p + 4) as *mut u32) = val as u32;
            }
        }
        *p += word * 2;
    };

    write_auxv(&mut pos, 6, 4096);         // AT_PAGESZ = 4096
    write_auxv(&mut pos, 25, random_addr);  // AT_RANDOM = pointer to 16 random bytes
    write_auxv(&mut pos, 0, 0);             // AT_NULL

    base // return sp
}

// =============================================================================
// Syscall handlers
// =============================================================================

/// exit(1) / exit_group(252)
fn sys_exit(tid: usize, a: &Args) -> SyscallResult {
    let code = a.a0 as i32;
    SyscallResult { retval: 0, switch_to: Some(thread::exit_thread(tid, code)) }
}

/// fork(2)
fn sys_fork(tid: usize, _a: &Args, regs: &mut Regs) -> SyscallResult {
    let current = thread::get_thread(tid).unwrap();
    let mut child_root = crate::RootPageTable::empty();
    startup::arch_user_fork(&mut child_root);

    let child = match thread::create_thread(Some(tid), child_root, true) {
        Some(t) => t,
        None => return SyscallResult::val(-ENOMEM),
    };

    child.cpu_state = *regs;

    // Inherit fds, cwd, and heap state
    match (&current.mode, &mut child.mode) {
        (thread::ThreadMode::Linux(pl), thread::ThreadMode::Linux(cl)) => {
            pl.dup_all_fds(cl);
            cl.cwd = pl.cwd;
            cl.cwd_len = pl.cwd_len;
            cl.heap_base = pl.heap_base;
            cl.heap_end = pl.heap_end;
            cl.mmap_cursor = pl.mmap_cursor;
            cl.tls_entry = pl.tls_entry;
            cl.tls_base = pl.tls_base;
            cl.tls_limit = pl.tls_limit;
            cl.tls_limit_in_pages = pl.tls_limit_in_pages;
        }
        (thread::ThreadMode::Dos(pd), thread::ThreadMode::Linux(cl)) => {
            // DOS parent forking Linux child (shouldn't happen, but handle gracefully)
            cl.cwd = pd.cwd;
            cl.cwd_len = pd.cwd_len;
        }
        _ => {}
    }

    // Child returns 0
    thread::set_return(child, 0);
    current.state = thread::ThreadState::Ready;
    let child_tid = child.tid;
    SyscallResult { retval: child_tid as i64, switch_to: Some(child_tid as usize) }
}

/// clone(120) — fork-like clone with optional child_stack
/// Supports plain fork (flags=SIGCHLD, stack=0) and posix_spawn-style
/// vfork (CLONE_VM|CLONE_VFORK|SIGCHLD, stack=child_stack).
fn sys_clone(tid: usize, a: &Args, regs: &mut Regs) -> SyscallResult {
    let flags = a.a0 as u32;
    let child_stack = a.a1 as usize;
    const SIGCHLD: u32 = 17;
    const CLONE_VM: u32 = 0x100;
    const CLONE_VFORK: u32 = 0x4000;

    if flags & 0xFF != SIGCHLD {
        return SyscallResult::val(-ENOSYS);
    }

    let is_vfork = flags & (CLONE_VM | CLONE_VFORK) == (CLONE_VM | CLONE_VFORK);

    if is_vfork {
        // CLONE_VM|CLONE_VFORK: not a fork. Child borrows parent's address
        // space with a different stack. Parent frozen until child execs/exits.
        let current = thread::get_thread(tid).unwrap();

        // Copy parent's root entries so context switches work. No COW — just
        // the directory pointers. Parent is frozen so there's no conflict.
        let child_root = current.root;
        let child = match thread::create_thread(Some(tid), child_root, true) {
            Some(t) => t,
            None => return SyscallResult::val(-ENOMEM),
        };

        child.cpu_state = *regs;
        child.cpu_state.frame.rsp = child_stack as u64;

        if let (thread::ThreadMode::Linux(pl), thread::ThreadMode::Linux(cl)) =
            (&current.mode, &mut child.mode)
        {
            pl.dup_all_fds(cl);
            cl.cwd = pl.cwd;
            cl.cwd_len = pl.cwd_len;
            cl.heap_base = pl.heap_base;
            cl.heap_end = pl.heap_end;
            cl.mmap_cursor = pl.mmap_cursor;
            cl.tls_entry = pl.tls_entry;
            cl.tls_base = pl.tls_base;
            cl.tls_limit = pl.tls_limit;
            cl.tls_limit_in_pages = pl.tls_limit_in_pages;
            cl.vfork_parent = Some(tid);
        }

        thread::set_return(child, 0);
        let child_tid = child.tid;

        // Block parent until child execs or exits
        current.cpu_state = *regs;
        current.cpu_state.rax = child_tid as u64;
        thread::block_thread(tid);

        SyscallResult { retval: child_tid as i64, switch_to: Some(child_tid as usize) }
    } else {
        // Plain fork (SIGCHLD only, or SIGCHLD with child_stack)
        let result = sys_fork(tid, a, regs);

        if child_stack != 0 {
            if let Some(child_tid) = result.switch_to {
                if let Some(child) = thread::get_thread(child_tid) {
                    child.cpu_state.frame.rsp = child_stack as u64;
                }
            }
        }

        result
    }
}

/// read(3)
fn sys_read(tid: usize, a: &Args, regs: &mut Regs) -> SyscallResult {
    let fd = a.a0 as usize;
    let buf = a.a1 as usize;
    let len = a.a2 as usize;

    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    let linux = linux_state(tid);
    let fd_kind = linux.fds[fd];

    match fd_kind {
        thread::FdKind::PipeRead(idx) => {
            let user_buf = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len) };
            let n = crate::kernel::kpipe::read(idx, user_buf);
            if n > 0 {
                return SyscallResult::val(n as i32);
            }
            // No data — check if writers exist
            if !crate::kernel::kpipe::has_writers(idx) {
                return SyscallResult::val(0); // EOF
            }
            // Block until data arrives
            let current = thread::get_thread(tid).unwrap();
            thread::save_state(current, regs);
            current.state = thread::ThreadState::Blocked;
            if let thread::ThreadMode::Linux(ref mut l) = current.mode {
                l.pending_read = Some(thread::PendingRead {
                    fd_kind,
                    buf_ptr: buf,
                    buf_len: len,
                });
            }
            let next = thread::schedule(tid).unwrap_or(tid);
            SyscallResult { retval: 0, switch_to: Some(next) }
        }
        thread::FdKind::Vfs(handle) => {
            let user_buf = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len) };
            SyscallResult::val(vfs::read_by_handle(handle, user_buf))
        }
        thread::FdKind::ConsoleOut | thread::FdKind::PipeWrite(_) => {
            SyscallResult::val(-EBADF)
        }
        thread::FdKind::None => SyscallResult::val(-EBADF),
    }
}

/// write(4)
fn sys_write(tid: usize, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    let buf = a.a1 as usize as *const u8;
    let len = a.a2 as usize;

    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    let linux = linux_state(tid);
    let fd_kind = linux.fds[fd];

    match fd_kind {
        thread::FdKind::ConsoleOut => {
            unsafe {
                for i in 0..len {
                    vga::vga().putchar(*buf.add(i));
                }
            }
            SyscallResult::val(len as i32)
        }
        thread::FdKind::PipeWrite(idx) => {
            let data = unsafe { core::slice::from_raw_parts(buf, len) };
            let r = crate::kernel::kpipe::write(idx, data);
            if r < 0 {
                SyscallResult::val(-EPIPE)
            } else {
                SyscallResult::val(r)
            }
        }
        thread::FdKind::Vfs(handle) => {
            let data = unsafe { core::slice::from_raw_parts(buf, len) };
            SyscallResult::val(vfs::write_by_handle(handle, data))
        }
        thread::FdKind::PipeRead(_) | thread::FdKind::None => {
            SyscallResult::val(-EBADF)
        }
    }
}

/// open(5)
fn sys_open(tid: usize, a: &Args) -> SyscallResult {
    let path_ptr = a.a0 as usize;
    let path = unsafe { read_c_str(path_ptr, 256) };

    let mut buf = [0u8; 164];
    let cwd = thread_cwd(tid);
    let resolved = resolve_path(path, cwd, &mut buf);
    let handle = vfs::open_to_handle(resolved);
    if handle < 0 { return SyscallResult::val(handle); }

    let linux = linux_state(tid);
    match linux.alloc_fd(3) {
        Some(fd) => {
            linux.fds[fd] = thread::FdKind::Vfs(handle);
            SyscallResult::val(fd as i32)
        }
        None => {
            vfs::close_vfs_handle(handle);
            SyscallResult::val(-24) // EMFILE
        }
    }
}

/// close(6)
fn sys_close(tid: usize, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    let linux = linux_state(tid);
    if linux.fds[fd].is_none() { return SyscallResult::val(-EBADF); }
    linux.close_fd(fd);
    SyscallResult::val(0)
}

/// execve(11)
fn sys_execve(tid: usize, a: &Args, regs: &mut Regs) -> SyscallResult {
    let path_ptr = a.a0 as usize;
    let argv_ptr = a.a1 as usize;
    let _envp_ptr = a.a2 as usize;

    let path = unsafe { read_c_str(path_ptr, 256) };

    let is_com = has_ext(path, b"COM");
    let is_exe = has_ext(path, b"EXE");

    // Read argv from caller's address space before we free it
    let args = read_c_argv32(argv_ptr);

    // Snapshot cwd, close CLOEXEC fds, drop symbols
    let cwd_snapshot: [u8; 64];
    let cwd_len_snapshot: usize;
    {
        let current = thread::get_thread(tid).unwrap();
        match &mut current.mode {
            thread::ThreadMode::Dos(d) => {
                vfs::close_all_fds(&mut d.fds);
                cwd_snapshot = d.cwd;
                cwd_len_snapshot = d.cwd_len;
                d.symbols = None;
            }
            thread::ThreadMode::Linux(l) => {
                l.close_cloexec();
                cwd_snapshot = l.cwd;
                cwd_len_snapshot = l.cwd_len;
                l.symbols = None;
            }
        }
    }

    // Resolve path + open via handle-based VFS
    let mut path_buf = [0u8; 164];
    let resolved = resolve_path(path, &cwd_snapshot[..cwd_len_snapshot], &mut path_buf);
    let handle = vfs::open_to_handle(resolved);
    if handle < 0 { return SyscallResult::val(-ENOENT); }
    let size = vfs::file_size_by_handle(handle) as usize;
    let mut buffer = alloc::vec![0; size];
    vfs::read_by_handle(handle, &mut buffer);
    vfs::close_vfs_handle(handle);

    let want_64 = match lib::elf::Elf::parse(&buffer) {
        Ok(e) => e.class() == lib::elf::ElfClass::Elf64,
        Err(_) => false,
    };

    // DOS executables
    if is_com || is_exe {
        exec_dos(tid, &buffer, is_exe, resolved);
        *regs = thread::get_thread(tid).unwrap().cpu_state;
        return SyscallResult { retval: 0, switch_to: Some(tid) };
    }

    // Check if this is a vfork child (shares parent's address space)
    let vfork_parent = {
        let current = thread::get_thread(tid).unwrap();
        match &current.mode {
            thread::ThreadMode::Linux(l) => l.vfork_parent,
            _ => None,
        }
    };

    if vfork_parent.is_some() {
        // Vfork child: allocate a fresh address space, don't touch parent's pages.
        let mut new_root = crate::RootPageTable::empty();
        startup::arch_switch_to(
            &mut thread::get_thread(tid).unwrap().cpu_state,
            &mut new_root,
            core::ptr::null_mut(),
        );
        // Now running in a blank address space — set it as this thread's root
        thread::get_thread(tid).unwrap().root = new_root;
    } else {
        // Normal execve: free old address space
        startup::arch_user_clean();
    }

    let loaded = match elf::load_elf(&buffer) {
        Ok(e) => e,
        Err(_) => {
            return SyscallResult { retval: 0, switch_to: Some(thread::exit_thread(tid, -ENOEXEC)) };
        }
    };

    let symbols = SymbolData::new(buffer.into_boxed_slice());

    let current = thread::get_thread(tid).unwrap();

    // Set up Linux-style argv on new user stack
    let sp = setup_user_stack(&args, want_64);

    if want_64 {
        thread::init_process_thread_64(current, loaded.entry, sp as u64);
    } else {
        thread::init_process_thread(current, loaded.entry as u32, sp as u32);
    }

    // Initialize heap state (fds 0/1/2 survive from parent — only CLOEXEC fds were closed)
    match &mut current.mode {
        thread::ThreadMode::Linux(l) => {
            l.symbols = symbols;
            l.heap_base = loaded.max_vaddr;
            l.heap_end = loaded.max_vaddr;
            l.mmap_cursor = elf::USER_STACK_TOP - 0x0100_0000;
            // Clear vfork flag and unblock parent
            if let Some(parent_tid) = l.vfork_parent.take() {
                thread::unblock_thread(parent_tid);
            }
        }
        thread::ThreadMode::Dos(d) => {
            d.symbols = symbols;
        }
    }

    *regs = current.cpu_state;
    SyscallResult { retval: 0, switch_to: Some(tid) }
}

/// Execute a DOS program (.COM or .EXE) in VM86 mode.
fn exec_dos(tid: usize, data: &[u8], is_exe: bool, prog_name: &[u8]) {
    use crate::kernel::vm86;

    startup::arch_user_clean();
    startup::arch_map_low_mem();
    vm86::setup_ivt();

    let (cs, ip, ss, sp, end_seg) = if is_exe && vm86::is_mz_exe(data) {
        vm86::load_exe(data, prog_name).unwrap_or_else(|| {
            crate::println!("Invalid MZ EXE");
            (0, 0, 0, 0, 0)
        })
    } else {
        vm86::load_com(data, prog_name)
    };

    let current = thread::get_thread(tid).unwrap();
    thread::init_process_thread_vm86(current, vm86::COM_SEGMENT, cs, ip, ss, sp);
    let dos = current.dos_mut();
    dos.vm86.heap_seg = end_seg;
    dos.vm86.dta = (vm86::COM_SEGMENT as u32) * 16 + 0x80;
    dos.symbols = None;
}

/// chdir(12)
fn sys_chdir(tid: usize, a: &Args) -> SyscallResult {
    let path = unsafe { read_c_str(a.a0 as usize, 256) };
    let (cwd, cwd_len) = match &mut thread::get_thread(tid).unwrap().mode {
        thread::ThreadMode::Dos(d) => (&mut d.cwd, &mut d.cwd_len),
        thread::ThreadMode::Linux(l) => (&mut l.cwd, &mut l.cwd_len),
    };
    SyscallResult::val(do_chdir(path, cwd, cwd_len))
}

/// time(13) — stub
fn sys_time(a: &Args) -> SyscallResult {
    let ptr = a.a0 as usize;
    if ptr != 0 {
        unsafe { *(ptr as *mut u32) = 0; }
    }
    SyscallResult::val(0)
}

/// lseek(19)
fn sys_lseek(tid: usize, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    let offset = a.a1 as i32;
    let whence = a.a2 as i32;
    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    match linux_state(tid).fds[fd] {
        thread::FdKind::Vfs(handle) => SyscallResult::val(vfs::seek_by_handle(handle, offset, whence)),
        thread::FdKind::PipeRead(_) | thread::FdKind::PipeWrite(_) => SyscallResult::val(-ESPIPE),
        _ => SyscallResult::val(-EBADF),
    }
}

/// getpid(20)
fn sys_getpid(tid: usize) -> SyscallResult {
    SyscallResult::val(tid as i32)
}

/// access(33) — check file existence via VFS stat
fn sys_access(tid: usize, a: &Args) -> SyscallResult {
    let path = unsafe { read_c_str(a.a0 as usize, 256) };
    let mut buf = [0u8; 164];
    let cwd = thread_cwd(tid);
    let resolved = resolve_path(path, cwd, &mut buf);
    let handle = vfs::open_to_handle(resolved);
    if handle < 0 {
        return SyscallResult::val(-ENOENT);
    }
    vfs::close_vfs_handle(handle);
    SyscallResult::val(0)
}

/// brk(45)
fn sys_brk(tid: usize, a: &Args) -> SyscallResult {
    let addr = a.a0 as usize;
    let t = thread::get_thread(tid).unwrap();
    let linux = match &mut t.mode {
        thread::ThreadMode::Linux(l) => l,
        _ => return SyscallResult::val64(0),
    };

    if addr == 0 {
        // Query current brk
        return SyscallResult::val64(linux.heap_end as i64);
    }

    let new_end = addr.max(linux.heap_base).min(linux.mmap_cursor);
    linux.heap_end = new_end;
    SyscallResult::val64(linux.heap_end as i64)
}

/// fcntl(55) / fcntl64(221)
fn sys_fcntl(tid: usize, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    let cmd = a.a1 as i32;
    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    let linux = linux_state(tid);
    if linux.fds[fd].is_none() { return SyscallResult::val(-EBADF); }

    const F_GETFD: i32 = 1;
    const F_SETFD: i32 = 2;
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;
    const FD_CLOEXEC: i32 = 1;

    match cmd {
        F_GETFD => {
            let cloexec = if linux.cloexec & (1 << fd) != 0 { FD_CLOEXEC } else { 0 };
            SyscallResult::val(cloexec)
        }
        F_SETFD => {
            let arg = a.a2 as i32;
            if arg & FD_CLOEXEC != 0 {
                linux.cloexec |= 1 << fd;
            } else {
                linux.cloexec &= !(1 << fd);
            }
            SyscallResult::val(0)
        }
        F_GETFL | F_SETFL => SyscallResult::val(0), // stub
        _ => SyscallResult::val(-EINVAL),
    }
}

/// munmap(91)
fn sys_munmap(tid: usize, a: &Args) -> SyscallResult {
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
fn sys_wait4(tid: usize, a: &Args, regs: &mut Regs) -> SyscallResult {
    let pid = a.a0 as i32;
    let status_ptr = a.a1 as usize;
    let _options = a.a2 as i32;

    let (child_tid, exit_code) = thread::waitpid(tid, pid);

    if child_tid >= 0 {
        // Write status: Linux encodes as (exit_code << 8) for normal exit
        if status_ptr != 0 {
            unsafe { *(status_ptr as *mut i32) = (exit_code & 0xFF) << 8; }
        }
        return SyscallResult::val(child_tid);
    }

    if child_tid == -10 {
        // ECHILD — no children
        return SyscallResult::val(-ECHILD);
    }

    // EAGAIN — children exist but none exited. Block and yield.
    let current = thread::get_thread(tid).unwrap();
    thread::save_state(current, regs);
    current.state = thread::ThreadState::Blocked;
    let next = thread::schedule(tid).unwrap_or(0);
    SyscallResult { retval: 0, switch_to: Some(next) }
}

/// uname(122)
fn sys_uname(a: &Args) -> SyscallResult {
    let buf = a.a0 as usize as *mut u8;
    if buf.is_null() { return SyscallResult::val(-EFAULT); }

    // Linux struct old_utsname: 5 fields, 65 bytes each
    unsafe {
        let p = buf;
        core::ptr::write_bytes(p, 0, 65 * 6);
        let write_field = |offset: usize, s: &[u8]| {
            let dst = p.add(offset);
            core::ptr::copy_nonoverlapping(s.as_ptr(), dst, s.len().min(64));
        };
        write_field(0, b"Linux");
        write_field(65, b"retroos");
        write_field(130, b"5.0.0");
        write_field(195, b"#1");
        write_field(260, b"i686");
        write_field(325, b"(none)");
    }
    SyscallResult::val(0)
}

/// _llseek(140) — 64-bit lseek
fn sys_llseek(tid: usize, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    let offset_hi = a.a1 as u32;
    let offset_lo = a.a2 as u32;
    let result_ptr = a.a3 as usize;
    let whence = a.a4 as i32;

    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    let handle = match linux_state(tid).fds[fd] {
        thread::FdKind::Vfs(h) => h,
        thread::FdKind::PipeRead(_) | thread::FdKind::PipeWrite(_) => return SyscallResult::val(-ESPIPE),
        _ => return SyscallResult::val(-EBADF),
    };

    let offset = ((offset_hi as i64) << 32) | (offset_lo as i64);
    let r = vfs::seek_by_handle(handle, offset as i32, whence);
    if r < 0 { return SyscallResult::val(r); }

    if result_ptr != 0 {
        unsafe { *(result_ptr as *mut i64) = r as i64; }
    }
    SyscallResult::val(0)
}

/// writev(146)
fn sys_writev(tid: usize, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    let iov_ptr = a.a1 as usize;
    let iovcnt = a.a2 as usize;

    if iovcnt > 1024 { return SyscallResult::val(-EINVAL); }
    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    let fd_kind = linux_state(tid).fds[fd];

    let mut total = 0i32;

    for i in 0..iovcnt {
        // struct iovec { void *iov_base; size_t iov_len; } — 8 bytes on i386
        let base_addr = iov_ptr + i * 8;
        let iov_base = unsafe { *(base_addr as *const u32) } as usize;
        let iov_len = unsafe { *((base_addr + 4) as *const u32) } as usize;

        if iov_len == 0 { continue; }

        match fd_kind {
            thread::FdKind::ConsoleOut => {
                unsafe {
                    for j in 0..iov_len {
                        vga::vga().putchar(*(iov_base as *const u8).add(j));
                    }
                }
                total += iov_len as i32;
            }
            thread::FdKind::PipeWrite(idx) => {
                let data = unsafe { core::slice::from_raw_parts(iov_base as *const u8, iov_len) };
                let r = crate::kernel::kpipe::write(idx, data);
                if r < 0 { return SyscallResult::val(-EPIPE); }
                total += r;
            }
            thread::FdKind::Vfs(handle) => {
                let data = unsafe { core::slice::from_raw_parts(iov_base as *const u8, iov_len) };
                let r = vfs::write_by_handle(handle, data);
                if r < 0 { return SyscallResult::val(r); }
                total += r;
            }
            _ => return SyscallResult::val(-EBADF),
        }
    }

    SyscallResult::val(total)
}

/// sched_yield(158)
fn sys_sched_yield(tid: usize, regs: &mut Regs) -> SyscallResult {
    let current = thread::get_thread(tid).unwrap();
    thread::save_state(current, regs);
    thread::set_return(current, 0);
    current.state = thread::ThreadState::Ready;
    SyscallResult { retval: 0, switch_to: thread::schedule(tid) }
}

/// nanosleep(162) — stub: yield once
fn sys_nanosleep() -> SyscallResult {
    SyscallResult::val(0)
}

/// poll(168) — report readability/writability based on FdKind
fn sys_poll(tid: usize, a: &Args) -> SyscallResult {
    let fds_ptr = a.a0 as usize;
    let nfds = a.a1 as usize;
    let linux = linux_state(tid);

    // struct pollfd { int fd; short events; short revents; } = 8 bytes
    let mut ready = 0i32;
    for i in 0..nfds {
        let base = fds_ptr + i * 8;
        let fd = unsafe { *(base as *const i32) } as usize;
        let events = unsafe { *((base + 4) as *const i16) };
        let mut revents: i16 = 0;
        const POLLIN: i16 = 1;
        const POLLOUT: i16 = 4;

        if fd < thread::MAX_FDS {
            match linux.fds[fd] {
                thread::FdKind::PipeRead(idx) => {
                    if (events & POLLIN) != 0 && crate::kernel::kpipe::has_data(idx) {
                        revents |= POLLIN;
                    }
                }
                thread::FdKind::ConsoleOut => {
                    if (events & POLLOUT) != 0 { revents |= POLLOUT; }
                }
                thread::FdKind::PipeWrite(idx) => {
                    if (events & POLLOUT) != 0 { revents |= POLLOUT; }
                }
                thread::FdKind::Vfs(_) => {
                    // VFS files: always readable/writable for poll
                    if (events & POLLIN) != 0 { revents |= POLLIN; }
                    if (events & POLLOUT) != 0 { revents |= POLLOUT; }
                }
                thread::FdKind::None => {}
            }
        }
        unsafe { *((base + 6) as *mut i16) = revents; }
        if revents != 0 { ready += 1; }
    }
    SyscallResult::val(ready)
}

/// getcwd(183)
fn sys_getcwd(tid: usize, a: &Args) -> SyscallResult {
    let ptr = a.a0 as usize as *mut u8;
    let size = a.a1 as usize;
    let cwd = match &thread::get_thread(tid).unwrap().mode {
        thread::ThreadMode::Dos(d) => d.cwd_str(),
        thread::ThreadMode::Linux(l) => l.cwd_str(),
    };
    // Linux getcwd returns absolute path with leading /
    if size < cwd.len() + 2 { return SyscallResult::val(-EINVAL); }
    unsafe {
        *(ptr) = b'/';
        core::ptr::copy_nonoverlapping(cwd.as_ptr(), ptr.add(1), cwd.len());
        *(ptr.add(1 + cwd.len())) = 0; // NUL
    }
    SyscallResult::val((cwd.len() + 2) as i32)
}

/// mmap2(192) — anonymous private only
fn sys_mmap2(tid: usize, a: &Args) -> SyscallResult {
    let addr_hint = a.a0 as usize;
    let length = a.a1 as usize;
    let _prot = a.a2 as u32;
    let flags = a.a3 as u32;
    let fd = a.a4 as i32;
    let _offset_pages = a.a5 as u32;

    const MAP_ANONYMOUS: u32 = 0x20;
    const MAP_PRIVATE: u32 = 0x02;
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

    let t = thread::get_thread(tid).unwrap();
    let linux = match &mut t.mode {
        thread::ThreadMode::Linux(l) => l,
        _ => return SyscallResult::val64(-ENOSYS as i64),
    };

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
fn sys_stat64(tid: usize, a: &Args) -> SyscallResult {
    let path_ptr = a.a0 as usize;
    let stat_buf = a.a1 as usize;
    let path = unsafe { read_c_str(path_ptr, 256) };

    let mut pbuf = [0u8; 164];
    let cwd = thread_cwd(tid);
    let resolved = resolve_path(path, cwd, &mut pbuf);

    // Check if it's a directory
    if vfs::dir_exists(resolved) {
        write_stat64(stat_buf, 0o40755, 0);
        return SyscallResult::val(0);
    }

    let handle = vfs::open_to_handle(resolved);
    if handle < 0 { return SyscallResult::val(-ENOENT); }
    let size = vfs::file_size_by_handle(handle);
    vfs::close_vfs_handle(handle);
    write_stat64(stat_buf, 0o100644, size);
    SyscallResult::val(0)
}

/// fstat64(197)
fn sys_fstat64(tid: usize, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    let stat_buf = a.a1 as usize;

    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    match linux_state(tid).fds[fd] {
        thread::FdKind::ConsoleOut | thread::FdKind::PipeRead(_) | thread::FdKind::PipeWrite(_) => {
            // stdin/stdout/stderr / pipes — character device / pipe
            write_stat64(stat_buf, 0o20666, 0); // S_IFCHR
            SyscallResult::val(0)
        }
        thread::FdKind::Vfs(handle) => {
            let size = vfs::file_size_by_handle(handle);
            write_stat64(stat_buf, 0o100644, size); // S_IFREG
            SyscallResult::val(0)
        }
        thread::FdKind::None => SyscallResult::val(-EBADF),
    }
}

/// fstatat64(300)
fn sys_fstatat64(tid: usize, a: &Args) -> SyscallResult {
    let _dirfd = a.a0 as i32;
    // Treat as stat64 on the path (a.a1 = path, a.a2 = stat buf)
    let shifted = Args { a0: a.a1, a1: a.a2, a2: a.a3, a3: a.a4, a4: a.a5, a5: 0 };
    sys_stat64(tid, &shifted)
}

/// Write a minimal Linux stat64 struct to user memory.
/// struct stat64 on i386 is 96 bytes. We fill mode, size, blksize.
fn write_stat64(buf: usize, mode: u32, size: u32) {
    unsafe {
        core::ptr::write_bytes(buf as *mut u8, 0, 96);
        // st_mode at offset 16 (u32)
        *((buf + 16) as *mut u32) = mode;
        // st_size at offset 44 (u64 on stat64)
        *((buf + 44) as *mut u64) = size as u64;
        // st_blksize at offset 56 (u32)
        *((buf + 56) as *mut u32) = 4096;
        // st_blocks at offset 64 (u64) — size / 512
        *((buf + 64) as *mut u64) = ((size as u64) + 511) / 512;
    }
}

/// getdents64(220)
fn sys_getdents64(tid: usize, a: &Args) -> SyscallResult {
    let fd = a.a0 as i32;
    let dirp = a.a1 as usize;
    let count = a.a2 as usize;

    // We don't have directory fds — use the thread's cwd as the directory.
    // This is a simplification: real getdents64 works with an fd from openat.
    // For now: if fd matches an open fd, check if it's a directory path.
    let cwd = match &thread::get_thread(tid).unwrap().mode {
        thread::ThreadMode::Dos(d) => &d.cwd[..d.cwd_len],
        thread::ThreadMode::Linux(l) => &l.cwd[..l.cwd_len],
    };

    let mut offset = 0usize;
    let mut index = 0usize;

    loop {
        let entry = match vfs::readdir(cwd, index) {
            Some(e) => e,
            None => break,
        };
        index += 1;

        let name = &entry.name[..entry.name_len];
        // struct linux_dirent64: d_ino(8) + d_off(8) + d_reclen(2) + d_type(1) + d_name[...]
        let reclen = (19 + name.len() + 1 + 7) & !7; // 8-byte align
        if offset + reclen > count { break; }

        let base = dirp + offset;
        unsafe {
            core::ptr::write_bytes(base as *mut u8, 0, reclen);
            *(base as *mut u64) = index as u64;         // d_ino
            *((base + 8) as *mut u64) = index as u64;   // d_off
            *((base + 16) as *mut u16) = reclen as u16;  // d_reclen
            *((base + 18) as *mut u8) = if entry.is_dir { 4 } else { 8 }; // d_type: DT_DIR/DT_REG
            core::ptr::copy_nonoverlapping(name.as_ptr(), (base + 19) as *mut u8, name.len());
        }
        offset += reclen;
    }

    SyscallResult::val(offset as i32)
}

/// set_thread_area(243) — parse user_desc struct, set GDT TLS entry
fn sys_set_thread_area(a: &Args) -> SyscallResult {
    let u_info = a.a0 as usize;
    if u_info == 0 { return SyscallResult::val(-EFAULT); }

    // struct user_desc { entry_number: i32, base_addr: u32, limit: u32, flags: u32 }
    let entry_number = unsafe { *(u_info as *const i32) };
    let base_addr = unsafe { *((u_info + 4) as *const u32) };
    let limit = unsafe { *((u_info + 8) as *const u32) };
    let flags = unsafe { *((u_info + 12) as *const u32) };
    let limit_in_pages = flags & (1 << 4) != 0;

    let idx = startup::arch_set_tls_entry(entry_number, base_addr, limit, limit_in_pages);
    if idx < 0 { return SyscallResult::val(-ESRCH); }

    // Write back the allocated entry number
    unsafe { *(u_info as *mut i32) = idx; }
    SyscallResult::val(0)
}

/// sys_set_thread_area variant that also saves TLS state to LinuxState for context-switch restore
fn sys_set_thread_area_with_tid(tid: usize, a: &Args) -> SyscallResult {
    let result = sys_set_thread_area(a);
    if result.retval == 0 {
        let u_info = a.a0 as usize;
        let t = thread::get_thread(tid).unwrap();
        if let thread::ThreadMode::Linux(l) = &mut t.mode {
            l.tls_entry = unsafe { *(u_info as *const i32) };
            l.tls_base = unsafe { *((u_info + 4) as *const u32) };
            l.tls_limit = unsafe { *((u_info + 8) as *const u32) };
            l.tls_limit_in_pages = unsafe { *((u_info + 12) as *const u32) } & (1 << 4) != 0;
        }
    }
    result
}

/// set_tid_address(258)
fn sys_set_tid_address(tid: usize) -> SyscallResult {
    SyscallResult::val(tid as i32)
}

/// clock_gettime(265) — monotonic from tick counter
fn sys_clock_gettime(a: &Args) -> SyscallResult {
    let _clock_id = a.a0 as u32;
    let tp = a.a1 as usize;
    if tp != 0 {
        let ticks = crate::arch::get_ticks() as u64;
        // PIT ticks at ~1193182 Hz, timer IRQ at ~100 Hz (div=11932)
        let secs = ticks / 100;
        let nsecs = (ticks % 100) * 10_000_000;
        unsafe {
            *(tp as *mut u32) = secs as u32;       // tv_sec
            *((tp + 4) as *mut u32) = nsecs as u32; // tv_nsec
        }
    }
    SyscallResult::val(0)
}

/// openat(295) — treat AT_FDCWD as cwd-relative, else EBADF
fn sys_openat(tid: usize, a: &Args) -> SyscallResult {
    let dirfd = a.a0 as i32;
    const AT_FDCWD: i32 = -100;
    if dirfd != AT_FDCWD && dirfd < 0 {
        return SyscallResult::val(-EBADF);
    }
    // Shift args: a1=path, a2=flags, a3=mode → treat as open(path, flags, mode)
    let shifted = Args { a0: a.a1, a1: a.a2, a2: a.a3, a3: 0, a4: 0, a5: 0 };
    sys_open(tid, &shifted)
}

/// getrandom(355) — stub: fill with PRNG output
fn sys_getrandom(a: &Args) -> SyscallResult {
    let buf = a.a0 as usize;
    let buflen = a.a1 as usize;
    unsafe {
        let p = buf as *mut u8;
        for i in 0..buflen {
            *p.add(i) = thread::prng() as u8;
        }
    }
    SyscallResult::val(buflen as i32)
}

/// pipe(42) / pipe2(359)
fn sys_pipe(tid: usize, a: &Args, is_pipe2: bool) -> SyscallResult {
    let pipefd_ptr = a.a0 as usize;
    let flags = if is_pipe2 { a.a1 as u32 } else { 0 };
    const O_CLOEXEC: u32 = 0o2000000;

    let pipe_idx = match crate::kernel::kpipe::alloc() {
        Some(idx) => idx,
        None => return SyscallResult::val(-24), // EMFILE
    };

    let linux = linux_state(tid);
    let read_fd = match linux.alloc_fd(0) {
        Some(fd) => fd,
        None => {
            crate::kernel::kpipe::close_reader(pipe_idx);
            crate::kernel::kpipe::close_writer(pipe_idx);
            return SyscallResult::val(-24);
        }
    };
    linux.fds[read_fd] = thread::FdKind::PipeRead(pipe_idx);

    let write_fd = match linux.alloc_fd(0) {
        Some(fd) => fd,
        None => {
            linux.close_fd(read_fd);
            crate::kernel::kpipe::close_writer(pipe_idx);
            return SyscallResult::val(-24);
        }
    };
    linux.fds[write_fd] = thread::FdKind::PipeWrite(pipe_idx);

    if flags & O_CLOEXEC != 0 {
        linux.cloexec |= (1 << read_fd) | (1 << write_fd);
    }

    // Write [read_fd, write_fd] to user pointer
    unsafe {
        *(pipefd_ptr as *mut i32) = read_fd as i32;
        *((pipefd_ptr + 4) as *mut i32) = write_fd as i32;
    }
    SyscallResult::val(0)
}

/// dup2(63)
fn sys_dup2(tid: usize, a: &Args) -> SyscallResult {
    let oldfd = a.a0 as usize;
    let newfd = a.a1 as usize;

    if oldfd >= thread::MAX_FDS || newfd >= thread::MAX_FDS {
        return SyscallResult::val(-EBADF);
    }

    let linux = linux_state(tid);
    if linux.fds[oldfd].is_none() { return SyscallResult::val(-EBADF); }

    // If same fd, just return it
    if oldfd == newfd { return SyscallResult::val(newfd as i32); }

    // Close newfd if open
    if !linux.fds[newfd].is_none() {
        linux.close_fd(newfd);
    }

    // Copy fd kind and increment refcount
    let kind = linux.fds[oldfd];
    match kind {
        thread::FdKind::Vfs(handle) => vfs::add_vfs_ref(handle),
        thread::FdKind::PipeRead(idx) => crate::kernel::kpipe::add_reader(idx),
        thread::FdKind::PipeWrite(idx) => crate::kernel::kpipe::add_writer(idx),
        thread::FdKind::ConsoleOut | thread::FdKind::None => {}
    }
    linux.fds[newfd] = kind;
    // dup2 does NOT inherit cloexec
    linux.cloexec &= !(1 << newfd);

    SyscallResult::val(newfd as i32)
}
