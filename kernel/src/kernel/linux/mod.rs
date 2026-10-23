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

macro_rules! linux_trace {
    ($($arg:tt)*) => {
        if crate::kernel::startup::trace_enabled() {
            $crate::compact_dbg_println!($($arg)*);
        }
    };
}

mod async_io;
mod entropy;
mod record_lock;
pub(crate) mod environment;
mod file_mapping;
mod shared_mapping;
mod file_io;
mod tty;
mod time;
mod itimer;
mod vsyscall;
mod system;
mod signals;
mod proc_fd;
mod script;
mod limits;
mod message;
mod select;

use crate::kernel::elf;
use crate::kernel::thread;
use crate::kernel::thread::{FdKind, PendingRead, PendingPoll, MAX_FDS};
use crate::kernel::vfs;
use crate::Regs;
use crate::compact_println;

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

pub fn repaint_console() { crate::kernel::term::mark_dirty(); }

pub fn try_signal_fault<A: crate::Arch>(machine: &mut A, linux: &mut LinuxState,
    process: i32, regs: &mut Regs, addr: u32) -> bool {
    signals::deliver_fault(machine, linux, process, regs, addr)
}

/// One terminal presentation, independent of which Linux process runs in it.
pub const CONSOLE_ENDPOINT: crate::kernel::gui::EndpointId =
    crate::kernel::gui::EndpointId(u32::MAX - 1);
static CONSOLE_FOREGROUND: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

pub fn console_foreground<A: crate::Arch>(threads: &[thread::Thread<A>]) -> Option<usize> {
    let live_linux = |t: &thread::Thread<A>| matches!(t.personality, thread::Personality::Linux(_))
        && matches!(t.kernel.state, thread::ThreadState::Running
            | thread::ThreadState::Ready | thread::ThreadState::Blocked);
    let tid = CONSOLE_FOREGROUND.load(core::sync::atomic::Ordering::Relaxed);
    if threads.get(tid).is_some_and(live_linux) { return Some(tid); }
    threads.iter().enumerate().skip(1).rev()
        .find(|(_, t)| live_linux(t)).map(|(tid, _)| tid)
}

pub fn foreground_console(tid: usize) {
    CONSOLE_FOREGROUND.store(tid, core::sync::atomic::Ordering::Relaxed);
}

/// Render the shared terminal into its packed shadow, composite the OSD, and
/// publish that completed frame through the focused Linux display.
pub fn render<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    display: &mut crate::kernel::display::Display,
    desktop: &mut crate::kernel::gui::Desktop,
    endpoint: crate::kernel::gui::EndpointId,
) {
    crate::kernel::term::present_on(machine, bios, display, desktop, endpoint);
}

/// Linux-specific thread state
pub struct LinuxState {
    alarm: itimer::Timer,
    vfork_parent: Option<usize>,
    keyboard: alloc::sync::Arc<spin::Mutex<lib::keyboard::State>>,
    async_io: async_io::State,
    signals: signals::State,
    tty: alloc::sync::Arc<spin::Mutex<tty::Console>>,
    pub heap_base: usize,
    pub heap_end: usize,
    pub mmap_cursor: usize,
    occupied_ranges: alloc::vec::Vec<(usize, usize)>,
    shared_mappings: shared_mapping::State,
    pub tls_entry: i32,            // GDT index for TLS (13-15), -1 = none
    pub tls_base: u32,
    pub tls_limit: u32,
    pub tls_limit_in_pages: bool,
    pub pending_read: Option<PendingRead>,  // Blocked read on any fd kind
    pub pending_poll: Option<PendingPoll>,  // Blocked poll on a pollfd array
    pending_socket: Option<PendingSocket>,
    pending_select:Option<select::Request>,
    pending_random: Option<entropy::Request>,
    pending_flock: Option<(i32, u32)>,
    pending_record_lock: Option<record_lock::Request>,
    pub wait_status_ptr: usize,            // Deferred wait4 status write
    pub wait_exit_code: i32,
    waiting_child: Option<i32>,
    reap_child: Option<usize>,
    /// VFS-form cwd (lowercase, forward-slash, no leading/trailing slash).
    /// Linux personality stores cwd here; DOS personality stores it inside
    /// `DosState.dfs` in DOS-form (uppercase, backslash). KernelThread carries
    /// no cwd of its own — see CLAUDE notes on personality-owned state.
    pub cwd: [u8; vfs::PATH_KEY_MAX],
    pub cwd_len: usize,
    /// Path this process's image was loaded from — what `/proc/self/exe`
    /// resolves to. Set on each successful exec; preserved across the
    /// in-place ELF execve. Lets self-re-exec'ing binaries (busybox standalone
    /// shell) find themselves without a real /proc or any hardcoded path.
    pub exec_path: [u8; vfs::PATH_KEY_MAX],
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
            alarm: itimer::Timer::default(),
            vfork_parent: None,
            keyboard: alloc::sync::Arc::new(spin::Mutex::new(lib::keyboard::State::new())),
            async_io: async_io::State::default(),
            signals: signals::State::default(),
            tty: alloc::sync::Arc::new(spin::Mutex::new(tty::Console::new())),
            heap_base: 0,
            heap_end: 0,
            mmap_cursor: crate::kernel::elf::USER_STACK_TOP - 0x0100_0000,
            occupied_ranges: alloc::vec::Vec::new(),
            shared_mappings: shared_mapping::State::default(),
            tls_entry: -1,
            tls_base: 0,
            tls_limit: 0,
            tls_limit_in_pages: false,
            pending_read: None,
            pending_poll: None,
            pending_socket: None,
            pending_select:None,
            pending_random: None,
            pending_flock: None,
            pending_record_lock: None,
            wait_status_ptr: 0,
            wait_exit_code: 0,
            waiting_child: None,
            reap_child: None,
            cwd: [0; vfs::PATH_KEY_MAX],
            cwd_len: 0,
            exec_path: [0; vfs::PATH_KEY_MAX],
            exec_path_len: 0,
        }
    }

    pub fn waits_for_record_lock(&self) -> bool { self.pending_record_lock.is_some() }

    pub(crate) fn shares_terminal(&self, other: &Self) -> bool {
        alloc::sync::Arc::ptr_eq(&self.tty, &other.tty)
    }

    pub(crate) fn has_blocked_work(&self) -> bool {
        self.pending_read.is_some() || self.pending_poll.is_some()
            || self.pending_socket.is_some() || self.pending_select.is_some()
            || self.pending_random.is_some() || self.pending_flock.is_some()
            || self.pending_record_lock.is_some() || self.waiting_child.is_some()
            || async_io::parked(&self.async_io)
    }

    pub(crate) fn borrows_space_from(&self, parent: usize) -> bool {
        self.vfork_parent == Some(parent)
    }

    pub(crate) fn waits_for_child(&self, child: i32) -> bool {
        self.waiting_child.is_some_and(|pid| pid == -1 || pid == child)
    }

    pub(crate) fn child_wait_completed(&mut self, child: usize, code: i32) {
        self.waiting_child = None;
        self.wait_exit_code = code;
        self.reap_child = Some(child);
    }

    pub fn close_virtual_fds(&mut self) { self.async_io = async_io::State::default(); }

    /// Called only after this process's guest aliases have been removed.
    pub(crate) fn release_mappings<A: crate::Arch>(&mut self, machine: &mut A) {
        self.shared_mappings.release(machine, 0, usize::MAX);
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

    /// Called on every swap-in (whether or not we're refocusing): rebind
    /// per-thread CPU state and finalize a deferred wait4 status write.
    pub fn on_resume<A: crate::Arch>(&mut self, machine: &mut A) {
        if self.tls_entry >= 0 {
            machine.set_tls_entry(
                self.tls_entry, self.tls_base,
                self.tls_limit, self.tls_limit_in_pages,
            );
        }
        if self.reap_child.is_some() && self.wait_status_ptr != 0 {
            machine.write::<i32>(self.wait_status_ptr, (self.wait_exit_code & 0xFF) << 8);
            self.wait_status_ptr = 0;
        }
    }

    /// Feed console input through the terminal settings shared by forked processes.
    pub fn process_key<A: crate::Arch>(&mut self, _machine: &mut A, _fds: &[FdKind; MAX_FDS], scancode: u8) {
        crate::compact_dbg_println!("KEY scan={:02X}", scancode);
        let mut keyboard = self.keyboard.lock();
        if !crate::kernel::keyboard::update_console(&mut keyboard,scancode) { return; }
        let event = crate::kernel::keyboard::event();
        let navigation = !((0x47..=0x53).contains(&event.scan) && event.length != 0);
        let sequence: &[u8] = match if navigation { scancode } else { 0 } {
            0x48 => b"\x1b[A", 0x50 => b"\x1b[B", 0x4d => b"\x1b[C", 0x4b => b"\x1b[D",
            0x47 => b"\x1b[H", 0x4f => b"\x1b[F", 0x49 => b"\x1b[5~", 0x51 => b"\x1b[6~",
            0x52 => b"\x1b[2~", 0x53 => b"\x1b[3~",
            0x3b => b"\x1bOP", 0x3c => b"\x1bOQ", 0x3d => b"\x1bOR", 0x3e => b"\x1bOS",
            0x3f => b"\x1b[15~", 0x40 => b"\x1b[17~", 0x41 => b"\x1b[18~", 0x42 => b"\x1b[19~",
            0x43 => b"\x1b[20~", 0x44 => b"\x1b[21~", 0x57 => b"\x1b[23~", 0x58 => b"\x1b[24~",
            0x0f if crate::kernel::keyboard::key_down(0x2a) || crate::kernel::keyboard::key_down(0x36) => b"\x1b[Z",
            _ => b"",
        };
        {
            // Keyboard input belongs to the controlling console, even while
            // the CPU polls a helper whose stdin is redirected to an IPC pipe.
            let idx = thread::console_pipe();
            let mut tty = self.tty.lock();
            tty.set_column(lib::term::term().cursor_pos().0);
            let mut feed = |bytes: &[u8]| tty.input(bytes, |data| { crate::kernel::kpipe::write(idx, data); }, || crate::kernel::kpipe::write_eof(idx), |data| {
                for &byte in data { lib::term::put_utf8(byte); }
                crate::kernel::term::mark_dirty();
            });
            if !sequence.is_empty() { feed(sequence); return; }
            if keyboard.down(0x38,false) && !keyboard.altgr() && event.length != 0 {
                feed(b"\x1b");
            }
            for &character in event.characters() {
                let mut bytes = [0;4];
                let character = if character == '\n' { '\r' } else { character };
                feed(character.encode_utf8(&mut bytes).as_bytes());
            }
        }
    }
}

// =============================================================================
// Extracted syscall arguments (mode-independent)
// =============================================================================

#[derive(Clone, Copy)]
struct Args {
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
}

struct PendingSocket {
    nr: u32,
    args: Args,
    mode64: bool,
    deadline: Option<u64>,
}

/// Only native socket operations are retried here. Hosted sockets keep their
/// existing backend behavior; MSG_DONTWAIT and O_NONBLOCK return immediately.
fn blocking_socket_call<A: crate::Arch>(
    machine: &mut A, kt: &thread::KernelThread<A>, nr: u32, args: Args, mode64: bool,
) -> Option<bool> {
    if !net::native_backend() { return None; }
    let (fd, flags, connect) = if !mode64 && nr == 102 {
        let mut raw = [0; 24];
        machine.copy_from(args.a1 as usize, &mut raw);
        let word = |i: usize| u32::from_le_bytes(raw[i * 4..i * 4 + 4].try_into().unwrap());
        match args.a0 {
            3 => (word(0) as usize, 0, true),
            5 | 18 => (word(0) as usize, 0, false),
            9..=12 | 20 => (word(0) as usize, word(3), false),
            16 | 17 => (word(0) as usize,word(2),false),
            _ => return None,
        }
    } else {
        match (mode64, nr) {
            (false, 3 | 4 | 146) | (true, 0 | 1 | 20 | 43 | 288) => (args.a0 as usize, 0, false),
            (true, 42) => (args.a0 as usize, 0, true),
            (true, 44 | 45 | 307) | (false,345) => (args.a0 as usize, args.a3 as u32, false),
            (true,46 | 47) | (false, 370 | 372)=>(args.a0 as usize,args.a2 as u32,false),
            _ => return None,
        }
    };
    let thread::FdKind::Socket(h) = *kt.fds.get(fd)? else { return None };
    if net::nonblocking(h) || flags & 0x40 != 0 { return None; }
    Some(connect)
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
        KE::Irq => { async_io::schedule(machine, kt, linux, regs); itimer::poll(machine, kt, linux, regs).unwrap_or(thread::KernelAction::Done) },
        // 32-bit user uses INT 0x80 (lands as SoftInt); 64-bit user uses the
        // SYSCALL instruction (lands as Syscall). Both reach the same dispatch.
        KE::SoftInt(0x80) | KE::Syscall => dispatch_action(machine, kt, linux, regs),
        KE::PageFault { .. } => unreachable!("PageFault handled in event loop"),
        _ => {
            crate::compact_dbg_println!("[LINUX] fatal {:?} at EIP={:#x} tid={}", kevent, regs.ip32(), kt.tid);
            thread::KernelAction::Exit(-11)
        }
    }
}

pub fn refresh_system_tasks<A: crate::Arch>(threads: &[thread::Thread<A>]) {
    system::refresh_tasks(threads);
}

/// Handle only recognized Linux legacy instruction-fetch entry points.
pub fn try_vsyscall<A: crate::Arch>(machine: &mut A, regs: &mut Regs, address: u32) -> bool {
    vsyscall::emulate(machine, regs, address)
}

/// Lock releases can wake another process without borrowing its guest memory.
pub fn wake_record_locks<A: crate::Arch>(threads: &mut [thread::Thread<A>], current: usize, regs: &mut Regs) {
    if !crate::kernel::fs::record_locks::take_changed() { return; }
    for thread in threads {
        if thread.kernel.state != thread::ThreadState::Blocked { continue; }
        if let thread::Personality::Linux(linux) = &mut thread.personality
            && let Some(request) = linux.pending_record_lock
            && let Some(n) = request.acquire() {
            linux.pending_record_lock = None;
            thread.kernel.state = thread::ThreadState::Ready;
            thread.kernel.vcpu.regs.rax = n as i64 as u64;
            if thread.kernel.tid as usize == current { regs.rax = n as i64 as u64; }
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
    if itimer::poll(machine, kt, linux, regs).is_some() { return; }
    if async_io::parked(&linux.async_io) {
        async_io::schedule(machine, kt, linux, regs);
        return;
    }
    if let Some(request) = linux.pending_record_lock {
        if let Some(result) = request.step(machine) {
            regs.rax = result as i64 as u64;
            linux.pending_record_lock = None;
            kt.state = thread::ThreadState::Ready;
        }
        return;
    }
    if let Some((handle, operation)) = linux.pending_flock {
        let result = vfs::flock(handle, operation);
        if result != -11 {
            regs.rax = result as i64 as u64;
            linux.pending_flock = None;
            kt.state = thread::ThreadState::Ready;
        }
        return;
    }
    if let Some(request) = linux.pending_random {
        if let Some(result) = request.step(machine) {
            regs.rax = result as i64 as u64;
            linux.pending_random = None;
            kt.state = thread::ThreadState::Ready;
        }
        return;
    }
    if let Some(request)=linux.pending_select {
        if let Some(result)=request.step(machine,kt) {regs.rax=result as i64 as u64;linux.pending_select=None;kt.state=thread::ThreadState::Ready;}
        return;
    }
    if let Some(pending) = linux.pending_socket.take() {
        let result = if pending.deadline.is_some_and(|end| crate::kernel::portio::now_ns() >= end) {
            SyscallResult::val(-110)
        } else if pending.mode64 {
            dispatch_nr_64(machine, kt, linux, pending.nr, &pending.args, regs)
        } else {
            dispatch_nr(machine, kt, linux, pending.nr, &pending.args, regs)
        };
        if result.retval == -11 {
            linux.pending_socket = Some(pending);
        } else {
            regs.rax = result.retval as u64;
            kt.state = thread::ThreadState::Ready;
        }
        return;
    }
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
            if let Some(n) = crate::kernel::kpipe::read_event(idx, &mut tmp) {
                machine.copy_to(buf_ptr, &tmp[..n]);
                regs.rax = n as u64;
                linux.pending_read = None;
                kt.state = thread::ThreadState::Ready;
            }
        }
    } else if let Some(ref pp) = linux.pending_poll {
        let ready = run_poll(machine, kt, pp.fds_ptr, pp.nfds);
        if ready > 0 || pp.deadline_ns.is_some_and(|end| crate::kernel::portio::now_ns() >= end) {
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

    let trace_call = crate::kernel::startup::trace_linux_syscall(nr, regs.mode() == crate::UserMode::Mode64);
    if trace_call {
        linux_trace!("[LINUX] syscall {} a0={:#x} a1={:#x} a2={:#x} tid={}",
            nr, args.a0, args.a1, args.a2, kt.tid);
    }

    let result = if regs.mode() == crate::UserMode::Mode64 {
        if let Some(result) = async_io::call(machine, kt, linux, regs, nr, &args) { result } else { dispatch_nr_64(machine, kt, linux, nr, &args, regs) }
    } else {
        dispatch_nr(machine, kt, linux, nr, &args, regs)
    };

    if regs.mode() == crate::UserMode::Mode64 {
        async_io::after_io(kt, linux, nr, &args, result.retval);
    }

    if result.retval == -11
        && let Some(connect) = blocking_socket_call(machine, kt, nr, args, regs.mode() == crate::UserMode::Mode64)
    {
        linux.pending_socket = Some(PendingSocket { nr, args,
            mode64: regs.mode() == crate::UserMode::Mode64,
            deadline: connect.then(|| crate::kernel::portio::now_ns().saturating_add(30_000_000_000)),
        });
        kt.state = thread::ThreadState::Blocked;
        return thread::KernelAction::Done;
    }
    if trace_call { linux_trace!("[LINUX] syscall {} => {}", nr, result.retval); }
    regs.rax = result.retval as u64;
    // A lifecycle action (if the handler asked for one) is executed by the loop
    // after this borrow releases; it wins over a plain switch.
    if let Some(action) = result.action {
        return action;
    }
    async_io::schedule(machine, kt, linux, regs);
    if let Some(action) = itimer::poll(machine, kt, linux, regs) { return action; }
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
        10 | 40 => sys_path_mutation(machine,linux,a,nr),
        38 => sys_rename(machine,linux,a),
        93 => if (a.a1 as i32) < 0 { SyscallResult::val(-EINVAL) } else { sys_ftruncate(kt,a) },
        11  => sys_execve(machine, kt, linux, a, regs),
        12  => sys_chdir(machine, &mut kt.vcpu, linux, a),
        13  => time::time(machine,a,false),
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
        39 => sys_path_mutation(machine, linux, a, 39),
        42  => sys_pipe(machine, kt, a, false),
        45  => sys_brk(linux, a),
        54  => sys_ioctl(machine, kt, linux, a),
        180 => sys_pread64(machine, kt, a),
        181 => sys_pwrite64(machine, kt, a, false),
        55 | 221 if matches!(a.a1, 5..=7 | 12..=14) => record_lock::call(machine, kt, linux, a, false),
        55  => sys_fcntl(kt, a),
        143 => sys_flock(kt, linux, a),
        144 => shared_mapping::msync(linux, a),
        118 | 148 => sys_fsync(kt, a),
        370 => message::sendmsg(machine, kt, a, false),
        372 => message::recvmsg(machine, kt, a, false),
        15 => sys_chmod(machine, linux, a),
        94 => sys_fchmod(kt, a),
        301 => sys_unlinkat(machine, kt, linux, a),
        302 => sys_renameat(machine, kt, linux, a),
        41  => sys_dup(kt, a),
        63  => sys_dup2(kt, a),
        83 => sys_symlink(machine, kt, linux, a, false),
        304 => sys_symlink(machine, kt, linux, a, true),
        85  => sys_readlink(machine, kt, linux, a),
        // Old i386 struct stat — 64-byte layout. busybox/uclibc still uses
        // these and falls back from stat64; without them mode comes back
        // zero and access(X_OK) reports "Permission denied".
        106 => sys_stat_old(machine, kt, linux, a, true),
        107 => sys_stat_old(machine, kt, linux, a, false),
        108 => sys_fstat_old(machine, kt, a),
        91  => sys_munmap(machine, linux, a),
        114 => sys_wait4(machine, kt, a, regs),
        120 => sys_clone(machine, kt, linux, a, regs),
        190 => sys_vfork(a),
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
        195 => sys_stat64(machine, kt, linux, a, false, true),
        196 => sys_stat64(machine, kt, linux, a, false, false),
        197 => sys_fstat64(machine, kt, a, false),
        220 => sys_getdents64(machine, kt, linux, a),
        221 => sys_fcntl(kt, a),
        238 => sys_exit(machine, tid, a),
        240 => SyscallResult::val(0),
        243 => sys_set_thread_area(machine, kt, linux, a),
        252 => sys_exit(machine, tid, a),
        258 => SyscallResult::val(kt.tid),
        265 => time::clock_gettime(machine,a,false),
        266 => time::clock_getres(machine,a,false),
        403 => time::clock_gettime(machine,a,true),
        406 => time::clock_getres(machine,a,true),
        78  => time::gettimeofday(machine,a,false),
        270 => sys_exit(machine, tid, a),
        295 => sys_openat(machine, kt, linux, a),
        300 => sys_fstatat64(machine, kt, linux, a, false),
        305 => sys_readlinkat(machine, kt, linux, a),
        331 => sys_pipe(machine, kt, a, true),
        191 => limits::getrlimit(machine, a, false),
        340 => limits::prlimit(machine, kt, a),
        308 => select::call(machine,kt,linux,a,regs,false),
        413 => select::call(machine,kt,linux,a,regs,true),
        345 => message::sendmmsg(machine,kt,a,false),
        318 => vsyscall::getcpu(machine, a),
        116 => system::sysinfo(machine, a, false),
        355 => sys_getrandom(machine, kt, linux, a),
        320 => sys_utimensat(machine, kt, linux, a, false),
        412 => sys_utimensat(machine, kt, linux, a, true),
        383 => sys_statx(machine, kt, linux, a),
        102 => sys_socketcall(machine, kt, a),
        _ => {
            compact_println!("unimplemented syscall {}", nr);
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
        4   => sys_stat64(machine, kt, linux, a, true, true),
        5   => sys_fstat64(machine, kt, a, true),
        6   => sys_stat64(machine, kt, linux, a, true, false),
        7   => sys_poll(machine, kt, linux, a, regs),
        8   => sys_lseek(kt, a),
        9   => sys_mmap2(machine, kt, linux, a, a.a5 as usize), // mmap: offset in bytes
        10  => SyscallResult::val(0),
        11  => sys_munmap(machine, linux, a),
        12  => sys_brk(linux, a),
        13 | 14 | 15 | 131 => signals::call(machine, kt, linux, regs, nr, a),
        16  => sys_ioctl(machine, kt, linux, a),
        17  => sys_pread64(machine, kt, a),
        18  => sys_pwrite64(machine, kt, a, true),
        20  => sys_writev(machine, kt, a, true),
        21  => sys_access(machine, &mut kt.vcpu, linux, a),
        22  => sys_pipe(machine, kt, a, false),
        24  => sys_sched_yield(kt, regs),
        25  => sys_mremap(machine, linux, a),
        26  => shared_mapping::msync(linux, a),
        // statfs(137): -ENOSYS — callers fall back. fadvise64(221): advisory.
        137 => SyscallResult::val(-ENOSYS),
        332 => sys_statx(machine, kt, linux, a),
        221 => SyscallResult::val(0),
        32  => sys_dup(kt, a),
        33  => sys_dup2(kt, a),
        35  => sys_nanosleep(),
        36 | 38 => itimer::call(machine, linux, nr == 38, a),
        39  => SyscallResult::val(kt.tid),
        56  => sys_clone(machine, kt, linux, a, regs),
        57  => sys_fork(machine, kt, linux, a, regs),
        58  => sys_vfork(a),
        59  => sys_execve(machine, kt, linux, a, regs),
        60  => sys_exit(machine, tid, a),
        61  => sys_wait4(machine, kt, a, regs),
        63  => sys_uname(machine, &mut kt.vcpu, a, true),
        72 if matches!(a.a1, 5..=7) => record_lock::call(machine, kt, linux, a, true),
        72  => sys_fcntl(kt, a),
        73 => sys_flock(kt, linux, a),
        74 | 75 => sys_fsync(kt, a),
        90 => sys_chmod(machine, linux, a),
        91 => sys_fchmod(kt, a),
        263 => sys_unlinkat(machine, kt, linux, a),
        264 => sys_renameat(machine, kt, linux, a),
        79  => sys_getcwd(machine, &mut kt.vcpu, linux, a),
        80  => sys_chdir(machine, &mut kt.vcpu, linux, a),
        77 => sys_ftruncate(kt,a),
        82 => sys_rename(machine,linux,a),
        83 | 84 | 87 => sys_path_mutation(machine, linux, a, match nr { 83 => 39, 84 => 40, _ => 10 }),
        88 => sys_symlink(machine, kt, linux, a, false),
        266 => sys_symlink(machine, kt, linux, a, true),
        89  => sys_readlink(machine, kt, linux, a),
        96  => time::gettimeofday(machine,a,true),
        102 | 104 | 107 | 108 => SyscallResult::val(0),
        110 => SyscallResult::val(kt.tid),
        // setpgid(109)/getpgrp(111)/setsid(112)/getpgid(121)/getsid(124):
        // single-process job model — return our tid as group/session (mirrors
        // the i386 path) so dash's job-control setup converges (getpgrp ==
        // tcgetpgrp) instead of spinning on getpgrp/kill.
        109 | 111 | 112 | 121 | 124 => SyscallResult::val(kt.tid),
        62  => SyscallResult::val(0), // kill — no-op (no real job control)
        158 => sys_arch_prctl(machine, kt, linux, a, regs),
        200 => sys_exit(machine, tid, a),
        201 => time::time(machine,a,true),
        202 => sys_futex(machine, kt, a),
        217 => sys_getdents64(machine, kt, linux, a),
        218 => SyscallResult::val(kt.tid),
        228 => time::clock_gettime(machine,a,true),
        229 => time::clock_getres(machine,a,true),
        231 => sys_exit(machine, tid, a),
        234 => sys_exit(machine, tid, a),
        257 => sys_openat(machine, kt, linux, a),
        262 => sys_fstatat64(machine, kt, linux, a, true),
        267 => sys_readlinkat(machine, kt, linux, a),
        269 => sys_faccessat(machine, linux, a),
        273 => SyscallResult::val(0),       // set_robust_list — no threads share
        280 => sys_utimensat(machine, kt, linux, a, true),
        293 => sys_pipe(machine, kt, a, true),
        294 => SyscallResult::val(-ENOSYS), // inotify_init1: no filesystem event queue yet
        334 => SyscallResult::val(-ENOSYS), // rseq — glibc falls back cleanly
        439 => sys_faccessat(machine, linux, a),
        97 => limits::getrlimit(machine, a, true),
        302 => limits::prlimit(machine, kt, a),
        309 => vsyscall::getcpu(machine, a),
        99 => system::sysinfo(machine, a, true),
        318 => sys_getrandom(machine, kt, linux, a),
        // Sockets (x86-64 direct numbering).
        41  => sys_socket(kt, a.a0, a.a1, a.a2),
        42  => sys_connect(machine, kt, a.a0, a.a1 as usize, a.a2 as usize),
        43  => sys_accept(machine, kt, a.a0, a.a1 as usize, a.a2 as usize),
        44  => sys_sendto(machine, kt, a.a0, a.a1 as usize, a.a2 as usize, a.a3, a.a4 as usize, a.a5 as usize),
        46 => message::sendmsg(machine,kt,a,true),
        47 => message::recvmsg(machine,kt,a,true),
        270 => select::call(machine,kt,linux,a,regs,true),
        307 => message::sendmmsg(machine,kt,a,true),
        45  => sys_recvfrom(machine, kt, a.a0, a.a1 as usize, a.a2 as usize, a.a3, a.a4 as usize, a.a5 as usize),
        48  => sys_shutdown(kt, a.a0, a.a1),
        49  => sys_bind(machine, kt, a.a0, a.a1 as usize, a.a2 as usize),
        50  => sys_listen(kt, a.a0, a.a1),
        51  => sys_getsockname(machine, kt, a.a0, a.a1 as usize, a.a2 as usize, false),
        52  => sys_getsockname(machine, kt, a.a0, a.a1 as usize, a.a2 as usize, true),
        54  => sys_setsockopt(machine, kt, a.a0, a.a1, a.a2, a.a3 as usize, a.a4 as usize),
        55  => sys_getsockopt(machine, kt, a.a0, a.a1, a.a2, a.a3 as usize, a.a4 as usize),
        288 => sys_accept(machine, kt, a.a0, a.a1 as usize, a.a2 as usize), // accept4
        _ => {
            compact_println!("unimplemented x86_64 syscall {}", nr);
            SyscallResult::val(-ENOSYS)
        }
    }
}

// =============================================================================
// Helpers: C string / path handling
// =============================================================================

/// Resolve a path (NUL-terminated user pointer) against cwd.
/// Leading `/` = absolute (strip it). Otherwise prepend cwd.
pub fn resolve_path<'a>(path: &[u8], cwd: &[u8], buf: &'a mut [u8]) -> &'a [u8] {
    crate::kernel::exec::resolve_path(path, cwd, buf)
}

/// Copy a complete mutation path, rejecting overflow before touching the VFS.
fn mutation_path<A: crate::Arch>(machine: &mut A, pointer: usize, base: &[u8]) -> Result<alloc::vec::Vec<u8>, i32> {
    let mut raw = [0; vfs::PATH_KEY_MAX];
    let n = machine.copy_cstr(pointer, &mut raw);
    if n == raw.len() { return Err(-36); }
    if n == 0 { return Err(-ENOENT); }
    if raw[0] != b'/' && base.len() + n + 1 >= vfs::PATH_KEY_MAX { return Err(-36); }
    let mut path = [0; vfs::PATH_KEY_MAX];
    Ok(resolve_path(&raw[..n], base, &mut path).to_vec())
}

/// Change cwd. Validates directory exists. cwd/cwd_len are mutated in place.
pub fn do_chdir(path: &[u8], cwd: &mut [u8; vfs::PATH_KEY_MAX], cwd_len: &mut usize) -> i32 {
    if path.is_empty() { return -ENOENT; }
    let required = if path[0] == b'/' { path.len() } else { cwd_len.saturating_add(path.len()).saturating_add(1) };
    if required >= vfs::PATH_KEY_MAX { return -36; }
    let mut buffer = [0; vfs::PATH_KEY_MAX];
    let resolved = resolve_path(path, &cwd[..*cwd_len], &mut buffer);
    let Some(canonical) = vfs::canonical_path(resolved) else { return -ENOENT; };
    if !vfs::dir_exists(&canonical) {
        return if vfs::stat(&canonical, true).is_some() { -20 } else { -ENOENT };
    }
    if canonical.len() >= cwd.len() { return -36; }
    cwd[..canonical.len()].copy_from_slice(&canonical);
    *cwd_len = canonical.len();
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
///   [argc] [argv[0]..argv[N-1]] [NULL] [envp[0]..envp[M-1]] [NULL] [auxv...] [AT_NULL]
///   [16 random bytes] [string pool]
///
/// For 64-bit: same layout with 8-byte slots.
pub(crate) fn setup_user_stack<A: crate::Arch>(machine: &mut A, _vcpu: &mut Regs, args: &[alloc::vec::Vec<u8>], want_64: bool, extra_auxv: &[(usize, usize)], environment: Option<&[u8]>) -> usize {
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
    let defaults = environment::initial(crate::kernel::dos::c_root(), lib::locale::current().posix);
    // execve supplies the caller's environment exactly, including an empty
    // one. Boot/cross-personality launches synthesize Linux conventions.
    let inherited: alloc::vec::Vec<&[u8]> = environment.map(|block|
        block.split(|&byte| byte == 0).take_while(|entry| !entry.is_empty()).collect()).unwrap_or_default();
    let default_strings: alloc::vec::Vec<&[u8]> = defaults.split(|&byte| byte == 0).take_while(|entry| !entry.is_empty()).collect();
    let env_strings = if environment.is_some() { inherited.as_slice() } else { default_strings.as_slice() };
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
    // exec also supplies its program headers so libc can discover PT_TLS.
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
pub(crate) fn exec_elf_image_into<A: crate::Arch>(machine: &mut A, threads: &mut [thread::Thread<A>], tid: usize, data: &crate::kernel::exec::ExecutableImage, path: &[u8], args: &[alloc::vec::Vec<u8>], environment: Option<&[u8]>) -> Result<(), i32> {
    exec_elf_source_into(machine, threads, tid, data, data.source.as_ref(), path, args, environment)
}

#[allow(clippy::too_many_arguments)]
fn exec_elf_source_into<A: crate::Arch>(machine: &mut A, threads: &mut [thread::Thread<A>], tid: usize, data: &[u8], source: Option<&crate::kernel::exec::ExecutableFile>, path: &[u8], args: &[alloc::vec::Vec<u8>], environment: Option<&[u8]>) -> Result<(), i32> {
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

    foreground_console(tid);

    // Both static and dynamic PIE must stay clear of the low BIOS/VGA and
    // hosted trap-workspace mappings. Static musl relocates itself using auxv.
    let main_bias = if is_pie { PIE_BASE } else { 0 };
    let loaded = elf::load_elf_source(machine, data, main_bias, source).map_err(|_| 8)?;
    let want_64 = loaded.class == elf::ElfClass::Elf64;

    // Dynamic: load the interpreter (ld.so) at INTERP_BASE and build the full
    // auxv so it can self-relocate, relocate the program, and load its libs.
    // ld.so runs first, so the CPU entry is the interpreter's. Static: jump
    // straight to the program entry with a minimal auxv.
    let mut occupied_ranges = alloc::vec::Vec::new();
    let (cpu_entry, extra_auxv): (u64, alloc::vec::Vec<(usize, usize)>) = if let Some(ip) = &interp_path {
        // PT_INTERP is an absolute path in the (unified) root filesystem, e.g.
        // "/lib64/ld-linux-x86-64.so.2" → VFS "lib64/ld-linux-x86-64.so.2".
        let mut s: &[u8] = ip;
        while s.first() == Some(&b'/') { s = &s[1..]; }
        let interp_data = crate::kernel::exec::load_executable_resolved(s).map_err(|_| 8)?;
        let interp_loaded = elf::load_elf_source(machine, &interp_data, INTERP_BASE, interp_data.source.as_ref()).map_err(|_| 8)?;
        occupied_ranges.push((INTERP_BASE, interp_loaded.max_vaddr));
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
        // Static libc also uses the program headers to discover PT_TLS.
        // Omitting these silently gives pthreads undersized TLS blocks.
        (loaded.entry, alloc::vec![
            (3, loaded.phdr_vaddr), (4, loaded.phentsize), (5, loaded.phnum),
            (9, loaded.entry as usize),
        ])
    };

    let sp = setup_user_stack(machine, &mut current.kernel.vcpu, args, want_64, &extra_auxv, environment);
    if want_64 {
        thread::init_process_thread_64(current, cpu_entry, sp as u64);
    } else {
        thread::init_process_thread(current, cpu_entry as u32, sp as u32);
    }

    if let thread::Personality::Linux(l) = &mut current.personality {
        l.occupied_ranges = occupied_ranges;
        l.heap_base = loaded.max_vaddr;
        l.heap_end = loaded.max_vaddr;
        l.mmap_cursor = elf::USER_STACK_TOP - 0x0100_0000;
        let canonical = vfs::canonical_path(path);
        l.set_exec_path(canonical.as_deref().unwrap_or(path));
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
    SyscallResult::act(0, thread::KernelAction::Fork { on_done: fork_set_retval, child_stack: 0, shared_until_exec: false })
}

/// Share the live address space while the parent is suspended, until exec/exit.
fn sys_vfork(_a: &Args) -> SyscallResult {
    SyscallResult::act(0, thread::KernelAction::Fork {
        on_done: fork_set_retval, child_stack: 0, shared_until_exec: true,
    })
}

/// Process clone, including the CLONE_VM | CLONE_VFORK | SIGCHLD spawn mode.
fn sys_clone<A: crate::Arch>(_machine: &mut A, _kt: &mut thread::KernelThread<A>, _linux: &mut LinuxState, a: &Args, _regs: &mut Regs) -> SyscallResult {
    let shared_until_exec = a.a0 == 0x4111;
    if a.a0 & 0x100 != 0 && !shared_until_exec { return SyscallResult::val(-EINVAL); }
    SyscallResult::act(0, thread::KernelAction::Fork { on_done: fork_set_retval, child_stack: a.a1 as usize, shared_until_exec })
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
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub(crate) fn handle_fork<A: crate::Arch>(
    machine: &mut A,
    threads: &mut [thread::Thread<A>],
    vcpu: &mut Regs,
    parent_tid: usize,
    child_stack: usize,
    shared_until_exec: bool,
    on_done: fn(&mut Regs, i32),
) -> Option<usize> {
    let mut child_root = A::PageTable::default();
    if !shared_until_exec { machine.user_fork(&mut child_root); }

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

    let mut snapshot = machine.clean_fx_template();
    machine.switch_fx(&mut snapshot);
    child.kernel.fx_state = snapshot;
    machine.switch_fx(&mut snapshot);
    parent.kernel.dup_all_fds(&mut child.kernel);
    if let (thread::Personality::Linux(pl), thread::Personality::Linux(cl)) =
        (&parent.personality, &mut child.personality)
    {
        cl.vfork_parent = shared_until_exec.then_some(parent_tid);
        cl.heap_base = pl.heap_base;
        cl.heap_end = pl.heap_end;
        cl.mmap_cursor = pl.mmap_cursor;
        cl.occupied_ranges = pl.occupied_ranges.clone();
        cl.shared_mappings = pl.shared_mappings.fork();
        cl.signals = signals::fork(&pl.signals, async_io::current_id(&pl.async_io, parent.kernel.tid), child.kernel.tid);
        cl.tls_entry = pl.tls_entry;
        cl.tls_base = pl.tls_base;
        cl.tls_limit = pl.tls_limit;
        cl.tls_limit_in_pages = pl.tls_limit_in_pages;
        cl.cwd = pl.cwd;
        cl.cwd_len = pl.cwd_len;
        cl.exec_path = pl.exec_path;
        cl.exec_path_len = pl.exec_path_len;
        cl.tty = pl.tty.clone();
        cl.keyboard = pl.keyboard.clone();
        cl.async_io = async_io::fork_state(&pl.async_io);
    }

    parent.kernel.state = if shared_until_exec { thread::ThreadState::Blocked } else { thread::ThreadState::Ready };
    if shared_until_exec {
        // Park the live shared space in the child. The ordinary switch will
        // save an empty space in the suspended parent, preserving one owner.
        child.kernel.vcpu.space = machine.activate(A::PageTable::default(), core::ptr::null_mut(), core::ptr::null_mut());
    }
    foreground_console(child_tid);
    on_done(vcpu, child_tid as i32);
    Some(child_tid)
}

/// Return the shared image to its suspended owner before child exec/exit
/// frees memory. A failed exec never reaches this point, so spawn's error
/// write remains visible in the parent's original address space.
pub(crate) fn release_vfork<A: crate::Arch>(machine: &mut A, threads: &mut [thread::Thread<A>], tid: usize) {
    let parent_tid = match &mut threads[tid].personality {
        thread::Personality::Linux(linux) => linux.vfork_parent.take(),
        _ => None,
    };
    let Some(parent_tid) = parent_tid else { return; };
    let shared = machine.activate(A::PageTable::default(), core::ptr::null_mut(), core::ptr::null_mut());
    let (child, parent) = thread::get_two_threads(threads, tid, parent_tid);
    parent.kernel.vcpu.space = shared;
    if let (thread::Personality::Linux(cl), thread::Personality::Linux(pl)) = (&child.personality, &mut parent.personality) {
        pl.heap_base = cl.heap_base;
        pl.heap_end = cl.heap_end;
        pl.mmap_cursor = cl.mmap_cursor;
        pl.occupied_ranges = cl.occupied_ranges.clone();
        let mappings = cl.shared_mappings.fork();
        pl.release_mappings(machine);
        pl.shared_mappings = mappings;
    }
    parent.kernel.state = thread::ThreadState::Ready;
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
            if let Some(n) = crate::kernel::kpipe::read_event(idx, &mut tmp) {
                crate::compact_dbg_println!("READ single fd={} bytes={:?}", fd, &tmp[..n]);
                machine.copy_to(buf, &tmp[..n]);
                return SyscallResult::val(n as i32);
            }
            // No data — check if writers exist
            if !crate::kernel::kpipe::has_writers(idx) {
                return SyscallResult::val(0); // EOF
            }
            if crate::kernel::kpipe::nonblocking(idx, false) { return SyscallResult::val(-11); }
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
            // Native EAGAIN is suspended by dispatch_action until ready.
            let mut tmp = alloc::vec![0u8; len.min(65536)];
            let n = net::recvfrom(h, &mut tmp, 0, &mut []);
            if n > 0 { machine.copy_to(buf, &tmp[..n as usize]); }
            SyscallResult::val(n)
        }
        thread::FdKind::ConsoleOut | thread::FdKind::PipeWrite(_) | thread::FdKind::Dir { .. } => {
            SyscallResult::val(-EBADF)
        }
        thread::FdKind::None => SyscallResult::val(-EBADF),
    }
}

/// Terminal queries reply through the same input endpoint as keyboard bytes.
fn terminal_responses<A: crate::Arch>(kt: &thread::KernelThread<A>) {
    let mut reply = [0; 64];
    let n = lib::term::take_response(&mut reply);
    if let FdKind::PipeRead(pipe) = kt.fds[0] && n > 0 {
        crate::kernel::kpipe::write(pipe, &reply[..n]);
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
                lib::term::put_utf8(b);
                // Keep startup errors after a DOS launch restores its screen.
                if fd == 2 {
                    lib::log::debug_byte(b);
                }
            }
            terminal_responses(kt);
            crate::kernel::term::mark_dirty();
            SyscallResult::val(len as i32)
        }
        thread::FdKind::PipeWrite(idx) => {
            let mut tmp = alloc::vec![0u8; len];
            machine.copy_from(buf, &mut tmp);
            let r = crate::kernel::kpipe::write(idx, &tmp);
            if r == -1 {
                SyscallResult::val(-EPIPE)
            } else {
                SyscallResult::val(r)
            }
        }
        thread::FdKind::Vfs(handle) => {
            SyscallResult::val(file_io::write_user(machine, handle, buf, len))
        }
        thread::FdKind::Socket(h) => {
            // write() on a socket == send() with no flags.
            let mut tmp = alloc::vec![0u8; len.min(65536)];
            machine.copy_from(buf, &mut tmp);
            SyscallResult::val(net::sendto(h, &tmp, 0, &[]))
        }
        thread::FdKind::PipeRead(_) | thread::FdKind::None | thread::FdKind::Dir { .. } => {
            SyscallResult::val(-EBADF)
        }
    }
}

/// open(5)
fn sys_open<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, linux: &LinuxState, a: &Args) -> SyscallResult {
    let path_ptr = a.a0 as usize;
    let mut path_buf = [0u8; vfs::PATH_KEY_MAX];
    let path_len = machine.copy_cstr(path_ptr, &mut path_buf);
    if path_len == path_buf.len() { return SyscallResult::val(-36); }
    let path = &path_buf[..path_len];

    let mut buf = [0u8; vfs::PATH_KEY_MAX];
    let resolved = resolve_path(path, linux.cwd_str(), &mut buf);

    // Directories: the fd records WHICH directory was opened (dir-handle
    // table) so getdents64 lists it — `ls /path` opens an fd on /path.
    if proc_fd::is_dir(resolved) || vfs::dir_exists(resolved) {
        return match kt.alloc_fd(3) {
            Some(fd) => {
                let handle = vfs::open_dir_handle(resolved);
                if handle < 0 {
                    return SyscallResult::val(handle); // EMFILE
                }
                kt.fds[fd] = thread::FdKind::Dir { handle, next: 0 };
                linux_trace!("[LINUX] directory open {} fd={} handle={}",
                    core::str::from_utf8(resolved).unwrap_or("<non-UTF8>"), fd, handle);
                SyscallResult::val(fd as i32)
            }
            None => SyscallResult::val(-24), // EMFILE
        };
    }

    let flags = a.a1 as u32;
    let exists = vfs::path_exists(resolved);
    if flags & 0xc0 == 0xc0 && exists { return SyscallResult::val(-17); } // O_CREAT|O_EXCL
    if !exists && flags & 0x40 == 0 { return SyscallResult::val(-ENOENT); }
    if flags & 0x10000 != 0 {
        linux_trace!("[LINUX] open O_DIRECTORY rejected {}", core::str::from_utf8(resolved).unwrap_or("<non-UTF8>"));
        return SyscallResult::val(-20);
    } // O_DIRECTORY
    let handle = if flags & 0x200 != 0 || !exists { vfs::create_to_handle(resolved) } else { vfs::open_to_handle(resolved) };
    if handle < 0 { return SyscallResult::val(handle); }
    let access = match flags & 3 {
        0 => vfs::OpenAccess::Read, 1 => vfs::OpenAccess::Write, _ => vfs::OpenAccess::ReadWrite,
    };
    let rc = vfs::configure_handle_access(handle, access);
    if rc < 0 {
        vfs::close_vfs_handle(handle);
        return SyscallResult::val(rc);
    }

    match kt.alloc_fd(3) {
        Some(fd) => {
            kt.fds[fd] = thread::FdKind::Vfs(handle);
            if flags & 0x80000 != 0 { kt.cloexec |= 1u64 << fd; }
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
// Sockets — hosted std::net or the native Ethernet/IP stack. Native blocking
// calls suspend through pending_socket while the event loop services the NIC.
// =============================================================================

mod socket;
use socket as net;

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
        15 => sys_getsockopt(machine, kt, g(0), g(1), g(2), g(3) as usize, g(4) as usize),
        17 => { let args = Args { a0:g(0), a1:g(1), a2:g(2), a3:0, a4:0, a5:0 }; message::recvmsg(machine,kt,&args,false) },
        16 | 20 => {let args=Args {a0:g(0),a1:g(1),a2:g(2),a3:g(3),a4:0,a5:0};
            if a.a0==16 {message::sendmsg(machine,kt,&args,false)}else{message::sendmmsg(machine,kt,&args,false)}
        },
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
        Some(fd) => {
            kt.fds[fd] = thread::FdKind::Socket(h);
            if ty & 0x80000 != 0 { kt.cloexec |= 1 << fd; }
            SyscallResult::val(fd as i32)
        }
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
    let mut data = alloc::vec![0u8; len.min(65536)];
    machine.copy_from(buf_ptr, &mut data);
    let (addr, n) = read_sockaddr(machine, addr_ptr, addr_len);
    SyscallResult::val(net::sendto(h, &data, flags as i32, &addr[..n]))
}

#[allow(clippy::too_many_arguments)]
fn sys_recvfrom<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, fd: u64, buf_ptr: usize, len: usize, flags: u64, addr_ptr: usize, addrlen_ptr: usize) -> SyscallResult {
    let h = match sock_handle(kt, fd) { Ok(h) => h, Err(e) => return SyscallResult::val(e) };
    let mut data = alloc::vec![0u8; len.min(65536)];
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

fn sys_getsockopt<A: crate::Arch>(machine: &mut A, kt: &thread::KernelThread<A>, fd: u64,
    level: u64, name: u64, value: usize, length: usize) -> SyscallResult
{
    let h = match sock_handle(kt, fd) { Ok(h) => h, Err(e) => return SyscallResult::val(e) };
    if !matches!((level,name),(1,4)|(0,11)) { return SyscallResult::val(-92); }
    if value == 0 || length == 0 { return SyscallResult::val(-14); }
    let capacity = machine.read::<u32>(length) as usize;
    let error=if level==0 {net::receive_errors(h)}else{net::socket_error(h)};
    if error < 0 { return SyscallResult::val(error); }
    machine.copy_to(value, &error.to_le_bytes()[..capacity.min(4)]);
    machine.write::<u32>(length, capacity.min(4) as u32);
    SyscallResult::val(0)
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
    let envp_ptr = a.a2 as usize;

    let mut raw_path_buf = [0u8; vfs::PATH_KEY_MAX];
    let raw_path_len = machine.copy_cstr(path_ptr, &mut raw_path_buf);
    if raw_path_len == raw_path_buf.len() { return SyscallResult::val(-36); }
    let raw_path = &raw_path_buf[..raw_path_len];
    linux_trace!("[LINUX] execve path={}", core::str::from_utf8(raw_path).unwrap_or("<non-UTF8>"));
    // Resolve /proc/self/exe to this process's own load path (tracked in
    // LinuxState.exec_path, set on every exec) — busybox's standalone-shell
    // mode re-execs itself that way, and we have no real /proc. Copy to the
    // kernel heap: `raw_path` borrows user memory that arch_user_clean() below
    // unmaps, and we use `path` after that (format detection + init_thread).
    let mut path: alloc::vec::Vec<u8> = if raw_path == b"/proc/self/exe" {
        if linux.exec_path_str().is_empty() { return SyscallResult::val(-ENOENT); }
        [b"/".as_slice(), linux.exec_path_str()].concat()
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
    let entries = read_c_argv(machine,envp_ptr,wide);
    let mut environment = alloc::vec::Vec::new();
    for entry in entries { environment.extend_from_slice(&entry); environment.push(0); }
    if environment.is_empty() { environment.push(0); }
    environment.push(0);
    if environment.len() > 32 * 1024 { return SyscallResult::val(-7); } // E2BIG

    if args.is_empty() { args.push(path.clone()); }

    // Snapshot cwd up front — execve preserves it across the address-space
    // teardown, but `linux` borrows from the thread we're about to clobber.
    let cwd_snapshot: alloc::vec::Vec<u8> = linux.cwd_str().into();

    // Load file (resolves path against cwd)
    let mut resolved = [0; vfs::PATH_KEY_MAX];
    let mut buffer = match exec::load_executable_resolved(exec::resolve_path(&path, &cwd_snapshot, &mut resolved)) {
        Ok(b) => b,
        Err(error) => {
            linux_trace!("[LINUX] execve load failed errno={}", error);
            return SyscallResult::val(-error);
        }
    };

    path = [b"/".as_slice(), exec::resolve_path(&path, &cwd_snapshot, &mut resolved)].concat();

    // Scripts use their declared interpreter before the general DOS/native
    // format dispatch. Preserve the optional argument as one argv element.
    for depth in 0..=4 {
        let interpreter = match script::parse(&buffer) {
            Ok(Some(interpreter)) => interpreter,
            Ok(None) => break,
            Err(error) => return SyscallResult::val(-error),
        };
        if depth == 4 { return SyscallResult::val(-40); } // ELOOP
        let mut next = alloc::vec![interpreter.path.clone()];
        if let Some(argument) = interpreter.argument { next.push(argument); }
        next.push(path);
        next.extend(args.into_iter().skip(1));
        args = next;
        let resolved_interpreter = exec::resolve_path(&interpreter.path, &cwd_snapshot, &mut resolved);
        buffer = match exec::load_executable_resolved(resolved_interpreter) {
            Ok(buffer) => buffer,
            Err(error) => return SyscallResult::val(-error),
        };
        path = [b"/".as_slice(), resolved_interpreter].concat();
    }

    // A 64-bit ELF on a backend without 64-bit user execution must fail HERE,
    // before the point of no return, so the caller survives and can fall back
    // (shell.elf tries /bin/busybox after /bin/sh).
    if matches!(exec::detect_format(&buffer, &path), exec::BinaryFormat::Elf)
        && crate::kernel::elf::is_class64(&buffer)
        && !machine.user_64_supported()
    {
        return SyscallResult::val(-ENOEXEC);
    }

    let format = exec::detect_format(&buffer, &path);
    let mut cmdtail = if matches!(format, exec::BinaryFormat::MzExe | exec::BinaryFormat::Com) {
        let tail = dos_command_tail(&args);
        if tail.len() > 126 { return SyscallResult::val(-7); } // E2BIG: PSP command tail capacity.
        let mut resolved = [0; vfs::PATH_KEY_MAX];
        args[0] = exec::resolve_path(&path, &cwd_snapshot, &mut resolved).to_vec();
        tail
    } else { alloc::vec::Vec::new() };

    // COMMAND owns RETROOS.INI [launch] interpretation, DOS/32A wrapping and game
    // launch policy. Use the same process-replacing entry as CreateProcess;
    // keep direct DOS loading available on minimal systems without a shell.
    if matches!(format, exec::BinaryFormat::MzExe | exec::BinaryFormat::Com) {
        let launcher = [crate::kernel::dos::c_root(), b"RETROOS/COMMAND.COM"].concat();
        if !args[0].eq_ignore_ascii_case(&launcher) && let Ok(shell) = exec::load_file_resolved(&launcher) {
            let mut dos_path = [0; crate::kernel::dos::DFS_PATH_MAX];
            let n = crate::kernel::dos::vfs_to_dos(&args[0], &mut dos_path);
            let mut tail = b"/E ".to_vec();
            let quoted = dos_path[..n].contains(&b' ');
            if quoted { tail.push(b'"'); }
            tail.extend_from_slice(&dos_path[..n]);
            if quoted { tail.push(b'"'); }
            if !cmdtail.is_empty() { tail.push(b' '); tail.extend_from_slice(&cmdtail); }
            if tail.len() > 126 { return SyscallResult::val(-7); }
            cmdtail = tail;
            args = alloc::vec![launcher.clone()];
            path = launcher;
            buffer = shell.into();
        }
    }

    // File loaded — hand teardown + rebuild to the executor (`handle_exec`),
    // which runs off this handler's borrow so its in-place
    // init_thread/exit_thread/reg-reload don't alias `kt`. The point of no
    // return (drop symbols, close CLOEXEC, free pages, re-image) is the
    // executor's; until then execve still fails cleanly (the -ENOENT above).
    SyscallResult::act(0, thread::KernelAction::Exec {
        buffer, path, args, cmdtail, env: environment,
        cwd: cwd_snapshot, personality_name: Some(thread::PersonalityName::Linux), policy: Default::default(),
    })
}

/// Executor for `KernelAction::Exec`: re-image the current process in place.
/// Runs after the syscall handler's borrow releases, so its `get_thread`/
/// `init_thread`/`exit_thread` on `tid` are clean. Returns `None` (stay on the
/// re-imaged thread) or the next tid if the load fails and the thread exits.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub(crate) fn handle_exec<A: crate::Arch>(
    machine: &mut A,
    bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    threads: &mut [thread::Thread<A>],
    vcpu: &mut Regs,
    tid: usize,
    buffer: crate::kernel::exec::ExecutableImage,
    path: alloc::vec::Vec<u8>,
    args: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    cmdtail: alloc::vec::Vec<u8>,
    env: alloc::vec::Vec<u8>,
    cwd: alloc::vec::Vec<u8>,
    personality_name: Option<thread::PersonalityName>,
    policy: crate::kernel::dos::LaunchPolicy,
    exiting_display: &mut Option<crate::kernel::display::ExitDisplay>,
    sb_handoff: &mut Option<crate::kernel::drivers::sb16::Sb16>,
    display: &mut Option<crate::kernel::display::Display>,
) -> Option<usize> {
    use crate::kernel::exec;
    let format = if personality_name == Some(thread::PersonalityName::Dos) {
        exec::detect_format_for_dos(&buffer, &path)
    } else {
        exec::detect_format(&buffer, &path)
    };

    // A DOS shell started through Win32 CreateProcess owns the display and
    // Sound Blaster while it replaces itself. Detach those resources before
    // exec_dos_into drops the old DosState, then bind them to the new image.
    let replacing_dos = personality_name == Some(thread::PersonalityName::Dos);
    let starting_dos = matches!(format, exec::BinaryFormat::MzExe | exec::BinaryFormat::Com);
    let focused_dos = (replacing_dos || starting_dos) && crate::kernel::focus::focused() == tid;
    let exec_display = if focused_dos {
        Some(match display.take() {
            Some(surface) => crate::kernel::display::DisplayHandoff::from_surface(surface, machine),
            None => thread::get_thread(threads, tid).unwrap()
                .personality.release_display(machine, bios_workspace),
        })
    } else {
        None
    };
    let exec_sb = if focused_dos {
        thread::get_thread(threads, tid).unwrap().personality.release_sb(machine)
    } else {
        None
    };
    if exec_sb.is_some() {
        assert!(sb_handoff.is_none(), "stale SB handoff during DOS exec");
    }

    // Point of no return — drop symbols + close CLOEXEC fds.
    {
        let cur = thread::get_thread(threads, tid).unwrap();
        cur.kernel.close_cloexec();
        if let thread::Personality::Linux(linux) = &mut cur.personality { async_io::close_cloexec(&mut linux.async_io); }
    }

    let inherited_async = if matches!(format, exec::BinaryFormat::Elf) {
        match &thread::get_thread(threads, tid).unwrap().personality {
            thread::Personality::Linux(linux) => Some((async_io::exec_state(&linux.async_io), linux.tty.clone(), linux.keyboard.clone(),
                signals::exec(&linux.signals, async_io::current_id(&linux.async_io, tid as i32), tid as i32), linux.alarm)),
            _ => None,
        }
    } else { None };

    release_vfork(machine, threads, tid);

    // Native protected-mode images need a clean address space; DOS handles
    // its own setup inside exec_dos_into.
    if matches!(format, exec::BinaryFormat::Elf | exec::BinaryFormat::Lx
        | exec::BinaryFormat::Ne | exec::BinaryFormat::Pe) {
        machine.free_user_pages();
        if let thread::Personality::Linux(linux) = &mut thread::get_thread(threads, tid).unwrap().personality {
            linux.release_mappings(machine);
        }
    }

    let exec_vga = match format {
        exec::BinaryFormat::Elf | exec::BinaryFormat::Lx | exec::BinaryFormat::Ne
            | exec::BinaryFormat::Pe => exec::ExecVga::None,
        _ => exec::ExecVga::Dos(crate::kernel::bios_display::DosVideo::Vga(
            crate::kernel::bios_display::EmulatedVga::initial_mode3())),
    };
    if exec::init_thread(machine, threads, tid, buffer, &path, args, cmdtail, env, cwd,
        personality_name, policy, exec_vga).is_err() {
        if let Some(handoff) = exec_display {
            *display = Some(handoff.into_surface(machine, bios_workspace));
        }
        if exec_sb.is_some() {
            *sb_handoff = exec_sb;
        }
        return Some(thread::exit_thread(
            threads, machine, bios_workspace, tid, -ENOEXEC, exiting_display, sb_handoff, display,
        ));
    }

    if let Some(inherited) = inherited_async
        && let thread::Personality::Linux(linux) = &mut thread::get_thread(threads, tid).unwrap().personality
    {
        (linux.async_io, linux.tty, linux.keyboard, linux.signals, linux.alarm) = inherited;
    }
    if let Some(handoff) = exec_display {
        let new = thread::get_thread(threads, tid).unwrap();
        if crate::kernel::osd::is_open()
            || matches!(new.personality, thread::Personality::Linux(_)
                | thread::Personality::Os2(_) | thread::Personality::Windows(_))
        {
            *display = Some(handoff.into_surface(machine, bios_workspace));
        } else {
            if starting_dos && !replacing_dos {
                new.personality.acquire_display_restore(machine, bios_workspace, handoff);
            } else {
                new.personality.acquire_display_replace(machine, bios_workspace, handoff);
            }
        }
    }
    if focused_dos {
        *sb_handoff = thread::get_thread(threads, tid).unwrap()
            .personality.adopt_sb(machine, exec_sb);
    }

    // Reload the live frame from the rebuilt stored frame; stay on this thread.
    (*vcpu) = thread::get_thread(threads, tid).unwrap().kernel.vcpu.regs;
    None
}


/// chdir(12)
fn sys_chdir<A: crate::Arch>(machine: &mut A, _vcpu: &mut Regs, linux: &mut LinuxState, a: &Args) -> SyscallResult {
    let mut path_buf = [0u8; vfs::PATH_KEY_MAX];
    let path_len = machine.copy_cstr(a.a0 as usize, &mut path_buf);
    if path_len == path_buf.len() { return SyscallResult::val(-36); }
    let path = &path_buf[..path_len];
    SyscallResult::val(do_chdir(path, &mut linux.cwd, &mut linux.cwd_len))
}

/// lseek(19)
fn sys_rename<A: crate::Arch>(machine: &mut A, linux: &LinuxState, a: &Args) -> SyscallResult {
    let old = match mutation_path(machine, a.a0 as usize, linux.cwd_str()) { Ok(path) => path, Err(error) => return SyscallResult::val(error) };
    let new = match mutation_path(machine, a.a1 as usize, linux.cwd_str()) { Ok(path) => path, Err(error) => return SyscallResult::val(error) };
    SyscallResult::val(vfs::rename(&old, &new))
}
/// renameat resolves each relative path against its own directory descriptor.
fn sys_renameat<A: crate::Arch>(machine: &mut A, kt: &thread::KernelThread<A>, linux: &LinuxState, a: &Args) -> SyscallResult {
    let mut paths = [alloc::vec::Vec::new(), alloc::vec::Vec::new()];
    for (index, fd, pointer) in [(0, a.a0 as i32, a.a1), (1, a.a2 as i32, a.a3)] {
        let mut raw = [0; vfs::PATH_KEY_MAX];
        let n = machine.copy_cstr(pointer as usize, &mut raw);
        if n == raw.len() { return SyscallResult::val(-36); }
        if n == 0 { return SyscallResult::val(-ENOENT); }
        if raw[0] != b'/' && fd != -100 {
            match kt.fds.get(fd as usize) {
                Some(thread::FdKind::Dir { .. }) => {},
                Some(thread::FdKind::None) | None => return SyscallResult::val(-EBADF),
                _ => return SyscallResult::val(-20),
            }
        }
        let mut directory = [0; vfs::DIR_PATH_MAX];
        let base = at_base(kt, linux, fd, &mut directory);
        if raw[0] != b'/' && base.len() + n + 1 >= vfs::PATH_KEY_MAX { return SyscallResult::val(-36); }
        let mut resolved = [0; vfs::PATH_KEY_MAX];
        paths[index] = resolve_path(&raw[..n], base, &mut resolved).to_vec();
    }
    SyscallResult::val(vfs::rename(&paths[0], &paths[1]))
}

fn sys_path_mutation<A: crate::Arch>(machine: &mut A, linux: &LinuxState, a: &Args, nr: u32) -> SyscallResult {
    let path = match mutation_path(machine, a.a0 as usize, linux.cwd_str()) { Ok(path) => path, Err(error) => return SyscallResult::val(error) };
    SyscallResult::val(match nr {39 => vfs::mkdir(&path),40 => vfs::rmdir(&path),_ => vfs::delete(&path)})
}
fn sys_ftruncate<A: crate::Arch>(kt: &thread::KernelThread<A>, a: &Args) -> SyscallResult {
    if a.a1 > u64::from(u32::MAX) {return SyscallResult::val(-22);}
    match kt.fds.get(a.a0 as usize) {
        Some(thread::FdKind::Vfs(handle)) => SyscallResult::val(vfs::resize_by_handle(*handle,a.a1 as u32)),
        _ => SyscallResult::val(-EBADF),
    }
}

fn sys_lseek<A: crate::Arch>(kt: &mut thread::KernelThread<A>, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    let offset = a.a1 as i32;
    let whence = a.a2 as i32;
    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    match kt.fds[fd] {
        thread::FdKind::Vfs(handle) => SyscallResult::val(vfs::seek_by_handle(handle, offset, whence)),
        thread::FdKind::Dir { handle, next } => {
            let position = match (whence, offset) {
                (0, position) if position >= 0 => position as u32,
                (1, 0) => next,
                _ => return SyscallResult::val(-EINVAL),
            };
            kt.fds[fd] = thread::FdKind::Dir { handle, next: position };
            SyscallResult::val(position as i32)
        }
        thread::FdKind::PipeRead(_) | thread::FdKind::PipeWrite(_) => SyscallResult::val(-ESPIPE),
        _ => SyscallResult::val(-EBADF),
    }
}

/// Console terminal settings use the same 36-byte Linux ABI for both client sizes.
fn sys_ioctl<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, linux: &mut LinuxState, a: &Args) -> SyscallResult {
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

    if kind.is_none() { return SyscallResult::val(-EBADF); }
    if cmd == 0x541b { // FIONREAD / TIOCINQ
        if arg == 0 || arg.checked_add(4).is_none_or(|end| end > 0xc0000000) { return SyscallResult::val(-EFAULT); }
        let count = match kind {
            FdKind::PipeRead(index) | FdKind::PipeWrite(index) => crate::kernel::kpipe::available_bytes(index) as i32,
            FdKind::Socket(handle) => match crate::kernel::net::available_bytes(handle) {
                Ok(count) => count,
                Err(error) => return SyscallResult::val(-net::errno(error)),
            },
            _ => return SyscallResult::val(-ENOTTY),
        };
        machine.write::<i32>(arg, count);
        return SyscallResult::val(0);
    }

    if cmd == 0x5421 { // FIONBIO shares flags with fcntl(F_SETFL).
        if arg == 0 || arg.checked_add(4).is_none_or(|end| end > 0xc0000000) { return SyscallResult::val(-EFAULT); }
        let enabled = machine.read::<i32>(arg) != 0;
        match kind {
            FdKind::Socket(h) => net::set_nonblocking(h, enabled),
            FdKind::PipeRead(index) => crate::kernel::kpipe::set_nonblocking(index, false, enabled),
            FdKind::PipeWrite(index) => crate::kernel::kpipe::set_nonblocking(index, true, enabled),
            _ => return SyscallResult::val(-ENOTTY),
        }
        return SyscallResult::val(0);
    }

    // Only console-attached fds are "ttys" for our purposes.
    let is_tty = matches!(kind,
        thread::FdKind::ConsoleOut
        | thread::FdKind::PipeRead(_)
        | thread::FdKind::PipeWrite(_));
    if !is_tty { return SyscallResult::val(-ENOTTY); }

    match cmd {
        TCGETS => {
            // The Linux kernel termios ABI is 36 bytes for both client sizes.
            if arg == 0 { return SyscallResult::val(-EFAULT); }
            machine.copy_to(arg, &linux.tty.lock().termios);
            SyscallResult::val(0)
        }
        TCSETS | 0x5403 | 0x5404 => {
            if arg == 0 { return SyscallResult::val(-EFAULT); }
            let mut settings = [0; 36];
            machine.copy_from(arg, &mut settings);
            let pipe = match kt.fds[0] { FdKind::PipeRead(i) => Some(i), _ => None };
            if cmd == 0x5404 && let Some(pipe) = pipe { crate::kernel::kpipe::discard(pipe); }
            linux.tty.lock().configure(settings, cmd == 0x5404, |data| {
                if let Some(pipe) = pipe { crate::kernel::kpipe::write(pipe, data); }
            });
            SyscallResult::val(0)
        },
        TIOCSWINSZ | TIOCSPGRP => SyscallResult::val(0), // accept and discard
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

fn sys_symlink<A: crate::Arch>(machine: &mut A, kt: &thread::KernelThread<A>, linux: &LinuxState, args: &Args, at: bool) -> SyscallResult {
    let mut target = [0; vfs::PATH_KEY_MAX];
    let target_len = machine.copy_cstr(args.a0 as usize, &mut target);
    let mut raw = [0; vfs::PATH_KEY_MAX];
    let raw_len = machine.copy_cstr((if at { args.a2 } else { args.a1 }) as usize, &mut raw);
    if target_len == target.len() || raw_len == raw.len() { return SyscallResult::val(-36); }
    if target_len == 0 || raw_len == 0 { return SyscallResult::val(-ENOENT); }
    let dirfd = if at { args.a1 as i32 } else { -100 };
    if raw[0] != b'/' && dirfd != -100 {
        match kt.fds.get(dirfd as usize) {
            Some(thread::FdKind::Dir { .. }) => {},
            Some(thread::FdKind::None) | None => return SyscallResult::val(-EBADF),
            _ => return SyscallResult::val(-20),
        }
    }
    let mut directory = [0; vfs::DIR_PATH_MAX];
    let base = at_base(kt, linux, dirfd, &mut directory);
    if raw[0] != b'/' && base.len() + raw_len + 1 >= vfs::PATH_KEY_MAX { return SyscallResult::val(-36); }
    let mut path = [0; vfs::PATH_KEY_MAX];
    let resolved = resolve_path(&raw[..raw_len], base, &mut path);
    SyscallResult::val(vfs::symlink(&target[..target_len], resolved))
}

fn readlink_at<A: crate::Arch>(
    machine: &mut A,
    kt: &thread::KernelThread<A>,
    linux: &LinuxState,
    path_ptr: usize,
    base: &[u8],
    buf: usize,
    bufsz: usize,
) -> SyscallResult {
    let executable = linux.exec_path_str();
    if bufsz == 0 { return SyscallResult::val(-EINVAL); }
    let mut self_exe_buf = [0u8; vfs::PATH_KEY_MAX];
    let self_exe_len = machine.copy_cstr(path_ptr, &mut self_exe_buf);
    let is_self_exe = &self_exe_buf[..self_exe_len] == b"/proc/self/exe";
    if is_self_exe {
        if executable.is_empty() { return SyscallResult::val(-ENOENT); }
        let target = if executable.starts_with(b"/") { executable.to_vec() }
            else { [b"/".as_slice(), executable].concat() };
        let n = target.len().min(bufsz);
        machine.copy_to(buf, &target[..n]);
        return SyscallResult::val(n as i32);
    }

    let mut resolved_buf = [0u8; vfs::DIR_PATH_MAX];
    let resolved = resolve_path(&self_exe_buf[..self_exe_len], base, &mut resolved_buf);
    linux_trace!("[LINUX] readlink path={} base={} resolved={}",
        core::str::from_utf8(&self_exe_buf[..self_exe_len]).unwrap_or("<non-UTF8>"),
        core::str::from_utf8(base).unwrap_or("<non-UTF8>"),
        core::str::from_utf8(resolved).unwrap_or("<non-UTF8>"));
    if let Some(target) = proc_fd::readlink(kt, linux, resolved) {
        let Some(target) = target else { return SyscallResult::val(-ENOENT); };
        let count = target.len().min(bufsz);
        machine.copy_to(buf, &target[..count]);
        return SyscallResult::val(count as i32);
    }
    if proc_fd::is_dir(resolved) { return SyscallResult::val(-EINVAL); }
    let mut target = [0u8; vfs::DIR_PATH_MAX];
    match vfs::readlink(resolved, &mut target[..bufsz.min(vfs::DIR_PATH_MAX)]) {
        Some(n) => {
            machine.copy_to(buf, &target[..n]);
            SyscallResult::val(n as i32)
        }
        // realpath uses ENOENT to reject a missing component, and EINVAL
        // to accept an existing component that is not a symbolic link.
        None => SyscallResult::val(if vfs::stat(resolved, false).is_some() { -EINVAL } else { -ENOENT }),
    }
}

/// readlink(85/89) — read the target without following the final component.
fn sys_readlink<A: crate::Arch>(
    machine: &mut A,
    kt: &thread::KernelThread<A>,
    linux: &LinuxState,
    a: &Args,
) -> SyscallResult {
    readlink_at(
        machine,
        kt,
        linux,
        a.a0 as usize,
        linux.cwd_str(),
        a.a1 as usize,
        a.a2 as usize,
    )
}

/// readlinkat(267), with the same dirfd handling as the other `*at` calls.
fn sys_readlinkat<A: crate::Arch>(
    machine: &mut A,
    kt: &thread::KernelThread<A>,
    linux: &LinuxState,
    a: &Args,
) -> SyscallResult {
    let mut dir_buf = [0u8; vfs::DIR_PATH_MAX];
    let base = at_base(kt, linux, a.a0 as i32, &mut dir_buf);
    readlink_at(
        machine,
        kt,
        linux,
        a.a1 as usize,
        base,
        a.a2 as usize,
        a.a3 as usize,
    )
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

/// Existence check behind access/faccessat, including directories.
fn access_at<A: crate::Arch>(machine: &mut A, linux: &LinuxState, path_ptr: usize) -> SyscallResult {
    let mut path_buf = [0u8; vfs::PATH_KEY_MAX];
    let path_len = machine.copy_cstr(path_ptr, &mut path_buf);
    if path_len == path_buf.len() { return SyscallResult::val(-36); }
    let path = &path_buf[..path_len];
    let mut buf = [0u8; vfs::PATH_KEY_MAX];
    let resolved = resolve_path(path, linux.cwd_str(), &mut buf);
    SyscallResult::val(if proc_fd::is_dir(resolved) || vfs::stat(resolved, true).is_some() { 0 } else { -ENOENT })
}

/// brk(45)
fn sys_brk(linux: &mut LinuxState, a: &Args) -> SyscallResult {
    let addr = a.a0 as usize;

    if addr == 0 {
        // Query current brk
        return SyscallResult::val64(linux.heap_end as i64);
    }

    let ceiling = linux.occupied_ranges.iter().filter(|(start, _)| *start >= linux.heap_base)
        .map(|(start, _)| *start).min().unwrap_or(linux.mmap_cursor).min(linux.mmap_cursor);
    let new_end = addr.max(linux.heap_base).min(ceiling);
    linux.heap_end = new_end;
    SyscallResult::val64(linux.heap_end as i64)
}

fn flock_handle<A: crate::Arch>(kt: &thread::KernelThread<A>, args: &Args) -> Result<i32, i32> {
    match kt.fds.get(args.a0 as usize) {
        Some(thread::FdKind::Vfs(h)) => Ok(*h),
        _ => Err(-EBADF),
    }
}
fn sys_flock<A: crate::Arch>(kt: &mut thread::KernelThread<A>, linux: &mut LinuxState, args: &Args) -> SyscallResult {
    let h = match flock_handle(kt, args) { Ok(h) => h, Err(e) => return SyscallResult::val(e) };
    if args.a1 > u32::MAX as u64 { return SyscallResult::val(-EINVAL); }
    let operation = args.a1 as u32;
    let result = vfs::flock(h, operation);
    if result == -11 && operation & 4 == 0 {
        linux.pending_flock = Some((h, operation));
        kt.state = thread::ThreadState::Blocked;
        SyscallResult::val(0)
    } else { SyscallResult::val(result) }
}
fn sys_fsync<A: crate::Arch>(kt: &thread::KernelThread<A>, args: &Args) -> SyscallResult {
    SyscallResult::val(match kt.fds.get(args.a0 as usize) {
        Some(thread::FdKind::Vfs(h)) => vfs::sync_by_handle(*h),
        Some(thread::FdKind::Dir { handle, .. }) => vfs::sync_directory(*handle),
        Some(thread::FdKind::None) | None => -EBADF,
        _ => -EINVAL,
    })
}
fn sys_fchmod<A: crate::Arch>(kt: &thread::KernelThread<A>, args: &Args) -> SyscallResult {
    let mode = args.a1 as u32 & 0o7777;
    let result = match kt.fds.get(args.a0 as usize) {
        Some(thread::FdKind::Vfs(h)) => vfs::set_handle_mode(*h, mode),
        Some(thread::FdKind::Dir { handle, .. }) => {
            let mut path = [0; vfs::DIR_PATH_MAX];
            match vfs::dir_handle_path(*handle, &mut path) {
                Some(n) => vfs::set_path_mode(&path[..n], mode), None => -EBADF,
            }
        }
        _ => -EBADF,
    };
    SyscallResult::val(result)
}
fn sys_unlinkat<A: crate::Arch>(machine: &mut A, kt: &thread::KernelThread<A>, linux: &LinuxState, args: &Args) -> SyscallResult {
    if args.a2 & !0x200 != 0 { return SyscallResult::val(-EINVAL); }
    let mut raw = [0; vfs::PATH_KEY_MAX]; let n = machine.copy_cstr(args.a1 as usize, &mut raw);
    if n == raw.len() { return SyscallResult::val(-36); }
    if n == 0 { return SyscallResult::val(-ENOENT); }
    let fd = args.a0 as i32;
    if raw.first() != Some(&b'/') && fd != -100
        && !matches!(kt.fds.get(fd as usize), Some(thread::FdKind::Dir { .. })) {
        return SyscallResult::val(-EBADF);
    }
    let mut base = [0; vfs::DIR_PATH_MAX];
    let path = match mutation_path(machine, args.a1 as usize, at_base(kt, linux, fd, &mut base)) { Ok(path) => path, Err(error) => return SyscallResult::val(error) };
    SyscallResult::val(if args.a2 & 0x200 != 0 { vfs::rmdir(&path) } else { vfs::delete(&path) })
}
fn sys_chmod<A: crate::Arch>(machine: &mut A, linux: &LinuxState, args: &Args) -> SyscallResult {
    let path = match mutation_path(machine, args.a0 as usize, linux.cwd_str()) { Ok(path) => path, Err(error) => return SyscallResult::val(error) };
    SyscallResult::val(vfs::set_path_mode(&path, args.a1 as u32 & 0o7777))
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
                thread::FdKind::Socket(h) => net::add_ref(h),
                thread::FdKind::Dir { handle, .. } => vfs::add_dir_ref(handle),
                thread::FdKind::ConsoleOut | thread::FdKind::None => {}
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
        F_GETFL => SyscallResult::val(match kt.fds[fd] {
            FdKind::PipeRead(index) => if crate::kernel::kpipe::nonblocking(index, false) { 0x800 } else { 0 },
            FdKind::PipeWrite(index) => 1 | if crate::kernel::kpipe::nonblocking(index, true) { 0x800 } else { 0 },
            thread::FdKind::Socket(h) => 2 | if net::nonblocking(h) { 0x800 } else { 0 },
            _ => 0,
        }),
        F_SETFL => {
            let enabled = a.a2 & 0x800 != 0;
            match kt.fds[fd] {
                FdKind::Socket(h) => net::set_nonblocking(h, enabled),
                FdKind::PipeRead(index) => crate::kernel::kpipe::set_nonblocking(index, false, enabled),
                FdKind::PipeWrite(index) => crate::kernel::kpipe::set_nonblocking(index, true, enabled),
                _ => {},
            }
            SyscallResult::val(0)
        }
        _ => SyscallResult::val(-EINVAL),
    }
}

/// munmap(91)
fn sys_munmap<A: crate::Arch>(machine: &mut A, linux: &mut LinuxState, a: &Args) -> SyscallResult {
    let addr = a.a0 as usize;
    let length = a.a1 as usize;
    if addr & 0xfff != 0 || length == 0 { return SyscallResult::val(-EINVAL); }
    let Some(end) = addr.checked_add(length).and_then(|v| v.checked_add(4095)).map(|v| v & !4095) else { return SyscallResult::val(-EINVAL); };
    if end > elf::USER_STACK_TOP { return SyscallResult::val(-EINVAL); }
    machine.unmap_range(addr / 4096, (end - addr) / 4096);
    linux.shared_mappings.release(machine, addr, end);
    // Reuse a just-freed region at the current downward allocation frontier.
    if addr == linux.mmap_cursor { linux.mmap_cursor = end; }
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
#[inline(never)]
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
        linux.waiting_child = Some(pid);
    }
    thread::block_thread(threads, tid);
    crate::kernel::sched::linux_blocked_successor(threads, tid, true)
        .or_else(|| thread::schedule(threads, tid))
}

/// Reap a consumed blocking wait after the exit transaction and space switch.
pub(crate) fn reap_waited_child<A: crate::Arch>(machine: &mut A, threads: &mut [thread::Thread<A>], parent: usize) {
    let child = match &mut threads[parent].personality {
        thread::Personality::Linux(linux) => linux.reap_child.take(),
        _ => None,
    };
    if let Some(child) = child
        && threads[child].kernel.state == thread::ThreadState::Zombie
        && threads[child].kernel.parent_tid == parent as i32 {
        thread::reap(threads, machine, child as i32);
    }
}

/// Serial diagnostics only: inspect saved process state without switching roots.
pub(crate) fn debug_processes<A: crate::Arch>(threads: &[thread::Thread<A>], active: usize) {
    let owner = match &threads[active].personality {
        thread::Personality::Linux(linux) => Some(linux),
        _ => None,
    };
    for (tid, task) in threads.iter().enumerate().skip(1) {
        if matches!(task.kernel.state, thread::ThreadState::Unused) { continue; }
        if let thread::Personality::Linux(linux) = &task.personality {
            let state = match task.kernel.state {
                thread::ThreadState::Ready => "ready", thread::ThreadState::Running => "running",
                thread::ThreadState::Blocked => "blocked", thread::ThreadState::Zombie => "zombie",
                thread::ThreadState::Unused => "unused",
            };
            crate::compact_dbg_println!("[LINUX TASK] tid={} state={} parent={} terminal_shared={} io={} parked={} read={} wait={} vfork_parent={} reap={}",
                tid, state, task.kernel.parent_tid,
                owner.is_some_and(|owner| owner.shares_terminal(linux)), linux.has_blocked_work(),
                async_io::parked(&linux.async_io), linux.pending_read.is_some(),
                linux.waiting_child.unwrap_or(-1), linux.vfork_parent.map_or(-1, |parent| parent as i32),
                linux.reap_child.map_or(-1, |child| child as i32));
        }
    }
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
    if let thread::FdKind::Socket(h) = fd_kind { return message::writev(machine, h, a, want_64); }

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

        if let thread::FdKind::Vfs(handle) = fd_kind {
            let count = iov_len.min(file_io::MAX_WRITE - total as usize);
            let result = file_io::write_user(machine, handle, iov_base, count);
            if result < 0 { return SyscallResult::val(if total == 0 { result } else { total }); }
            total += result;
            if result as usize != iov_len || total as usize == file_io::MAX_WRITE { return SyscallResult::val(total); }
            continue;
        }

        let mut iov = alloc::vec![0u8; iov_len];
        machine.copy_from(iov_base, &mut iov);
        match fd_kind {
            thread::FdKind::ConsoleOut => {
                for &b in &iov {
                    lib::term::put_utf8(b);
                    if fd == 2 {
                        lib::log::debug_byte(b);
                    }
                }
                terminal_responses(kt);
                crate::kernel::term::mark_dirty();
                total += iov_len as i32;
            }
            thread::FdKind::PipeWrite(idx) => {
                let r = crate::kernel::kpipe::write(idx, &iov);
                if r < 0 { return SyscallResult::val(if r == -1 { -EPIPE } else { r }); }
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

pub(super) fn fd_readiness<A:crate::Arch>(kt:&thread::KernelThread<A>,fd:usize,events:i16)->i16 {
    const POLLIN:i16=1;const POLLOUT:i16=4;
    let mut revents=0;
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
                // The native backend reports actual buffers/connection state;
                // hosted sockets retain their blocking backend behavior.
                thread::FdKind::Socket(h) => {
                    revents |= net::readiness(h, events);
                }
                thread::FdKind::None => {revents|=32;}
            }
        }
    else {revents|=32;}
    revents
}

/// Evaluate a pollfd[] array once, writing revents and returning the
/// number of fds with non-zero revents. Used by both sys_poll's first try
/// and the event-loop's pending-poll retry.
pub(crate) fn run_poll<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, fds_ptr: usize, nfds: usize) -> i32 {
    let mut ready = 0i32;
    for i in 0..nfds {
        let base = fds_ptr + i * 8;
        let fd = machine.read::<i32>(base) as usize;
        if fd>i32::MAX as usize {machine.write::<i16>(base+6,0);continue;}
        let events = machine.read::<i16>(base + 4);
        let mut revents: i16 = 0;
        revents |= fd_readiness(kt,fd,events);
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
    linux.pending_poll = Some(thread::PendingPoll { fds_ptr, nfds, timeout_ms: timeout,
        deadline_ns: (timeout >= 0).then(|| crate::kernel::portio::now_ns().saturating_add(timeout as u64 * 1_000_000)),
    });
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
            if offset < 0 || offset > i64::from(u32::MAX) { return SyscallResult::val(-EINVAL); }
            let mut tmp = alloc::vec![0u8; len];
            let n = vfs::read_at_by_handle(handle, offset as u32, &mut tmp);
            if n > 0 { machine.copy_to(buf, &tmp[..n as usize]); }
            SyscallResult::val(n)
        }
        _ => SyscallResult::val(-EBADF),
    }
}

/// Linux pwrite64 keeps the open description's offset unchanged.
fn sys_pwrite64<A: crate::Arch>(machine: &mut A, kt: &thread::KernelThread<A>, a: &Args, native64: bool) -> SyscallResult {
    let offset = if native64 { a.a3 } else { a.a3 as u32 as u64 | ((a.a4 as u32 as u64) << 32) };
    if offset > u64::from(u32::MAX) { return SyscallResult::val(-EINVAL); }
    if a.a2 > i32::MAX as u64 { return SyscallResult::val(-EINVAL); }
    if a.a2 != 0 && (a.a1 == 0 || a.a1.checked_add(a.a2).is_none_or(|end| end > 0xc0000000)) {
        return SyscallResult::val(-14);
    }
    let handle = match kt.fds.get(a.a0 as usize) {
        Some(thread::FdKind::Vfs(h)) => *h,
        Some(thread::FdKind::PipeRead(_) | thread::FdKind::PipeWrite(_) | thread::FdKind::Socket(_)) => return SyscallResult::val(-ESPIPE),
        _ => return SyscallResult::val(-EBADF),
    };
    if matches!(vfs::handle_open_access(handle), Some(vfs::OpenAccess::Read)) {
        return SyscallResult::val(-EBADF);
    }
    let mut bytes = alloc::vec![0; (a.a2 as usize).min(65536)];
    machine.copy_from(a.a1 as usize, &mut bytes);
    SyscallResult::val(vfs::write_at_by_handle(handle, offset as u32, &bytes))
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
    const USER_END: u64 = 0xc0000000;
    if a.a1 == 0 { return SyscallResult::val(-EINVAL); }
    let Some(rounded) = a.a1.checked_add(4095).map(|n| n & !4095) else { return SyscallResult::val(-ENOMEM) };
    if rounded > USER_END { return SyscallResult::val(-ENOMEM); }
    let length = a.a1 as usize;
    let alloc_size = rounded as usize;
    let flags = a.a3 as u32;
    let fd = a.a4 as i32;

    const MAP_ANONYMOUS: u32 = 0x20;
    const MAP_FIXED: u32 = 0x10;

    let file_handle = if flags & MAP_ANONYMOUS == 0 {
        match kt.fds.get(fd as usize) {
            Some(thread::FdKind::Vfs(handle)) => Some(*handle),
            _ => return SyscallResult::val(-EBADF),
        }
    } else { None };
    let shared = file_handle.is_some() && matches!(flags & 3, 1 | 3);
    if shared && let Err(error) = vfs::mapping::validate(file_handle.unwrap(), offset_bytes, alloc_size, a.a2 & 2 != 0) {
        return SyscallResult::val(error);
    }

    let base = if flags & MAP_FIXED != 0 {
        if a.a0 == 0 || a.a0 & 4095 != 0 { return SyscallResult::val(-EINVAL); }
        let Some(_end) = a.a0.checked_add(rounded).filter(|end| *end <= USER_END) else { return SyscallResult::val(-ENOMEM) };
        a.a0 as usize
    } else {
        let Some(base) = file_mapping::allocate_below(linux.mmap_cursor, linux.heap_end, alloc_size, &linux.occupied_ranges)
            else { return SyscallResult::val(-ENOMEM) };
        linux.mmap_cursor = base;
        base
    };

    // MAP_FIXED replaces existing user pages, including read-only ELF pages.
    // Clear the mappings first so filling the replacement cannot fault on an
    // old protection bit or modify a frame shared with a forked process.
    if shared {
        if let Err(error) = linux.shared_mappings.map(machine, file_handle.unwrap(), offset_bytes, base, alloc_size, a.a2) {
            return SyscallResult::val(error);
        }
        if flags & MAP_FIXED != 0 { linux.occupied_ranges.push((base, base + alloc_size)); }
        return SyscallResult::val64(base as i64);
    }
    if flags & MAP_FIXED != 0 {
        machine.unmap_range(base / 4096, alloc_size / 4096);
        linux.shared_mappings.release(machine, base, base + alloc_size);
    }

    // File-backed mapping: read the file region into the (demand-allocated)
    // pages so the dynamic linker can map libc et al. Anonymous mappings stay
    // demand-zero (page-fault handler zero-fills on first touch). MAP_PRIVATE
    // file maps are treated as eager copies — fine since we never write back.
    if let Some(handle) = file_handle {
        machine.zero(base, alloc_size);
        if let Err(error) = file_mapping::copy_region(offset_bytes, length,
            |offset, bytes| vfs::read_at_by_handle(handle, offset, bytes),
            |offset, bytes| machine.copy_to(base + offset, bytes))
        { return SyscallResult::val(error); }
    } else {
        // Discard any old backing so reused addresses read as zero. The page
        // fault handler supplies zero pages on demand; reserving a large
        // region must not allocate and clear all its physical memory up front.
        if flags & MAP_FIXED == 0 { machine.unmap_range(base / 4096, alloc_size / 4096); }
    }

    if flags & MAP_FIXED != 0 { linux.occupied_ranges.push((base, base + alloc_size)); }
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
    if linux.shared_mappings.intersects(old_addr, old_addr.saturating_add(old_len)) {
        return SyscallResult::val(-EINVAL);
    }
    if new_len <= old_len {
        return SyscallResult::val64(old_addr as i64);
    }
    if flags & MREMAP_MAYMOVE == 0 {
        return SyscallResult::val64(-ENOMEM as i64);
    }
    let alloc_size = new_len.div_ceil(0x1000) * 0x1000;
    let Some(base) = file_mapping::allocate_below(linux.mmap_cursor, linux.heap_end, alloc_size, &linux.occupied_ranges)
        else { return SyscallResult::val(-ENOMEM) };
    linux.mmap_cursor = base;
    machine.zero(base, alloc_size);
    machine.copy_within(old_addr, base, old_len);
    SyscallResult::val64(base as i64)
}

/// utimensat, including futimens' Linux null-path form. Persist changes in
/// the shared filesystem backend rather than accepting a metadata-only fake.
fn sys_utimensat<A: crate::Arch>(machine: &mut A, kt: &thread::KernelThread<A>, linux: &LinuxState, a: &Args, wide: bool) -> SyscallResult {
    if a.a3 & !(0x100 | 0x1000) != 0 { return SyscallResult::val(-EINVAL); }
    let mut times = [Some(crate::kernel::clock::rtc_unix_timestamp().unwrap_or(0)); 2];
    if a.a2 != 0 {
        let stride = if wide { 16 } else { 8 };
        if a.a2.checked_add(2 * stride).is_none_or(|end| end > 0xc0000000) { return SyscallResult::val(-EFAULT); }
        for (index, value) in times.iter_mut().enumerate() {
            let pointer = a.a2 as usize + index * stride as usize;
            let (seconds, nanos) = if wide {
                (machine.read::<i64>(pointer), machine.read::<i64>(pointer + 8))
            } else {
                (i64::from(machine.read::<i32>(pointer)), i64::from(machine.read::<i32>(pointer + 4)))
            };
            match nanos {
                1_073_741_823 => {}, // UTIME_NOW
                1_073_741_822 => *value = None, // UTIME_OMIT
                0..=999_999_999 => match u32::try_from(seconds) {
                    Ok(seconds) => *value = Some(seconds),
                    Err(_) => return SyscallResult::val(-75),
                },
                _ => return SyscallResult::val(-EINVAL),
            }
        }
    }
    if times == [None, None] { return SyscallResult::val(0); }
    let fd = a.a0 as i32;
    let mut raw = [0; vfs::PATH_KEY_MAX];
    let length = if a.a1 == 0 { 0 } else { machine.copy_cstr(a.a1 as usize, &mut raw) };
    if length == raw.len() { return SyscallResult::val(-36); }
    if a.a1 == 0 || (length == 0 && a.a3 & 0x1000 != 0 && fd >= 0) {
        let path = match kt.fds.get(fd as usize) {
            Some(thread::FdKind::Vfs(handle)) => vfs::file_path_by_handle(*handle),
            Some(thread::FdKind::Dir { handle, .. }) => {
                let mut directory = [0; vfs::DIR_PATH_MAX];
                vfs::dir_handle_path(*handle, &mut directory).map(|len| directory[..len].to_vec())
            },
            _ => None,
        };
        return SyscallResult::val(path.map_or(-EBADF, |path| vfs::set_times(&path, true, times[0], times[1])));
    }
    if length == 0 { return SyscallResult::val(-ENOENT); }
    if raw[0] != b'/' && fd != -100 && !matches!(kt.fds.get(fd as usize), Some(thread::FdKind::Dir { .. })) {
        return SyscallResult::val(-EBADF);
    }
    let mut directory = [0; vfs::DIR_PATH_MAX];
    let base = at_base(kt, linux, fd, &mut directory);
    if raw[0] != b'/' && base.len() + length + 1 >= vfs::PATH_KEY_MAX { return SyscallResult::val(-36); }
    let mut buffer = [0; vfs::PATH_KEY_MAX];
    let resolved = resolve_path(&raw[..length], base, &mut buffer);
    SyscallResult::val(vfs::set_times(resolved, a.a3 & 0x100 == 0, times[0], times[1]))
}

/// Storage backends normally supply permissions only; device files also
/// supply their type so stat/fstat do not label them as regular files.
fn mode_with_type(mode: u16, default: u32) -> u32 {
    let mode = u32::from(mode);
    if mode & 0o170000 == 0 { mode | default } else { mode }
}

/// stat data (full st_mode incl. file type, size, ino) for a resolved VFS
/// path — the lookup shared by stat/fstatat/statx.
fn stat_lookup(resolved: &[u8]) -> Option<(u32, u32, u64, Option<u32>)> {
    if proc_fd::is_dir(resolved) { return Some((0o40500, 0, 0xf0000, None)); }
    let stat = vfs::stat(resolved, true)?;
    let kind = if stat.is_dir { 0o040000 } else { 0o100000 };
    Some((mode_with_type(stat.mode, kind), stat.size, stat.ino, stat.mtime))
}

/// Like `stat_lookup`, but preserve a symbolic link as the final object.
fn lstat_lookup(resolved: &[u8]) -> Option<(u32, u32, u64, Option<u32>)> {
    if proc_fd::is_dir(resolved) { return Some((0o40500, 0, 0xf0000, None)); }
    let stat = vfs::stat(resolved, false)?;
    let kind = if stat.is_symlink {
        0o120000
    } else if stat.is_dir {
        0o040000
    } else {
        0o100000
    };
    Some((mode_with_type(stat.mode, kind), stat.size, stat.ino, stat.mtime))
}

/// Base directory for `*at()` path resolution: a dirfd naming a directory
/// (via the dir-handle table) wins; AT_FDCWD / anything else = cwd.
fn at_base<'a, A: crate::Arch>(
    kt: &thread::KernelThread<A>,
    linux: &'a LinuxState,
    dirfd: i32,
    buf: &'a mut [u8; vfs::DIR_PATH_MAX],
) -> &'a [u8] {
    if dirfd >= 0
        && (dirfd as usize) < thread::MAX_FDS
        && let thread::FdKind::Dir { handle, .. } = kt.fds[dirfd as usize]
        && let Some(n) = vfs::dir_handle_path(handle, buf)
    {
        return &buf[..n];
    }
    linux.cwd_str()
}

/// stat64(195) / lstat64(196)
fn sys_stat64<A: crate::Arch>(machine: &mut A, kt: &thread::KernelThread<A>, linux: &LinuxState, a: &Args, want_64: bool, follow_final: bool) -> SyscallResult {
    let path_ptr = a.a0 as usize;
    let stat_buf = a.a1 as usize;
    let mut path_buf = [0u8; vfs::PATH_KEY_MAX];
    let path_len = machine.copy_cstr(path_ptr, &mut path_buf);
    if path_len == path_buf.len() { return SyscallResult::val(-36); }
    let path = &path_buf[..path_len];

    let mut pbuf = [0u8; vfs::PATH_KEY_MAX];
    let resolved = resolve_path(path, linux.cwd_str(), &mut pbuf);

    let stat = proc_fd::stat(kt, linux, resolved, follow_final).unwrap_or_else(||
        if follow_final { stat_lookup(resolved) } else { lstat_lookup(resolved) });
    match stat {
        Some((mode, size, ino, mtime)) => {
            write_stat64(machine, stat_buf, mode, size, ino, mtime, want_64);
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
    let mut path_buf = [0u8; vfs::PATH_KEY_MAX];
    let path_len = machine.copy_cstr(path_ptr, &mut path_buf);
    if path_len == path_buf.len() { return SyscallResult::val(-36); }
    let path = &path_buf[..path_len];

    // Empty path (AT_EMPTY_PATH): stat the fd itself.
    if path.is_empty() {
        let fd = dirfd as usize;
        if dirfd < 0 || fd >= thread::MAX_FDS {
            return SyscallResult::val(-EBADF);
        }
        let (mode, size, ino) = match kt.fds[fd] {
            thread::FdKind::Vfs(h) => (
                mode_with_type(vfs::file_mode_by_handle(h), 0o100000),
                vfs::file_size_by_handle(h),
                vfs::file_ino_by_handle(h),
            ),
            thread::FdKind::Dir { .. } => (0o40755, 0, 0),
            thread::FdKind::None => return SyscallResult::val(-EBADF),
            _ => (0o20666, 0, 0), // console / pipe / socket: char-dev-ish
        };
        write_statx(machine, statx_buf, mode, size, ino, fd_mtime(kt, fd));
        return SyscallResult::val(0);
    }

    let mut dbuf = [0u8; vfs::DIR_PATH_MAX];
    let base = at_base(kt, linux, dirfd, &mut dbuf);
    let mut pbuf = [0u8; vfs::PATH_KEY_MAX];
    let resolved = resolve_path(path, base, &mut pbuf);
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    let stat = proc_fd::stat(kt, linux, resolved, a.a2 & AT_SYMLINK_NOFOLLOW == 0).unwrap_or_else(||
        if a.a2 & AT_SYMLINK_NOFOLLOW == 0 { stat_lookup(resolved) } else { lstat_lookup(resolved) });
    match stat {
        Some((mode, size, ino, mtime)) => {
            write_statx(machine, statx_buf, mode, size, ino, mtime);
            SyscallResult::val(0)
        }
        None => SyscallResult::val(-ENOENT),
    }
}

/// Write a Linux `struct statx` (256 bytes) covering STATX_BASIC_STATS.
fn write_statx<A: crate::Arch>(machine: &mut A, buf: usize, mode: u32, size: u32, ino: u64, mtime: Option<u32>) {
    machine.zero(buf, 256);
    machine.write::<u32>(buf, 0x71F | if mtime.is_some() { 0x40 } else { 0 }); // Basic fields plus available mtime
    machine.write::<u32>(buf + 4, 4096); // stx_blksize
    machine.write::<u32>(buf + 16, 1); // stx_nlink
    machine.write::<u16>(buf + 28, mode as u16); // stx_mode
    machine.write::<u64>(buf + 32, ino); // stx_ino
    machine.write::<u64>(buf + 40, size as u64); // stx_size
    machine.write::<u64>(buf + 48, (size as u64).div_ceil(512)); // stx_blocks
    machine.write::<u64>(buf + 112, u64::from(mtime.unwrap_or(0))); // stx_mtime.tv_sec
}

/// Shared VFS timestamp lookup for regular-file and directory descriptors.
fn fd_mtime<A: crate::Arch>(kt: &thread::KernelThread<A>, fd: usize) -> Option<u32> {
    match kt.fds.get(fd)? {
        thread::FdKind::Dir { handle, .. } => {
            let mut path = [0; vfs::DIR_PATH_MAX];
            let len = vfs::dir_handle_path(*handle, &mut path)?;
            vfs::stat(&path[..len], true)?.mtime
        }
        thread::FdKind::Vfs(_) => vfs::handle_mtime(fd as i32, &kt.fds),
        _ => None,
    }
}

/// fstat64(197)
fn sys_fstat64<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, a: &Args, want_64: bool) -> SyscallResult {
    let fd = a.a0 as usize;
    let stat_buf = a.a1 as usize;

    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    match kt.fds[fd] {
        thread::FdKind::ConsoleOut => {
            write_stat64(machine, stat_buf, 0o20666, 0, 0, None, want_64); // S_IFCHR
            SyscallResult::val(0)
        }
        thread::FdKind::PipeRead(index) if index == thread::console_pipe() => {
            write_stat64(machine, stat_buf, 0o20666, 0, 0, None, want_64);
            SyscallResult::val(0)
        }
        thread::FdKind::PipeRead(_) | thread::FdKind::PipeWrite(_) => {
            write_stat64(machine, stat_buf, 0o10600, 0, 0, None, want_64); // S_IFIFO
            SyscallResult::val(0)
        }
        thread::FdKind::Vfs(handle) => {
            let size = vfs::file_size_by_handle(handle);
            let mode = vfs::file_mode_by_handle(handle);
            let ino = vfs::file_ino_by_handle(handle);
            write_stat64(machine, stat_buf, mode_with_type(mode, 0o100000), size, ino, fd_mtime(kt, fd), want_64);
            SyscallResult::val(0)
        }
        thread::FdKind::Dir { .. } => {
            write_stat64(machine, stat_buf, 0o40755, 0, 0, fd_mtime(kt, fd), want_64); // S_IFDIR
            SyscallResult::val(0)
        }
        thread::FdKind::Socket(_) => {
            write_stat64(machine, stat_buf, 0o140000 | 0o777, 0, 0, None, want_64); // S_IFSOCK
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
    let mut path_buf = [0u8; vfs::PATH_KEY_MAX];
    let path_len = machine.copy_cstr(path_ptr, &mut path_buf);
    if path_len == path_buf.len() { return SyscallResult::val(-36); }
    let path = &path_buf[..path_len];

    if path.is_empty() && a.a3 & 0x1000 != 0 && dirfd >= 0 {
        let fd_args = Args { a0: dirfd as u64, a1: a.a2, ..*a };
        return sys_fstat64(machine, kt, &fd_args, want_64);
    }

    // Resolve relative to the dirfd's directory (dir-handle table) — ls does
    // fstatat(dirfd_of_dir, entry_name) for every listing entry.
    let mut dbuf = [0u8; vfs::DIR_PATH_MAX];
    let base = at_base(kt, linux, dirfd, &mut dbuf);
    let mut pbuf = [0u8; vfs::PATH_KEY_MAX];
    let resolved = resolve_path(path, base, &mut pbuf);
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    let stat = proc_fd::stat(kt, linux, resolved, a.a3 & AT_SYMLINK_NOFOLLOW == 0).unwrap_or_else(||
        if a.a3 & AT_SYMLINK_NOFOLLOW == 0 { stat_lookup(resolved) } else { lstat_lookup(resolved) });
    match stat {
        Some((mode, size, ino, mtime)) => {
            write_stat64(machine, stat_buf, mode, size, ino, mtime, want_64);
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
fn write_stat64<A: crate::Arch>(machine: &mut A, buf: usize, mode: u32, size: u32, ino: u64, mtime: Option<u32>, want_64: bool) {
    if want_64 {
        machine.zero(buf, 144);
        machine.write::<u64>(buf + 88, u64::from(mtime.unwrap_or(0))); // st_mtim.tv_sec
        machine.write::<u64>(buf, 1);                              // st_dev
        machine.write::<u64>(buf + 8, ino);                            // st_ino
        machine.write::<u64>(buf + 16, 1);                             // st_nlink
        machine.write::<u32>(buf + 24, mode);                          // st_mode
        machine.write::<u64>(buf + 48, size as u64);                   // st_size
        machine.write::<u64>(buf + 56, 4096);                          // st_blksize
        machine.write::<u64>(buf + 64, (size as u64).div_ceil(512));   // st_blocks
    } else {
        machine.zero(buf, 96);
        machine.write::<u32>(buf + 72, mtime.unwrap_or(0)); // st_mtim.tv_sec
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
fn write_stat_old<A: crate::Arch>(machine: &mut A, buf: usize, mode: u32, size: u32, mtime: Option<u32>) {
    machine.zero(buf, 64);
    machine.write::<u32>(buf + 40, mtime.unwrap_or(0)); // st_mtime
    machine.write::<u16>(buf + 0x08, mode as u16);          // st_mode
    machine.write::<u16>(buf + 0x0a, 1);                    // st_nlink
    machine.write::<u32>(buf + 0x14, size);                 // st_size
    machine.write::<u32>(buf + 0x18, 4096);                 // st_blksize
    machine.write::<u32>(buf + 0x1c, size.div_ceil(512));   // st_blocks
}

/// stat(106) / lstat(107) — old struct stat layout.
fn sys_stat_old<A: crate::Arch>(machine: &mut A, kt: &thread::KernelThread<A>, linux: &LinuxState, a: &Args, follow_final: bool) -> SyscallResult {
    let mut path_buf = [0u8; vfs::PATH_KEY_MAX];
    let path_len = machine.copy_cstr(a.a0 as usize, &mut path_buf);
    if path_len == path_buf.len() { return SyscallResult::val(-36); }
    let path = &path_buf[..path_len];
    let stat_buf = a.a1 as usize;
    let mut pbuf = [0u8; vfs::PATH_KEY_MAX];
    let resolved = resolve_path(path, linux.cwd_str(), &mut pbuf);
    let stat = proc_fd::stat(kt, linux, resolved, follow_final).unwrap_or_else(||
        if follow_final { stat_lookup(resolved) } else { lstat_lookup(resolved) });
    match stat {
        Some((mode, size, _, mtime)) => {
            write_stat_old(machine, stat_buf, mode, size, mtime);
            SyscallResult::val(0)
        }
        None => SyscallResult::val(-ENOENT),
    }
}

/// fstat(108) — old struct stat layout.
fn sys_fstat_old<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, a: &Args) -> SyscallResult {
    let fd = a.a0 as usize;
    let stat_buf = a.a1 as usize;
    if fd >= thread::MAX_FDS { return SyscallResult::val(-EBADF); }
    match kt.fds[fd] {
        thread::FdKind::ConsoleOut | thread::FdKind::PipeRead(_) | thread::FdKind::PipeWrite(_) => {
            write_stat_old(machine, stat_buf, 0o20666, 0, None); // S_IFCHR
            SyscallResult::val(0)
        }
        thread::FdKind::Vfs(handle) => {
            let size = vfs::file_size_by_handle(handle);
            let mode = vfs::file_mode_by_handle(handle);
            write_stat_old(machine, stat_buf, mode_with_type(mode, 0o100000), size, fd_mtime(kt, fd));
            SyscallResult::val(0)
        }
        thread::FdKind::Dir { .. } => {
            write_stat_old(machine, stat_buf, 0o40755, 0, fd_mtime(kt, fd));
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
        thread::FdKind::None => return SyscallResult::val(-EBADF),
        _ => return SyscallResult::val(-20),
    };

    // The fd's recorded directory; a dead/unknown handle falls back to cwd
    // (the pre-table behavior for opendir(".")).
    let mut dir_buf = [0u8; vfs::DIR_PATH_MAX];
    let directory: &[u8] = match vfs::dir_handle_path(handle, &mut dir_buf) {
        Some(len) => &dir_buf[..len],
        None => linux.cwd_str(),
    };
    if proc_fd::is_dir(directory) {
        let result = proc_fd::getdents(machine, kt, linux, &mut index, dirp, count);
        kt.fds[fd] = thread::FdKind::Dir { handle, next: index as u32 };
        return SyscallResult::val(result);
    }

    let mut offset = 0usize;
    while let Some(entry) = vfs::readdir(directory, index) {
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
        let file_type = if entry.is_dir {
            4 // DT_DIR
        } else if entry.is_symlink {
            10 // DT_LNK
        } else if entry.mode & 0o170000 != 0 {
            ((entry.mode & 0o170000) >> 12) as u8
        } else {
            8 // DT_REG
        };
        machine.write::<u8>(base + 18, file_type);
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

/// getrandom(355 i386 / 318 x86_64) — shared cryptographic entropy.
fn sys_getrandom<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, linux: &mut LinuxState, a: &Args) -> SyscallResult {
    match entropy::Request::read(a) {
        Err(error) => SyscallResult::val(error),
        Ok(request) => match request.step(machine) {
            Some(result) => SyscallResult::val(result),
            None => {
                linux.pending_random = Some(request);
                kt.state = thread::ThreadState::Blocked;
                SyscallResult::val(0)
            }
        },
    }
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
    crate::kernel::kpipe::set_nonblocking(pipe_idx, false, flags & 0x800 != 0);
    crate::kernel::kpipe::set_nonblocking(pipe_idx, true, flags & 0x800 != 0);

    if flags & O_CLOEXEC != 0 {
        kt.cloexec |= (1 << read_fd) | (1 << write_fd);
    }

    machine.write::<i32>(pipefd_ptr, read_fd as i32);
    machine.write::<i32>(pipefd_ptr + 4, write_fd as i32);
    SyscallResult::val(0)
}

/// dup shares the open description and clears close-on-exec on the new fd.
fn sys_dup<A: crate::Arch>(kt: &mut thread::KernelThread<A>, a: &Args) -> SyscallResult {
    sys_fcntl(kt, &Args { a0: a.a0, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 })
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
        thread::FdKind::Socket(h) => net::add_ref(h),
        thread::FdKind::Dir { handle, .. } => vfs::add_dir_ref(handle),
        thread::FdKind::ConsoleOut | thread::FdKind::None => {}
    }
    kt.fds[newfd] = kind;
    kt.cloexec &= !(1 << newfd);

    SyscallResult::val(newfd as i32)
}

/// DOS PSP command lines omit argv[0]; quote arguments containing whitespace.
fn dos_command_tail(args: &[alloc::vec::Vec<u8>]) -> alloc::vec::Vec<u8> {
    let mut tail = alloc::vec::Vec::new();
    for arg in args.iter().skip(1) {
        if !tail.is_empty() { tail.push(b' '); }
        let quoted = arg.is_empty() || arg.iter().any(|b| b.is_ascii_whitespace());
        if quoted { tail.push(b'"'); }
        tail.extend_from_slice(arg);
        if quoted { tail.push(b'"'); }
    }
    tail
}
