//! Thread and process management
//!
//! Thread states: Unused, Running, Ready, Blocked, Zombie
//! TID 0 is the idle/init thread (never scheduled away from if no other threads)

use crate::arch::{USER_CS, USER_CS64, USER_DS};
use crate::kernel::stacktrace::SymbolData;
use crate::println;
use crate::{Frame64, Regs};

// Re-export personality state types so `thread::DosState` / `thread::LinuxState` still works
pub use crate::kernel::dos::DosState;
pub use crate::kernel::linux::LinuxState;

/// Maximum number of threads
pub const MAX_THREADS: usize = 1024;

/// Maximum file descriptors per thread
pub const MAX_FDS: usize = 16;

/// What a file descriptor refers to
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FdKind {
    /// Slot is free
    None,
    /// VFS file (index into global FILE_TABLE)
    Vfs(i32),
    /// Read end of a kernel pipe
    PipeRead(u8),
    /// Write end of a kernel pipe
    PipeWrite(u8),
    /// Console stdout/stderr (VGA putchar)
    ConsoleOut,
}

impl FdKind {
    pub fn is_none(&self) -> bool { matches!(self, FdKind::None) }
}

/// A pending blocked read — generalized from stdin-only to any fd
pub struct PendingRead {
    pub fd_kind: FdKind,   // what we're reading from (PipeRead or ConsoleOut won't happen)
    pub buf_ptr: usize,
    pub buf_len: usize,
}

/// Thread state
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ThreadState {
    Unused = 0,
    Running,
    Ready,
    Blocked,
    Zombie,
}

/// What the OS personality wants the kernel to do.
/// Returned by the KernelEvent dispatch in `startup::event_loop`, by syscall
/// dispatch, and by DPMI INT/exception paths. The event loop acts on it —
/// personality code never touches scheduling.
pub enum KernelAction {
    /// Nothing to do, continue current thread.
    Done,
    /// Yield current thread to scheduler.
    Yield,
    /// Exit current thread with given code.
    Exit(i32),
    /// Fork: COW-clone current process. Callback receives child_tid (or -errno).
    Fork(fn(&mut crate::Regs, i32)),
    /// Switch to a specific thread (already resolved by caller).
    Switch(usize),
    /// ForkExec: fork a child, exec the given path, block parent.
    /// Callbacks set ABI-specific output on parent's regs.
    ForkExec {
        path: [u8; 164],
        path_len: usize,
        on_error: fn(&mut crate::Regs, i32),
        on_success: fn(&mut crate::Regs, child_tid: i32),
    },
    /// Exec: replace current process with program at path.
    Exec {
        path: [u8; 164],
        path_len: usize,
        args: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    },
}

/// OS personality — determines event loop dispatch and carries OS-specific state
pub enum Personality {
    /// DOS mode: VM86 (real mode) or DPMI (32-bit protected mode)
    Dos(DosState),
    /// Linux userspace (32 or 64-bit, distinguished by CS descriptor)
    Linux(LinuxState),
}

/// Backward compat alias
pub type ThreadMode = Personality;

/// Initialize Regs for user processes (extends Regs with descriptor-aware methods)
impl Regs {
    /// Initialize for a 32-bit user process (stored as Frame64; arch converts on exit if needed)
    pub fn init_user_process(&mut self, entry: u32, stack: u32) {
        let ds = USER_DS as u64;
        const IF_FLAG: u64 = 1 << 9;

        *self = Self::empty();
        self.gs = ds;
        self.fs = ds;
        self.es = ds;
        self.ds = ds;
        self.frame = Frame64 {
            rip: entry as u64,
            cs: USER_CS as u64,
            rflags: IF_FLAG,
            rsp: stack as u64,
            ss: USER_DS as u64,
        };
    }

    /// Initialize for a 64-bit user process
    pub fn init_user_process_64(&mut self, entry: u64, stack: u64) {
        let ds = USER_DS as u64;
        const IF_FLAG: u64 = 1 << 9;

        *self = Self::empty();
        self.gs = 0;   // FS/GS are MSR bases in 64-bit mode, 0 = no TLS yet
        self.fs = 0;
        self.es = ds;
        self.ds = ds;
        self.frame = Frame64 {
            rip: entry,
            cs: USER_CS64 as u64,
            rflags: IF_FLAG,
            rsp: stack,
            ss: USER_DS as u64,
        };
    }
}

/// Kernel-side thread state shared across all personalities.
/// Personality code receives `&mut KernelThread` alongside its own `&mut DosState`
/// or `&mut LinuxState`, giving clean split borrows with no wrapper hacks.
pub struct KernelThread {
    pub tid: i32,
    pub pid: i32,
    pub priority: i32,
    pub parent_tid: i32,
    pub state: ThreadState,
    pub time: u32,
    pub root: crate::RootPageTable,
    pub cpu_state: Regs,
    pub fx_state: crate::arch::FxState,
    pub exit_code: i32,
    pub addr_hash: u64,
    pub cpu_hash: u64,
    pub cwd: [u8; 64],
    pub cwd_len: usize,
    pub symbols: Option<SymbolData>,
    pub fds: [FdKind; MAX_FDS],
    pub cloexec: u16,
}

/// Thread control block = kernel state + OS personality
pub struct Thread {
    pub kernel: KernelThread,
    pub personality: Personality,
}

/// FNV-1a hash of a Regs struct (raw byte view).
/// Used to detect whether a saved thread's CPU state is modified while
/// the thread is not running.
pub fn hash_regs(r: &Regs) -> u64 {
    let bytes = unsafe {
        core::slice::from_raw_parts(r as *const _ as *const u8, core::mem::size_of::<Regs>())
    };
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Recompute a thread's cpu_hash after an out-of-band modification to cpu_state.
pub fn refresh_cpu_hash(t: &mut Thread) {
    t.kernel.cpu_hash = hash_regs(&t.kernel.cpu_state);
}

impl KernelThread {
    pub fn empty() -> Self {
        KernelThread {
            tid: 0,
            pid: 0,
            priority: 0,
            parent_tid: -1,
            state: ThreadState::Unused,
            time: 0,
            root: crate::RootPageTable::empty(),
            cpu_state: Regs::empty(),
            fx_state: crate::arch::FxState::zeroed(),
            exit_code: 0,
            addr_hash: 0,
            cpu_hash: 0,
            cwd: [0; 64],
            cwd_len: 0,
            symbols: None,
            fds: [FdKind::None; MAX_FDS],
            cloexec: 0,
        }
    }

    pub fn cwd_str(&self) -> &[u8] { &self.cwd[..self.cwd_len] }

    pub fn set_cwd(&mut self, path: &[u8]) {
        let len = path.len().min(self.cwd.len());
        self.cwd[..len].copy_from_slice(&path[..len]);
        self.cwd_len = len;
    }

    /// Find a free fd slot (starting from `from`). Returns fd number or None.
    pub fn alloc_fd(&self, from: usize) -> Option<usize> {
        for i in from..MAX_FDS {
            if self.fds[i].is_none() {
                return Some(i);
            }
        }
        None
    }

    /// Close a single fd, decrementing pipe/VFS refcounts as needed.
    pub fn close_fd(&mut self, fd: usize) {
        if fd >= MAX_FDS { return; }
        match self.fds[fd] {
            FdKind::Vfs(idx) => {
                crate::kernel::vfs::close_vfs_handle(idx);
            }
            FdKind::PipeRead(idx) => {
                crate::kernel::kpipe::close_reader(idx);
            }
            FdKind::PipeWrite(idx) => {
                crate::kernel::kpipe::close_writer(idx);
            }
            FdKind::ConsoleOut | FdKind::None => {}
        }
        self.fds[fd] = FdKind::None;
        self.cloexec &= !(1 << fd);
    }

    /// Close all fds.
    pub fn close_all_fds(&mut self) {
        for i in 0..MAX_FDS {
            self.close_fd(i);
        }
    }

    /// Close only CLOEXEC fds (for execve).
    pub fn close_cloexec(&mut self) {
        let mask = self.cloexec;
        for i in 0..MAX_FDS {
            if mask & (1 << i) != 0 {
                self.close_fd(i);
            }
        }
    }

    /// Duplicate fd table for fork. Increments refcounts on pipes and VFS handles.
    pub fn dup_all_fds(&self, dst: &mut KernelThread) {
        dst.fds = self.fds;
        dst.cloexec = self.cloexec;
        for i in 0..MAX_FDS {
            match dst.fds[i] {
                FdKind::Vfs(idx) => {
                    crate::kernel::vfs::add_vfs_ref(idx);
                }
                FdKind::PipeRead(idx) => {
                    crate::kernel::kpipe::add_reader(idx);
                }
                FdKind::PipeWrite(idx) => {
                    crate::kernel::kpipe::add_writer(idx);
                }
                FdKind::ConsoleOut | FdKind::None => {}
            }
        }
    }
}

impl Thread {
    pub fn empty() -> Self {
        Thread {
            kernel: KernelThread::empty(),
            personality: Personality::Linux(LinuxState::new()),
        }
    }

    /// Check if this thread is a DOS thread (VM86 or DPMI)
    pub fn is_dos(&self) -> bool {
        matches!(self.personality, Personality::Dos(_))
    }

    /// Check if this DOS thread has DPMI state active
    pub fn has_dpmi(&self) -> bool {
        matches!(&self.personality, Personality::Dos(dos) if dos.dpmi.is_some())
    }

    /// Get mutable reference to DosState (panics if not a DOS thread)
    pub fn dos_mut(&mut self) -> &mut DosState {
        match &mut self.personality {
            Personality::Dos(dos) => dos,
            _ => panic!("dos_mut on non-DOS thread"),
        }
    }
}

/// Thread array (heap-allocated to keep large RootPageTable out of .data)
static mut THREADS: alloc::vec::Vec<Thread> = alloc::vec::Vec::new();

/// Console stdin kpipe index (shared by all Linux processes)
static mut CONSOLE_PIPE: u8 = 0;

pub fn set_console_pipe(idx: u8) { unsafe { CONSOLE_PIPE = idx; } }
pub fn console_pipe() -> u8 { unsafe { CONSOLE_PIPE } }

/// Check if threading system is initialized
pub fn is_initialized() -> bool {
    unsafe { (*(&raw const THREADS)).len() > 0 }
}

pub fn prng() -> u64 {
    /// PRNG state for random scheduling
    static mut SEED: u64 = 0xcafe_babe_dead_beef;

    unsafe {
        const A: u64 = 0xdead_beed;
        const C: u64 = 0x1234_5679;
        SEED = A.wrapping_mul(SEED).wrapping_add(C);
        SEED
    }
}


/// Get thread by TID
pub fn get_thread(tid: usize) -> Option<&'static mut Thread> {
    if tid >= MAX_THREADS {
        return None;
    }
    unsafe {
        let thread = &mut THREADS[tid];
        if thread.kernel.state != ThreadState::Unused {
            Some(thread)
        } else {
            None
        }
    }
}

/// Get mutable references to two different threads (for switch_to).
pub fn get_two_threads(a: usize, b: usize) -> (&'static mut Thread, &'static mut Thread) {
    assert!(a != b && a < MAX_THREADS && b < MAX_THREADS);
    unsafe {
        let pa = &mut THREADS[a] as *mut Thread;
        let pb = &mut THREADS[b] as *mut Thread;
        (&mut *pa, &mut *pb)
    }
}

/// Create a new thread with the given root page table.
pub fn create_thread(parent_tid: Option<usize>, root: crate::RootPageTable, is_process: bool) -> Option<&'static mut Thread> {
    unsafe {
        let parent = parent_tid.map(|tid| &THREADS[tid].kernel);
        for i in 0..MAX_THREADS {
            if THREADS[i].kernel.state == ThreadState::Unused {
                let t = &mut THREADS[i];
                let k = &mut t.kernel;
                k.tid = i as i32;
                k.pid = if is_process { i as i32 } else { parent.map(|p| p.pid).unwrap_or(0) };
                k.priority = parent.map(|p| p.priority).unwrap_or(0);
                k.parent_tid = parent.map(|p| p.tid).unwrap_or(-1);
                k.state = ThreadState::Ready;
                k.time = crate::arch::get_ticks() as u32;
                k.root = root;
                k.cpu_state = Regs::empty();
                k.fx_state = crate::arch::clean_fx_template();
                k.exit_code = 0;
                k.addr_hash = 0;
                k.cpu_hash = 0;
                t.personality = Personality::Linux(LinuxState::new());
                return Some(t);
            }
        }
        None
    }
}

/// Initialize a thread as a 32-bit user process
pub fn init_process_thread(thread: &mut Thread, entry: u32, stack: u32) {
    thread.kernel.cpu_state.init_user_process(entry, stack);
}

/// Initialize a thread as a 64-bit user process
pub fn init_process_thread_64(thread: &mut Thread, entry: u64, stack: u64) {
    thread.kernel.cpu_state.init_user_process_64(entry, stack);
}

/// Initialize a thread for VM86 mode (.COM execution)
/// cs/ip/ss/sp are real-mode segment:offset values
pub fn init_process_thread_vm86(thread: &mut Thread, psp_seg: u16, cs: u16, ip: u16, ss: u16, sp: u16) {
    use crate::kernel::machine::{VM_FLAG, IF_FLAG, VIF_FLAG};
    thread.personality = Personality::Dos(DosState::new());

    let state = &mut thread.kernel.cpu_state;
    *state = Regs::empty();

    // DS=ES=PSP segment for DOS programs, FS=GS=0
    state.ds = psp_seg as u64;
    state.es = psp_seg as u64;
    state.fs = 0;
    state.gs = 0;

    state.frame = Frame64 {
        rip: ip as u64,
        cs: cs as u64,
        rflags: (VM_FLAG | IF_FLAG | VIF_FLAG | 0x1000) as u64,
        rsp: sp as u64,
        ss: ss as u64,
    };
}

/// Save CPU state to thread.
pub fn save_state(thread: &mut Thread, regs: &Regs) {
    thread.kernel.cpu_state = *regs;
}

/// Block a thread (waiting for child exit).
pub fn block_thread(tid: usize) {
    unsafe { THREADS[tid].kernel.state = ThreadState::Blocked; }
}

pub fn unblock_thread(tid: usize) {
    unsafe {
        if tid < MAX_THREADS && THREADS[tid].kernel.state == ThreadState::Blocked {
            THREADS[tid].kernel.state = ThreadState::Ready;
        }
    }
}

/// F11 / Ctrl-Z: cancel the parent's waitpid if it was blocked waiting on us.
/// After this call, parent and child are independent peers.
/// Signals "decoupled" to parent via AX=1 (synth fork_exec_wait return).
pub fn cancel_parent_wait(child_tid: usize) {
    unsafe {
        let child = &THREADS[child_tid];
        let parent_tid = child.kernel.parent_tid;
        if parent_tid < 0 || (parent_tid as usize) >= MAX_THREADS { return; }
        let parent = &mut THREADS[parent_tid as usize];
        if parent.kernel.state != ThreadState::Blocked { return; }
        parent.kernel.state = ThreadState::Ready;
        if let Personality::Dos(dos) = &mut parent.personality {
            dos.last_child_exit_status = 0;
        }
        // Signal decoupled to parent's synth fork_exec_wait: AX = 1 (status=decoupled).
        parent.kernel.cpu_state.rax = (parent.kernel.cpu_state.rax & !0xFFFF) | 0x0001;
        refresh_cpu_hash(parent);
    }
}

/// Yield a thread: save regs, mark Ready, schedule next.
pub fn yield_thread(tid: usize, regs: &crate::Regs) -> Option<usize> {
    unsafe {
        let k = &mut THREADS[tid].kernel;
        k.cpu_state = *regs;
        k.state = ThreadState::Ready;
    }
    schedule(tid)
}

/// Set return value in thread's saved state
pub fn set_return(thread: &mut Thread, ret: i32) {
    thread.kernel.cpu_state.rax = ret as i64 as u64;
}

/// Schedule next thread (randomly selected from ready threads).
/// Returns Some(idx) if a switch is needed, None to stay with current.
pub fn schedule(current_tid: usize) -> Option<usize> {
    unsafe {
        let mut next_idx: usize = usize::MAX;
        let mut count = 0u64;

        for i in 1..MAX_THREADS {
            if i == current_tid {
                continue;
            }
            if THREADS[i].kernel.state == ThreadState::Ready {
                count += 1;
                if prng() % count == 0 {
                    next_idx = i;
                }
            }
        }

        if next_idx == usize::MAX {
            None
        } else {
            Some(next_idx)
        }
    }
}

/// Take target thread's saved VGA state (swap, no data copy) and restore to hardware.
/// `dst` is the running caller's VGA state; the caller adopts target's screen.
/// Returns 0 on success, negative errno on failure.
pub fn vga_take(dst: &mut crate::kernel::machine::VgaState, target_tid: i32) -> i32 {
    if target_tid < 0 || (target_tid as usize) >= MAX_THREADS { return -22; } // EINVAL
    unsafe {
        let target = &mut *(&raw mut THREADS[target_tid as usize]);
        if target.kernel.state == ThreadState::Unused { return -3; } // ESRCH
        let src = match &mut target.personality {
            Personality::Dos(d) => &mut d.pc.vga,
            _ => return -22, // target not DOS
        };
        if src.planes.is_empty() { return -61; }
        core::mem::swap(dst, src);
        dst.restore_to_hardware();
    }
    0
}

/// F11 hotkey flag for thread cycling
static mut SWITCH_REQUESTED: bool = false;

pub fn request_switch() {
    unsafe { core::ptr::write_volatile(&raw mut SWITCH_REQUESTED, true); }
}

pub fn take_switch_request() -> bool {
    unsafe {
        let v = core::ptr::read_volatile(&raw const SWITCH_REQUESTED);
        if v { core::ptr::write_volatile(&raw mut SWITCH_REQUESTED, false); }
        v
    }
}

/// Round-robin: next active thread after current (skips thread 0).
/// Includes Blocked threads — F11 refocuses a blocked parent (VGA restore)
/// without unblocking it. Only Unused/Zombie are skipped.
pub fn cycle_next(current_tid: usize) -> Option<usize> {
    unsafe {
        let cur = current_tid;
        for offset in 1..MAX_THREADS {
            let i = (cur + offset) % MAX_THREADS;
            if i == 0 { continue; }
            match THREADS[i].kernel.state {
                ThreadState::Ready | ThreadState::Running | ThreadState::Blocked => return Some(i),
                _ => {}
            }
        }
        None
    }
}

/// Exit thread and schedule next.
/// Returns the TID of the next thread to run (falls back to thread 0/idle).
pub fn exit_thread(tid: usize, exit_code: i32) -> usize {
    unsafe {
        let thread = &mut THREADS[tid];
        let parent_tid = thread.kernel.parent_tid;
        match &mut thread.personality {
            Personality::Dos(dos) => {
                dos.pc.vga.save_from_hardware();
                if let Some(ref mut ems) = dos.ems {
                    ems.free_all_pages();
                }
                dos.ems = None;
                dos.xms = None;
                dos.pc.set_a20(true);
            }
            Personality::Linux(_) => {}
        }

        thread.kernel.close_all_fds();
        thread.kernel.symbols = None;

        thread.kernel.exit_code = exit_code;

        // Wake blocked parent and write status BEFORE arch_user_clean —
        // the parent's stack is still accessible through COW-shared pages.
        if parent_tid >= 0 && (parent_tid as usize) < MAX_THREADS {
            let parent = &mut THREADS[parent_tid as usize];
            let was_waiting = parent.kernel.state == ThreadState::Blocked;
            if was_waiting {
                parent.kernel.state = ThreadState::Ready;
                match &mut parent.personality {
                    Personality::Dos(_) => {
                        parent.kernel.cpu_state.rax = parent.kernel.cpu_state.rax & !0xFFFF;
                    }
                    Personality::Linux(linux) => {
                        parent.kernel.cpu_state.rax = thread.kernel.tid as u64;
                        // status_ptr was saved in sys_wait4 when parent blocked.
                        // Just set the exit code; the deferred write happens
                        // during thread switch when parent's address space is loaded.
                        linux.wait_exit_code = exit_code;
                    }
                }
                refresh_cpu_hash(parent);
            }
            if let Personality::Dos(dos) = &mut parent.personality {
                dos.last_child_exit_status = (exit_code as u8) as u16;
            }
        }

        crate::kernel::startup::arch_user_clean();
        thread.kernel.state = ThreadState::Zombie;

        schedule(tid).unwrap_or(0)
    }
}

/// Wait for a child to exit. Returns (child_tid, exit_code) or -ECHILD if no children.
/// If pid == -1, waits for any child. Otherwise waits for specific pid.
/// Non-blocking: returns -EAGAIN if children exist but none have exited yet.
pub fn waitpid(current_tid: usize, pid: i32) -> (i32, i32) {
    unsafe {
        let current_tid = THREADS[current_tid].kernel.tid;
        let mut has_children = false;

        for i in 1..MAX_THREADS {
            let k = &mut THREADS[i].kernel;
            if k.parent_tid == current_tid && k.state != ThreadState::Unused {
                has_children = true;
                if k.state == ThreadState::Zombie && (pid == -1 || k.tid == pid) {
                    let tid = k.tid;
                    let code = k.exit_code;
                    k.state = ThreadState::Unused;
                    return (tid, code);
                }
            }
        }

        if has_children {
            (-11, 0)  // EAGAIN
        } else {
            (-10, 0)  // ECHILD
        }
    }
}

/// Signal thread (e.g., on segfault).
/// Returns Some(idx) if a context switch is needed (current thread killed).
pub fn signal_thread(thread: &mut Thread, current_tid: usize, fault_address: usize) -> Option<usize> {
    if thread.kernel.pid == 0 {
        println!("\x1b[91mSEGV in init at {:#x}\x1b[0m", fault_address);
        loop { core::hint::spin_loop(); }
    } else {
        println!("SEGV in thread {} at {:#x} rip={:#x} cs={:#x} rsp={:#x} ss={:#x} fl={:#x} rax={:#x} rbx={:#x} rcx={:#x}",
            thread.kernel.tid, fault_address,
            thread.kernel.cpu_state.frame.rip, thread.kernel.cpu_state.frame.cs,
            thread.kernel.cpu_state.frame.rsp, thread.kernel.cpu_state.frame.ss,
            thread.kernel.cpu_state.frame.rflags,
            thread.kernel.cpu_state.rax, thread.kernel.cpu_state.rbx, thread.kernel.cpu_state.rcx);

        if current_tid == thread.kernel.tid as usize {
            crate::kernel::startup::arch_user_clean();
            thread.kernel.state = ThreadState::Zombie;
            thread.kernel.exit_code = -11;
            thread.kernel.symbols = None;
            Some(schedule(current_tid).unwrap_or(0))
        } else {
            thread.kernel.state = ThreadState::Zombie;
            None
        }
    }
}

/// Initialize threading system with init thread
#[allow(static_mut_refs)]
pub fn init_threading() {
    unsafe {
        // Allocate thread table on the heap
        THREADS.reserve(MAX_THREADS);
        for _ in 0..MAX_THREADS {
            THREADS.push(Thread::empty());
        }

        // Thread 0 is the init/idle thread (uses boot page directory)
        THREADS[0].kernel.tid = 0;
        THREADS[0].kernel.pid = 0;
        THREADS[0].kernel.priority = 0;
        THREADS[0].kernel.parent_tid = -1;
        THREADS[0].kernel.state = ThreadState::Running;
        // root stays empty — idle thread doesn't use user pages
    }
}
