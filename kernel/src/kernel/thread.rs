//! Thread and process management
//!
//! Thread states: Unused, Running, Ready, Blocked, Zombie
//! TID 0 is the idle/init thread (never scheduled away from if no other threads)

use crate::arch::descriptors::{USER_CS, USER_CS64, USER_DS};
use crate::kernel::stacktrace::SymbolData;
use crate::println;
use crate::{Frame64, Regs};

/// Maximum number of threads
pub const MAX_THREADS: usize = 1024;

/// Maximum file descriptors per thread
const MAX_FDS: usize = 16;

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
        self.gs = ds;
        self.fs = ds;
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

/// Thread control block
pub struct Thread {
    pub tid: i32,
    pub pid: i32,
    pub priority: i32,
    pub parent_tid: i32,
    pub state: ThreadState,
    pub time: u32,
    pub root: crate::RootPageTable,  // Root page table (union: u32 phys or [u64; 4] pdpt)
    pub num_fds: i32,
    pub fds: [i32; MAX_FDS],
    pub cpu_state: Regs,
    pub exit_code: i32,
    pub symbols: Option<SymbolData>,  // Debug symbols for userspace ELF
    pub vm86: crate::kernel::vm86::Vm86State,
    pub cwd: [u8; 64],     // Current working directory (e.g. "WOLF3D/", "" for root)
    pub cwd_len: usize,
}

impl Thread {
    pub fn empty() -> Self {
        Thread {
            tid: 0,
            pid: 0,
            priority: 0,
            parent_tid: -1,
            state: ThreadState::Unused,
            time: 0,
            root: crate::RootPageTable::empty(),
            num_fds: 0,
            fds: [-1; MAX_FDS],
            cpu_state: Regs::empty(),
            exit_code: 0,
            symbols: None,
            vm86: crate::kernel::vm86::Vm86State::new(),
            cwd: [0; 64],
            cwd_len: 0,
        }
    }

    /// Get current working directory as a byte slice
    pub fn cwd_str(&self) -> &[u8] {
        &self.cwd[..self.cwd_len]
    }

    /// Set current working directory. Path should end with '/' or be empty for root.
    pub fn set_cwd(&mut self, path: &[u8]) {
        let len = path.len().min(self.cwd.len());
        self.cwd[..len].copy_from_slice(&path[..len]);
        self.cwd_len = len;
    }
}

/// Thread array (heap-allocated to keep large RootPageTable out of .data)
static mut THREADS: alloc::vec::Vec<Thread> = alloc::vec::Vec::new();

/// Current running thread index (0 = idle/init, always valid after init)
static mut CURRENT_THREAD: usize = 0;

/// PRNG state for random scheduling
static mut SEED: u64 = 0xcafe_babe_dead_beef;

/// Check if threading system is initialized
pub fn is_initialized() -> bool {
    unsafe { (*(&raw const THREADS)).len() > 0 }
}

/// Get current thread (always valid — TID 0 is idle/init)
pub fn current() -> &'static mut Thread {
    unsafe { &mut THREADS[CURRENT_THREAD] }
}

/// Get thread by TID
pub fn get_thread(tid: usize) -> Option<&'static mut Thread> {
    if tid >= MAX_THREADS {
        return None;
    }
    unsafe {
        let thread = &mut THREADS[tid];
        if thread.state != ThreadState::Unused {
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
pub fn create_thread(parent: Option<&Thread>, root: crate::RootPageTable, is_process: bool) -> Option<&'static mut Thread> {
    unsafe {
        for i in 0..MAX_THREADS {
            if THREADS[i].state == ThreadState::Unused {
                let thread = &mut THREADS[i];
                thread.tid = i as i32;
                thread.pid = if is_process {
                    i as i32
                } else {
                    parent.map(|p| p.pid).unwrap_or(0)
                };
                thread.priority = parent.map(|p| p.priority).unwrap_or(0);
                thread.parent_tid = parent.map(|p| p.tid).unwrap_or(-1);
                thread.state = ThreadState::Ready;
                thread.time = crate::arch::irq::get_ticks() as u32;
                thread.root = root;
                thread.num_fds = 0;
                for fd in &mut thread.fds {
                    *fd = -1;
                }
                thread.cpu_state = Regs::empty();
                return Some(thread);
            }
        }
        None
    }
}

/// Initialize a thread as a 32-bit user process
pub fn init_process_thread(thread: &mut Thread, entry: u32, stack: u32) {
    thread.cpu_state.init_user_process(entry, stack);
}

/// Initialize a thread as a 64-bit user process
pub fn init_process_thread_64(thread: &mut Thread, entry: u64, stack: u64) {
    thread.cpu_state.init_user_process_64(entry, stack);
}

/// Initialize a thread for VM86 mode (.COM execution)
/// cs/ip/ss/sp are real-mode segment:offset values
pub fn init_process_thread_vm86(thread: &mut Thread, cs: u16, ip: u16, ss: u16, sp: u16) {
    thread.vm86 = crate::kernel::vm86::Vm86State::new();

    const VM_FLAG: u32 = 1 << 17;  // VM86 mode
    const IF_FLAG: u32 = 1 << 9;   // Interrupt enable
    const VIF_FLAG: u32 = 1 << 19; // Virtual interrupts enabled by default (hardware VIF)

    let state = &mut thread.cpu_state;
    *state = Regs::empty();

    // DS=ES=PSP segment for DOS programs, FS=GS=0
    // For .COM: PSP = CS. For .EXE: PSP = CS - 0x10 (PSP precedes load module).
    // Caller passes the load segment as CS; the PSP is always COM_SEGMENT.
    state.ds = crate::kernel::vm86::COM_SEGMENT as u64;
    state.es = crate::kernel::vm86::COM_SEGMENT as u64;
    state.fs = 0;
    state.gs = 0;

    state.frame = Frame64 {
        rip: ip as u64,
        cs: cs as u64,
        rflags: (VM_FLAG | IF_FLAG | VIF_FLAG) as u64,
        rsp: sp as u64,
        ss: ss as u64,
    };
}

/// Save CPU state to thread.
pub fn save_state(thread: &mut Thread, regs: &Regs) {
    thread.cpu_state = *regs;
}

/// Set return value in thread's saved state
pub fn set_return(thread: &mut Thread, ret: i32) {
    thread.cpu_state.rax = ret as i64 as u64;  // Sign-extend for 32-bit, zero-extend to 64
}

/// Schedule next thread (randomly selected from ready threads).
/// Returns Some(idx) if a switch is needed, None to stay with current.
pub fn schedule() -> Option<usize> {
    unsafe {
        const A: u64 = 0xdead_beed;
        const C: u64 = 0x1234_5679;
        SEED = A.wrapping_mul(SEED).wrapping_add(C);

        let current_tid = CURRENT_THREAD;

        let mut next_idx: usize = usize::MAX;
        let mut count = 0u64;

        for i in 1..MAX_THREADS {
            if i == current_tid {
                continue;
            }
            if THREADS[i].state == ThreadState::Ready {
                count += 1;
                if SEED % count == 0 {
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

/// Get the current thread index
pub fn current_idx() -> usize {
    unsafe { CURRENT_THREAD }
}

/// Set the current thread index (called by event loop before executing)
pub fn set_current(tid: usize) {
    unsafe { CURRENT_THREAD = tid; }
}

/// Exit current thread and schedule next.
/// Returns the TID of the next thread to run (falls back to thread 0/idle).
pub fn exit_thread(exit_code: i32) -> usize {
    unsafe {
        let thread = &mut THREADS[CURRENT_THREAD];
        let parent_tid = thread.parent_tid;
        crate::kernel::vfs::close_all_fds(&mut thread.fds);
        if let Some(ref mut ems) = thread.vm86.ems {
            ems.free_all_pages();
        }
        thread.vm86.ems = None;
        thread.vm86.xms = None;
        if thread.cpu_state.mode() == crate::UserMode::VM86 && !thread.vm86.a20_enabled {
            crate::kernel::startup::arch_set_a20(true, &mut thread.vm86.hma_pages);
            thread.vm86.a20_enabled = true;
        }
        
        // Use arch primitive instead of direct paging call
        crate::kernel::startup::arch_user_clean();

        thread.exit_code = exit_code;
        thread.state = ThreadState::Zombie;
        // Symbols are dropped here by RAII when thread goes zombie
        thread.symbols = None;

        // Wake blocked parent (e.g., waiting for EXEC'd child to finish)
        if parent_tid >= 0 && (parent_tid as usize) < MAX_THREADS {
            let parent = &mut THREADS[parent_tid as usize];
            if parent.state == ThreadState::Blocked {
                parent.state = ThreadState::Ready;
            }
        }

        CURRENT_THREAD = 0;
        schedule().unwrap_or(0)
    }
}

/// Wait for a child to exit. Returns (child_tid, exit_code) or -ECHILD if no children.
/// If pid == -1, waits for any child. Otherwise waits for specific pid.
/// Non-blocking: returns -EAGAIN if children exist but none have exited yet.
pub fn waitpid(pid: i32) -> (i32, i32) {
    unsafe {
        let current_tid = THREADS[CURRENT_THREAD].tid;
        let mut has_children = false;

        for i in 1..MAX_THREADS {
            let t = &mut THREADS[i];
            if t.parent_tid == current_tid && t.state != ThreadState::Unused {
                has_children = true;
                if t.state == ThreadState::Zombie && (pid == -1 || t.tid == pid) {
                    let tid = t.tid;
                    let code = t.exit_code;
                    t.state = ThreadState::Unused;
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
pub fn signal_thread(thread: &mut Thread, fault_address: usize) -> Option<usize> {
    if thread.pid == 0 {
        // Kernel thread - panic
        println!("\x1b[91mSEGV in init at {:#x}\x1b[0m", fault_address);
        loop { core::hint::spin_loop(); }
    } else {
        println!("SEGV in thread {} at {:#x}", thread.tid, fault_address);

        unsafe {
            if CURRENT_THREAD == thread.tid as usize {
                crate::kernel::startup::arch_user_clean();
                thread.state = ThreadState::Zombie;
                thread.exit_code = -11;  // SIGSEGV
                thread.symbols = None;
                CURRENT_THREAD = 0;
                Some(schedule().unwrap_or(0))
            } else {
                // Not current thread — can't free pages here (wrong address space)
                thread.state = ThreadState::Zombie;
                None
            }
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
        THREADS[0].tid = 0;
        THREADS[0].pid = 0;
        THREADS[0].priority = 0;
        THREADS[0].parent_tid = -1;
        THREADS[0].state = ThreadState::Running;
        // root stays empty — idle thread doesn't use user pages
        // CURRENT_THREAD defaults to 0, which is correct
    }
}
