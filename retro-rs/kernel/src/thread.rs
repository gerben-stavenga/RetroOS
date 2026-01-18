//! Thread and process management
//!
//! Thread states: Unused, Running, Ready, Blocked, Zombie
//! TID 0 is the idle/init thread (never scheduled away from if no other threads)

use crate::descriptors::{set_kernel_stack, USER_CS, USER_DS};
use crate::paging2::KERNEL_BASE;
use crate::{KERNEL_STACK, println};
use crate::x86;
use crate::Regs;

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

/// CPU state saved during context switch (matches Regs layout)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CpuState {
    pub gs: u32,
    pub fs: u32,
    pub es: u32,
    pub ds: u32,
    pub edi: u32,
    pub esi: u32,
    pub ebp: u32,
    pub esp_dummy: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,
    pub int_num: u32,
    pub err_code: u32,
    pub eip: u32,
    pub cs: u32,
    pub eflags: u32,
    pub user_esp: u32,
    pub user_ss: u32,
}

impl CpuState {
    pub const fn empty() -> Self {
        CpuState {
            gs: 0,
            fs: 0,
            es: 0,
            ds: 0,
            edi: 0,
            esi: 0,
            ebp: 0,
            esp_dummy: 0,
            ebx: 0,
            edx: 0,
            ecx: 0,
            eax: 0,
            int_num: 0,
            err_code: 0,
            eip: 0,
            cs: 0,
            eflags: 0,
            user_esp: 0,
            user_ss: 0,
        }
    }

    /// Initialize for a user process
    pub fn init_user_process(&mut self, entry: u32, stack: u32) {
        let ds = USER_DS as u32;
        let cs = USER_CS as u32;
        const IF_FLAG: u32 = 1 << 9; // Interrupt enable flag

        self.gs = ds;
        self.fs = ds;
        self.es = ds;
        self.ds = ds;
        self.edi = 0;
        self.esi = 0;
        self.ebp = 0;
        self.esp_dummy = 0;
        self.ebx = 0;
        self.edx = 0;
        self.ecx = 0;
        self.eax = 0;
        self.int_num = 0;
        self.err_code = 0;
        self.eip = entry;
        self.cs = cs;
        self.eflags = IF_FLAG;
        self.user_esp = stack;
        self.user_ss = ds;
    }
}

/// Thread control block
#[repr(C)]
pub struct Thread {
    pub tid: i32,
    pub pid: i32,
    pub priority: i32,
    pub parent_tid: i32,
    pub state: ThreadState,
    pub time: u32,
    pub page_dir: u32,  // Physical address of page directory
    pub num_fds: i32,
    pub fds: [i32; MAX_FDS],
    pub cpu_state: CpuState,
}

impl Thread {
    pub const fn empty() -> Self {
        Thread {
            tid: 0,
            pid: 0,
            priority: 0,
            parent_tid: -1,
            state: ThreadState::Unused,
            time: 0,
            page_dir: 0,
            num_fds: 0,
            fds: [-1; MAX_FDS],
            cpu_state: CpuState::empty(),
        }
    }
}

/// Thread array
static mut THREADS: [Thread; MAX_THREADS] = {
    const EMPTY: Thread = Thread::empty();
    [EMPTY; MAX_THREADS]
};

/// Current running thread
static mut CURRENT_THREAD: *mut Thread = core::ptr::null_mut();

/// PRNG state for random scheduling
static mut SEED: u64 = 0xcafe_babe_dead_beef;

/// Get current thread
pub fn current() -> Option<&'static mut Thread> {
    unsafe {
        if CURRENT_THREAD.is_null() {
            None
        } else {
            Some(&mut *CURRENT_THREAD)
        }
    }
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

/// Create a new thread
pub fn create_thread(parent: Option<&Thread>, page_dir: u32, is_process: bool) -> Option<&'static mut Thread> {
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
                thread.time = crate::irq::get_ticks() as u32;
                thread.page_dir = page_dir;
                thread.num_fds = 0;
                for fd in &mut thread.fds {
                    *fd = -1;
                }
                thread.cpu_state = CpuState::empty();
                return Some(thread);
            }
        }
        None
    }
}

/// Initialize a thread as a user process
pub fn init_process_thread(thread: &mut Thread, entry: u32) {
    thread.cpu_state.init_user_process(entry, KERNEL_BASE as u32);
}

/// Save current CPU state to thread
pub fn save_state(thread: &mut Thread) {
    unsafe {
        let stack_top = (&raw const KERNEL_STACK).cast::<u8>().add(128 * 1024) as usize;
        let regs = (stack_top - core::mem::size_of::<Regs>()) as *const Regs;
        // Copy Regs to CpuState (same layout)
        core::ptr::copy_nonoverlapping(
            regs as *const u8,
            &mut thread.cpu_state as *mut CpuState as *mut u8,
            core::mem::size_of::<CpuState>(),
        );
    }
}

/// Set return value in thread's saved state
pub fn set_return(thread: &mut Thread, ret: u32) {
    thread.cpu_state.eax = ret;
}

/// Schedule next thread
/// tid: current thread's TID to exclude
/// must_switch: if true, must switch even if no other threads (go to idle)
pub fn schedule(tid: i32, must_switch: bool) {
    unsafe {
        const A: u64 = 0xdead_beed;
        const C: u64 = 0x1234_5679;
        SEED = A.wrapping_mul(SEED).wrapping_add(C);

        let mut next_thread: *mut Thread = core::ptr::null_mut();
        let mut count = 0u64;

        // Skip thread 0 (idle) in normal scheduling
        for i in 1..MAX_THREADS {
            if i as i32 == tid {
                continue;
            }
            if THREADS[i].state == ThreadState::Ready {
                count += 1;
                // Reservoir sampling for random selection
                if SEED % count == 0 {
                    next_thread = &mut THREADS[i];
                }
            }
        }

        if next_thread.is_null() {
            if !must_switch || (!CURRENT_THREAD.is_null() && (*CURRENT_THREAD).tid == 0) {
                // Stay with current thread or already in idle
                return;
            }
            // Go to idle thread
            next_thread = &mut THREADS[0];
        }

        println!("Schedule -> tid {}", (*next_thread).tid);

        exit_to_thread(&mut *next_thread);
    }
}

/// Switch to a thread (does not return for calling thread)
pub fn exit_to_thread(thread: &mut Thread) -> ! {
    unsafe {
        thread.state = ThreadState::Running;

        // Switch page directory
        if thread.page_dir != 0 {
            x86::write_cr3(thread.page_dir);
        }

        // Update kernel stack in TSS for this thread
        let stack_top = (&raw const KERNEL_STACK).cast::<u8>().add(128 * 1024) as u32;
        set_kernel_stack(stack_top);

        CURRENT_THREAD = thread;

        // Exit to user mode via iret
        exit_kernel(&thread.cpu_state);
    }
}

// Exit kernel and return to user mode
// Implemented in entry.asm
unsafe extern "C" {
    fn exit_kernel(cpu_state: *const CpuState) -> !;
}

/// Mark current thread as zombie and schedule away
pub fn exit_thread(exit_code: i32) -> ! {
    unsafe {
        if !CURRENT_THREAD.is_null() {
            let thread = &mut *CURRENT_THREAD;
            thread.state = ThreadState::Unused;
            // TODO: Wake parent if waiting
            println!("Thread {} exited with code {}", thread.tid, exit_code);
        }
        schedule(-1, true);
    }
    // schedule with must_switch should never return
    loop {
        x86::cli();
        x86::hlt();
    }
}

/// Signal thread (e.g., on segfault)
pub fn signal_thread(thread: &mut Thread, fault_address: usize) {
    if thread.pid == 0 {
        // Kernel thread - panic
        println!("\x1b[91mSEGV in init at {:#x}\x1b[0m", fault_address);
        loop {
            x86::cli();
            x86::hlt();
        }
    } else {
        println!("SEGV in thread {} at {:#x}", thread.tid, fault_address);

        unsafe {
            if CURRENT_THREAD == thread as *mut _ {
                thread.state = ThreadState::Unused;
                schedule(thread.tid, true);
            } else {
                thread.state = ThreadState::Zombie;
            }
        }
    }
}

/// Initialize threading system with init thread
pub fn init_threading() {
    unsafe {
        // Thread 0 is the init/idle thread (uses current page directory)
        THREADS[0].tid = 0;
        THREADS[0].pid = 0;
        THREADS[0].priority = 0;
        THREADS[0].parent_tid = -1;
        THREADS[0].state = ThreadState::Running;
        THREADS[0].page_dir = x86::read_cr3();
        CURRENT_THREAD = &mut THREADS[0];
    }
}
