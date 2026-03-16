//! Thread and process management
//!
//! Thread states: Unused, Running, Ready, Blocked, Zombie
//! TID 0 is the idle/init thread (never scheduled away from if no other threads)

use crate::descriptors::{set_kernel_stack, USER_CS, USER_CS64, USER_DS};
use crate::stacktrace::SymbolData;
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

use crate::{Frame, Frame32, Frame64};

/// CPU state saved during context switch (matches Regs layout exactly)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CpuState {
    // Segment registers
    pub gs: u64,
    pub fs: u64,
    pub es: u64,
    pub ds: u64,
    // x86-64 extended registers
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    // General purpose registers
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rsp_dummy: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    // Interrupt info (zero-extended to 64-bit)
    pub int_num: u64,
    pub err_code: u64,
    // CPU-pushed interrupt frame (union, use f32 for 32-bit mode)
    pub frame: Frame,
}

impl CpuState {
    pub const fn empty() -> Self {
        CpuState {
            gs: 0,
            fs: 0,
            es: 0,
            ds: 0,
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rdi: 0,
            rsi: 0,
            rbp: 0,
            rsp_dummy: 0,
            rbx: 0,
            rdx: 0,
            rcx: 0,
            rax: 0,
            int_num: 0,
            err_code: 0,
            frame: Frame { f32: Frame32 { _pad: [0; 5], eip: 0, cs: 0, eflags: 0, esp: 0, ss: 0 } },
        }
    }

    /// Initialize for a 32-bit user process
    pub fn init_user_process(&mut self, entry: u32, stack: u32) {
        let ds = USER_DS as u64;
        let cs32 = USER_CS as u32;
        const IF_FLAG: u32 = 1 << 9; // Interrupt enable flag

        self.gs = ds;
        self.fs = ds;
        self.es = ds;
        self.ds = ds;
        self.r15 = 0;
        self.r14 = 0;
        self.r13 = 0;
        self.r12 = 0;
        self.r11 = 0;
        self.r10 = 0;
        self.r9 = 0;
        self.r8 = 0;
        self.rdi = 0;
        self.rsi = 0;
        self.rbp = 0;
        self.rsp_dummy = 0;
        self.rbx = 0;
        self.rdx = 0;
        self.rcx = 0;
        self.rax = 0;
        self.int_num = 0;
        self.err_code = 0;
        self.frame = Frame {
            f32: Frame32 {
                _pad: [0; 5],
                eip: entry,
                cs: cs32,
                eflags: IF_FLAG,
                esp: stack,
                ss: USER_DS as u32,
            }
        };
    }

    /// Initialize for a 64-bit user process
    pub fn init_user_process_64(&mut self, entry: u64, stack: u64) {
        let ds = USER_DS as u64;
        const IF_FLAG: u64 = 1 << 9;

        self.gs = ds;
        self.fs = ds;
        self.es = ds;
        self.ds = ds;
        self.r15 = 0;
        self.r14 = 0;
        self.r13 = 0;
        self.r12 = 0;
        self.r11 = 0;
        self.r10 = 0;
        self.r9 = 0;
        self.r8 = 0;
        self.rdi = 0;
        self.rsi = 0;
        self.rbp = 0;
        self.rsp_dummy = 0;
        self.rbx = 0;
        self.rdx = 0;
        self.rcx = 0;
        self.rax = 0;
        self.int_num = 0;
        self.err_code = 0;
        self.frame = Frame {
            f64: Frame64 {
                rip: entry,
                cs: USER_CS64 as u64,
                rflags: IF_FLAG,
                rsp: stack,
                ss: USER_DS as u64,
            }
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
    pub root: crate::paging2::RootPageTable,  // Root page table (union: u32 phys or [u64; 4] pdpt)
    pub num_fds: i32,
    pub fds: [i32; MAX_FDS],
    pub cpu_state: CpuState,
    pub exit_code: i32,
    pub is_64bit: bool,               // True if running in 64-bit (long) mode
    pub symbols: Option<SymbolData>,  // Debug symbols for userspace ELF
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
            root: crate::paging2::RootPageTable::empty(),
            num_fds: 0,
            fds: [-1; MAX_FDS],
            cpu_state: CpuState::empty(),
            exit_code: 0,
            is_64bit: false,
            symbols: None,
        }
    }
}

/// Thread array (heap-allocated to keep large RootPageTable out of .data)
static mut THREADS: alloc::vec::Vec<Thread> = alloc::vec::Vec::new();

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

/// Create a new thread.
/// `forked_root_page`: physical page number of the forked root page table
/// (from fork_current), or 0 to use the current address space.
pub fn create_thread(parent: Option<&Thread>, forked_root_page: u64, is_process: bool) -> Option<&'static mut Thread> {
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
                if forked_root_page == 0 {
                    thread.root.init_current();
                } else {
                    thread.root.init_fork(forked_root_page);
                }
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

/// Initialize a thread as a 32-bit user process
pub fn init_process_thread(thread: &mut Thread, entry: u32, stack: u32) {
    thread.is_64bit = false;
    thread.cpu_state.init_user_process(entry, stack);
}

/// Initialize a thread as a 64-bit user process
pub fn init_process_thread_64(thread: &mut Thread, entry: u64, stack: u64) {
    thread.is_64bit = true;
    thread.cpu_state.init_user_process_64(entry, stack);
}

/// Save current CPU state to thread
pub fn save_state(thread: &mut Thread) {
    unsafe {
        let stack_top = (&raw const KERNEL_STACK).cast::<u8>().add(128 * 1024) as usize;
        let regs = (stack_top - core::mem::size_of::<Regs>()) as *const Regs;
        let saved_eip = (*regs).frame.f32.eip;
        println!("save_state: tid={} rax={} eip={:#x}", thread.tid, (*regs).rax, saved_eip);
        // Copy Regs to CpuState (same layout)
        core::ptr::copy_nonoverlapping(
            regs as *const u8,
            &mut thread.cpu_state as *mut CpuState as *mut u8,
            core::mem::size_of::<CpuState>(),
        );
    }
}

/// Set return value in thread's saved state
pub fn set_return(thread: &mut Thread, ret: i32) {
    thread.cpu_state.rax = ret as i64 as u64;  // Sign-extend for 32-bit, zero-extend to 64
}

/// Schedule next thread (randomly selected from ready threads)
pub fn schedule() {
    unsafe {
        const A: u64 = 0xdead_beed;
        const C: u64 = 0x1234_5679;
        SEED = A.wrapping_mul(SEED).wrapping_add(C);

        let current_tid = if !CURRENT_THREAD.is_null() { (*CURRENT_THREAD).tid } else { -1 };

        let mut next_thread: *mut Thread = core::ptr::null_mut();
        let mut count = 0u64;

        for i in 1..MAX_THREADS {
            if i as i32 == current_tid {
                continue;
            }
            if THREADS[i].state == ThreadState::Ready {
                count += 1;
                if SEED % count == 0 {
                    next_thread = &mut THREADS[i];
                }
            }
        }

        if next_thread.is_null() {
            // No other threads ready — stay with current
            return;
        }

        exit_to_thread(&mut *next_thread);
    }
}

/// Switch to a thread (does not return for calling thread)
pub fn exit_to_thread(thread: &mut Thread) -> ! {
    unsafe {
        thread.state = ThreadState::Running;

        // Save outgoing thread's user entries
        if !CURRENT_THREAD.is_null() {
            (*CURRENT_THREAD).root.save();
        }

        let in_long_mode = crate::paging2::cpu_mode() == crate::paging2::CpuMode::Compat;
        let want_long_mode = thread.is_64bit;

        // Switch address space: load incoming thread's entries + CPU mode
        if want_long_mode != in_long_mode {
            thread.root.load_entries();
            // Sync HW_PDPT for both toggle directions:
            //   PAE→Compat: hardware still reads HW_PDPT for recursive mapping + trampoline
            //   Compat→PAE: new CR3 will point to HW_PDPT after toggle
            crate::paging2::sync_hw_pdpt();
            // Flush TLB so new entries take effect before mapping trampoline
            crate::x86::flush_tlb();
            crate::paging2::ensure_trampoline_mapped();
            crate::descriptors::toggle_mode(crate::paging2::toggle_cr3(want_long_mode));
        } else {
            thread.root.activate();
        }

        // Update kernel stack in TSS for this thread
        let stack_top = (&raw const KERNEL_STACK).cast::<u8>().add(128 * 1024);
        if thread.is_64bit {
            crate::descriptors::set_kernel_stack_64(stack_top as u64);
        } else {
            set_kernel_stack(stack_top as u32);
        }

        CURRENT_THREAD = thread;

        let ip = if thread.is_64bit {
            unsafe { thread.cpu_state.frame.f64.rip }
        } else {
            unsafe { thread.cpu_state.frame.f32.eip as u64 }
        };

        // Debug: read code bytes at ip and stack at esp to verify mapping
        let code = unsafe { core::ptr::read_unaligned(ip as *const u32) };
        let user_esp = if thread.is_64bit {
            unsafe { thread.cpu_state.frame.f64.rsp }
        } else {
            unsafe { thread.cpu_state.frame.f32.esp as u64 }
        };
        let stack_val = unsafe { core::ptr::read_unaligned(user_esp as *const u32) };
        println!("exit_to_thread: tid={} rax={} ip={:#x} code={:#010x} esp={:#x} [esp]={:#x}",
            thread.tid, thread.cpu_state.rax, ip, code, user_esp, stack_val);

        // Exit to user mode via iret
        exit_kernel(&thread.cpu_state, thread.is_64bit as u32);
    }
}

// Exit kernel and return to user mode
// Implemented in entry.asm
unsafe extern "C" {
    fn exit_kernel(cpu_state: *const CpuState, is_64bit: u32) -> !;
}

/// Exit current thread and schedule next
pub fn exit_thread(exit_code: i32) -> ! {
    unsafe {
        let thread = &mut *CURRENT_THREAD;
        println!("Thread {} exited with code {}", thread.tid, exit_code);
        crate::paging2::free_user_pages();
        thread.exit_code = exit_code;
        thread.state = ThreadState::Zombie;
        CURRENT_THREAD = core::ptr::null_mut();
        schedule();
    }
    panic!("No threads to schedule after exit");
}

/// Wait for a child to exit. Returns (child_tid, exit_code) or -ECHILD if no children.
/// If pid == -1, waits for any child. Otherwise waits for specific pid.
/// Non-blocking: returns -EAGAIN if children exist but none have exited yet.
pub fn waitpid(pid: i32) -> (i32, i32) {
    unsafe {
        let current_tid = if !CURRENT_THREAD.is_null() { (*CURRENT_THREAD).tid } else { return (-10, 0); };
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
                thread.state = ThreadState::Zombie;
                thread.exit_code = -11;  // SIGSEGV
                CURRENT_THREAD = core::ptr::null_mut();
                schedule();
            } else {
                thread.state = ThreadState::Zombie;
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

        // Thread 0 is the init/idle thread (uses current page directory)
        THREADS[0].tid = 0;
        THREADS[0].pid = 0;
        THREADS[0].priority = 0;
        THREADS[0].parent_tid = -1;
        THREADS[0].state = ThreadState::Running;
        THREADS[0].root.init_current();
        THREADS[0].root.activate();
        CURRENT_THREAD = &mut THREADS[0];
    }
}

