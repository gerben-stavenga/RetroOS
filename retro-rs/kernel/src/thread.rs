//! Thread and process management
//!
//! Thread states: Unused, Running, Ready, Blocked, Zombie
//! TID 0 is the idle/init thread (never scheduled away from if no other threads)

use crate::descriptors::{set_kernel_stack, USER_CS, USER_CS64, USER_DS};
use crate::stacktrace::SymbolData;
use crate::{KERNEL_STACK, println};
use crate::x86;
use crate::{Frame, Frame32, Frame64, Regs};

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

/// Thread execution mode (user code bitness)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadMode {
    Mode16,  // VM86 (requires PAE CPU mode)
    Mode32,  // 32-bit protected/compat
    Mode64,  // 64-bit long mode
}

/// Saved interrupt frame format
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameFormat {
    Protected,  // Frame32 (saved in PAE/Legacy CPU mode)
    Long,       // Frame64 (saved in Compat CPU mode)
}

impl FrameFormat {
    /// Frame format used by the current CPU mode
    pub fn current() -> Self {
        if Regs::use_f64() { FrameFormat::Long } else { FrameFormat::Protected }
    }

    pub fn is_long(self) -> bool {
        self == FrameFormat::Long
    }
}

/// Initialize Regs for user processes (extends Regs with descriptor-aware methods)
impl Regs {
    /// Initialize for a 32-bit user process
    pub fn init_user_process(&mut self, entry: u32, stack: u32) {
        let ds = USER_DS as u64;
        const IF_FLAG: u64 = 1 << 9;

        *self = Self::empty();
        self.gs = ds;
        self.fs = ds;
        self.es = ds;
        self.ds = ds;
        if Self::use_f64() {
            self.frame = Frame {
                f64: Frame64 {
                    rip: entry as u64, cs: USER_CS as u64, rflags: IF_FLAG,
                    rsp: stack as u64, ss: USER_DS as u64,
                }
            };
        } else {
            self.frame = Frame {
                f32: Frame32 {
                    _pad: [0; 5],
                    eip: entry, cs: USER_CS as u32, eflags: IF_FLAG as u32,
                    esp: stack, ss: USER_DS as u32,
                }
            };
        }
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
        self.frame = Frame {
            f64: Frame64 {
                rip: entry, cs: USER_CS64 as u64, rflags: IF_FLAG,
                rsp: stack, ss: USER_DS as u64,
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
    pub cpu_state: Regs,
    pub exit_code: i32,
    pub mode: ThreadMode,              // User code bitness (16/32/64)
    pub frame_format: FrameFormat,    // Saved interrupt frame format
    pub symbols: Option<SymbolData>,  // Debug symbols for userspace ELF
    pub vm86_vif: bool,               // VM86 virtual interrupt flag
    pub vm86_a20: bool,               // VM86 A20 gate (false=wrap, true=enabled)
    pub pending_signals: u32,         // Pending signal bitmask (bits 0-15 = hardware IRQs)
    pub vpic: crate::vm86::VirtualPic,      // Virtual PIC (per-thread)
    pub vkbd: crate::vm86::VirtualKeyboard, // Virtual keyboard (per-thread)
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
            cpu_state: Regs::empty(),
            exit_code: 0,
            mode: ThreadMode::Mode32,
            frame_format: FrameFormat::Protected,
            symbols: None,
            vm86_vif: false,
            vm86_a20: false,
            pending_signals: 0,
            vpic: crate::vm86::VirtualPic::new(),
            vkbd: crate::vm86::VirtualKeyboard::new(),
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
                thread.cpu_state = Regs::empty();
                return Some(thread);
            }
        }
        None
    }
}

/// Initialize a thread as a 32-bit user process
pub fn init_process_thread(thread: &mut Thread, entry: u32, stack: u32) {
    thread.mode = ThreadMode::Mode32;
    thread.frame_format = FrameFormat::current();
    thread.cpu_state.init_user_process(entry, stack);
}

/// Initialize a thread as a 64-bit user process
pub fn init_process_thread_64(thread: &mut Thread, entry: u64, stack: u64) {
    thread.mode = ThreadMode::Mode64;
    thread.frame_format = FrameFormat::Long;  // 64-bit threads always use Frame64
    thread.cpu_state.init_user_process_64(entry, stack);
}

/// Initialize a thread for VM86 mode (.COM execution)
/// cs/ip/ss/sp are real-mode segment:offset values
pub fn init_process_thread_vm86(thread: &mut Thread, cs: u16, ip: u16, ss: u16, sp: u16) {
    thread.mode = ThreadMode::Mode16;
    thread.frame_format = FrameFormat::Protected; // VM86 always uses Frame32 (IRET in PAE mode)
    thread.vm86_vif = true;  // Virtual interrupts enabled by default
    thread.vm86_a20 = false; // A20 disabled (wrap-around) by default

    const VM_FLAG: u32 = 1 << 17;  // VM86 mode
    const IF_FLAG: u32 = 1 << 9;   // Interrupt enable

    let state = &mut thread.cpu_state;
    *state = Regs::empty();

    // DS=ES=CS for .COM programs, FS=GS=0
    state.ds = cs as u64;
    state.es = cs as u64;
    state.fs = 0;
    state.gs = 0;

    // Set up Frame32 with VM86 flags — CPU interprets CS/SS as real-mode segments when VM=1
    state.frame = Frame {
        f32: Frame32 {
            _pad: [0; 5],
            eip: ip as u32,
            cs: cs as u32,
            eflags: VM_FLAG | IF_FLAG,
            esp: sp as u32,
            ss: ss as u32,
        }
    };
}

/// Save current CPU state to thread from the given Regs pointer.
/// For VM86 threads, the real-mode segments are already in regs.ds/es/fs/gs
/// (swapped in by isr_handler on entry), so they copy naturally into Regs.
pub fn save_state(thread: &mut Thread, regs: &Regs) {
    // Record frame format at save time (VM86 threads always use Protected)
    if thread.mode == ThreadMode::Mode16 {
        thread.frame_format = FrameFormat::Protected;
    } else {
        thread.frame_format = FrameFormat::current();
    }
    thread.cpu_state = *regs;
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
    thread.state = ThreadState::Running;

    // Save outgoing thread's user entries
    unsafe {
        if !CURRENT_THREAD.is_null() {
            (*CURRENT_THREAD).root.save();
        }
    }

    // Toggle CPU mode (PAE ↔ Compat) if needed.
    // Compat→PAE for VM86 (Mode16), PAE→Compat for 64-bit (Mode64).
    // Mode32 works in both modes — no toggle needed.
    let need_toggle = match crate::paging2::cpu_mode() {
        crate::paging2::CpuMode::Pae => thread.mode == ThreadMode::Mode64,
        crate::paging2::CpuMode::Compat => thread.mode == ThreadMode::Mode16,
        _ => false,
    };

    if need_toggle {
        thread.root.load_entries();
        crate::paging2::sync_hw_pdpt();
        crate::x86::flush_tlb();
        crate::paging2::ensure_trampoline_mapped();
        crate::descriptors::toggle_mode(crate::paging2::toggle_cr3(thread.mode == ThreadMode::Mode64));
    } else {
        thread.root.activate();
    }

    // Update kernel stack in TSS
    let stack_top = unsafe { (&raw const KERNEL_STACK).cast::<u8>().add(128 * 1024) };
    if thread.mode == ThreadMode::Mode64 || Regs::use_f64() {
        crate::descriptors::set_kernel_stack_64(stack_top as u64);
    } else {
        set_kernel_stack(stack_top as u32);
    }

    unsafe { CURRENT_THREAD = thread; }

    // Deliver pending signals before entering userspace
    if thread.mode == ThreadMode::Mode16 {
        crate::vm86::deliver_pending_signals(thread);
    }

    // Local exit frame: Regs + 4 extra u32 segments for VM86 IRET.
    // For non-VM86, the extra fields sit harmlessly past the iret frame.
    #[repr(C)]
    struct ExitFrame {
        regs: Regs,
        vm86_es: u32,
        vm86_ds: u32,
        vm86_fs: u32,
        vm86_gs: u32,
    }

    let mut frame = ExitFrame {
        regs: thread.cpu_state,
        vm86_es: 0,
        vm86_ds: 0,
        vm86_fs: 0,
        vm86_gs: 0,
    };

    let is_long;

    if thread.mode == ThreadMode::Mode16 {
        // VM86: move real-mode segments to extra area, zero regs fields
        // so exit_interrupt_32 loads null (safe); IRET pops real values from extra area
        frame.vm86_es = frame.regs.es as u32;
        frame.vm86_ds = frame.regs.ds as u32;
        frame.vm86_fs = frame.regs.fs as u32;
        frame.vm86_gs = frame.regs.gs as u32;
        frame.regs.ds = 0;
        frame.regs.es = 0;
        frame.regs.fs = 0;
        frame.regs.gs = 0;
        is_long = false;
    } else {
        // Convert frame format if it doesn't match current CPU mode
        let need = FrameFormat::current();
        if thread.frame_format != need {
            if need.is_long() {
                frame.regs.frame_to_64();
            } else {
                frame.regs.frame_to_32();
            }
            thread.frame_format = need;
        }
        is_long = thread.frame_format.is_long();
    }

    unsafe { exit_kernel(&frame.regs, is_long as u32) }
}

// Exit kernel and return to user mode
// Implemented in entry.asm
unsafe extern "C" {
    fn exit_kernel(cpu_state: *const Regs, use_long_frame: u32) -> !;
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

