//! System call implementations
//!
//! Syscall numbers (via INT 0x80):
//! - 0: Exit
//! - 1: Yield
//! - 4: Fork
//! - 5: Exec
//! - 6: Open
//! - 7: Waitpid
//! - 8: Read
//! - 9: Write
//!
//! Arguments passed in: EDX, ECX, EBX, ESI, EDI
//! 64-bit ABI: RDI, RSI, RDX, R10, R8 (remapped to canonical layout)
//! Return value in: EAX

use crate::elf;
use crate::descriptors;
use crate::paging2::{self, PAGE_SIZE};
use crate::stacktrace::SymbolData;
use crate::startup;
use crate::thread;
use crate::vga;
use crate::Regs;
use crate::{print, println};

/// Error: function not implemented
const ENOSYS: i32 = -38;

/// Error: no memory
const ENOMEM: i32 = -12;

/// Error: no such file
const ENOENT: i32 = -2;

/// Error: exec format error
const ENOEXEC: i32 = -8;

/// Syscall handler type
type SyscallFn = fn(&mut Regs) -> i32;

/// Syscall table
const SYSCALL_TABLE: [Option<SyscallFn>; 10] = [
    Some(sys_exit),   // 0
    Some(sys_yield),  // 1
    None,             // 2
    None,             // 3
    Some(sys_fork),   // 4
    Some(sys_exec),   // 5
    Some(sys_open),   // 6
    Some(sys_wait),   // 7
    Some(sys_read),   // 8
    Some(sys_write),  // 9
];

/// Dispatch a syscall
pub fn dispatch(regs: &mut Regs) {
    // 64-bit syscall ABI uses different registers: rdi=arg0, rsi=arg1, rdx=arg2, r10=arg3, r8=arg4
    // Remap to the canonical layout (rdx=arg0, rcx=arg1, rbx=arg2, rsi=arg3, rdi=arg4)
    // so handlers don't need to know which mode the caller is in.
    let is_64bit = thread::current().map_or(false, |t| t.is_64bit);
    if is_64bit {
        let (a0, a1, a2, a3, a4) = (regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8);
        regs.rdx = a0;
        regs.rcx = a1;
        regs.rbx = a2;
        regs.rsi = a3;
        regs.rdi = a4;
    }

    let syscall_num = regs.rax as usize;

    let result = if syscall_num < SYSCALL_TABLE.len() {
        if let Some(handler) = SYSCALL_TABLE[syscall_num] {
            handler(regs)
        } else {
            ENOSYS
        }
    } else {
        ENOSYS
    };

    regs.rax = result as u32 as u64;

    if syscall_num == 4 {
        println!("dispatch fork: result={} regs.rax={}", result, regs.rax);
    }
}

/// Exit syscall (0)
/// Terminates the current process
fn sys_exit(regs: &mut Regs) -> i32 {
    let exit_code = regs.rdx as i32;
    thread::exit_thread(exit_code);
}

/// Yield syscall (1)
/// Yields CPU to another thread
fn sys_yield(_regs: &mut Regs) -> i32 {
    // Save current state and schedule another thread
    if let Some(current) = thread::current() {
        thread::save_state(current);
        current.state = thread::ThreadState::Ready;
        thread::schedule();
    }
    0
}

/// Fork syscall (4)
/// Creates a copy of the current process
fn sys_fork(_regs: &mut Regs) -> i32 {
    // Fork the address space
    let new_page_dir = match paging2::fork_current() {
        Some(pd) => pd,
        None => return ENOMEM,
    };

    // Get current thread
    let current = match thread::current() {
        Some(t) => t,
        None => return ENOSYS,
    };

    // Save current thread's state
    thread::save_state(current);

    // Create child thread
    let child = match thread::create_thread(Some(current), new_page_dir, true) {
        Some(t) => t,
        None => return ENOMEM,
    };

    // Copy CPU state and mode from parent to child
    child.cpu_state = current.cpu_state;
    child.is_64bit = current.is_64bit;
    child.frame_is_64 = current.frame_is_64;

    // Child returns 0
    thread::set_return(child, 0);

    println!("Fork: parent={} child={} child.rax={}", current.tid, child.tid, child.cpu_state.rax);

    // Parent returns child's TID
    child.tid
}

/// Exec syscall (5)
/// Replaces current process with a new program
/// arg0 (rdx) = path pointer
/// arg1 (rcx) = path length
/// arg2 (rbx) = argv pointer (array of &str = [(ptr, len), ...])
/// arg3 (rsi) = argc (number of &str elements)
fn sys_exec(regs: &mut Regs) -> i32 {
    let path = unsafe { &*core::ptr::slice_from_raw_parts(regs.rdx as *const u8, regs.rcx as usize) };

    let Ok(path) = core::str::from_utf8(path) else {
        return ENOENT;
    };
    println!("Exec: {}", path);

    // Read argv from caller's address space (before we free it)
    let argc = regs.rsi as usize;
    let argv_ptr = regs.rbx as usize;
    let caller_64bit = thread::current().map_or(false, |t| t.is_64bit);
    let args = read_argv(argv_ptr, argc, caller_64bit);

    // Find the file in TAR
    let size = match startup::find_file(path.as_bytes()) {
        Some(s) => s,
        None => return ENOENT,
    };

    let mut buffer = alloc::vec![0; size];
    startup::read_file(&mut buffer);

    // Free current user pages and load new ELF (point of no return)
    paging2::free_user_pages();
    paging2::flush_tlb();

    let loaded = match elf::load_elf(&buffer) {
        Ok(e) => e,
        Err(_) => { thread::exit_thread(-ENOEXEC); },
    };

    let want_64 = loaded.class == elf::ElfClass::Elf64;
    println!("exec: want_64={} entry={:#x}", want_64, loaded.entry);
    if want_64 && !paging2::cpu_supports_long_mode() {
        thread::exit_thread(-ENOEXEC);
    }

    let symbols = SymbolData::new(buffer.into_boxed_slice());

    if let Some(current) = thread::current() {
        // Toggle CPU mode if needed (PAE → Compat)
        // In compat mode, both 32/64-bit run without toggling.
        if want_64 != current.is_64bit {
            let need_toggle = match paging2::cpu_mode() {
                paging2::CpuMode::Pae => want_64,
                paging2::CpuMode::Compat => false,  // TODO: toggle to PAE for VM86
                _ => false,
            };
            if need_toggle {
                paging2::ensure_trampoline_mapped();
                if !want_64 {
                    paging2::sync_hw_pdpt();
                }
                descriptors::toggle_mode(paging2::toggle_cr3(want_64));
            }
            current.is_64bit = want_64;
        }

        println!("exec: setting up stack");
        // Set up argv on the new user stack and get the adjusted SP
        let word = if want_64 { 8usize } else { 4usize };
        let stack = setup_user_stack(&args, want_64, word);

        if want_64 {
            thread::init_process_thread_64(current, loaded.entry, stack.sp as u64);
            // System V ABI: first two args in RDI, RSI
            current.cpu_state.rdi = stack.argc as u64;
            current.cpu_state.rsi = stack.argv as u64;
        } else {
            thread::init_process_thread(current, loaded.entry as u32, stack.sp as u32);
        }

        println!("exec: calling exit_to_thread");
        current.symbols = symbols;
        thread::exit_to_thread(current);
    }

    ENOSYS
}

/// Read argv from the caller's userspace into kernel-owned Vecs.
/// Each &str in userspace is (ptr, len) — 8 bytes for 32-bit, 16 bytes for 64-bit.
fn read_argv(argv_ptr: usize, argc: usize, is_64bit: bool) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
    let mut args = alloc::vec::Vec::with_capacity(argc);
    for i in 0..argc {
        let (str_ptr, str_len) = if is_64bit {
            let base = argv_ptr + i * 16;
            let ptr = unsafe { *(base as *const u64) } as usize;
            let len = unsafe { *((base + 8) as *const u64) } as usize;
            (ptr, len)
        } else {
            let base = argv_ptr + i * 8;
            let ptr = unsafe { *(base as *const u32) } as usize;
            let len = unsafe { *((base + 4) as *const u32) } as usize;
            (ptr, len)
        };
        let mut buf = alloc::vec![0u8; str_len];
        unsafe { core::ptr::copy_nonoverlapping(str_ptr as *const u8, buf.as_mut_ptr(), str_len); }
        args.push(buf);
    }
    args
}

/// Result of setting up the user stack with argv data
struct StackSetup {
    sp: usize,
    argc: usize,
    argv: usize,
}

/// Set up argv on the new process's user stack.
///
/// Stack layout (high to low):
///   [string bytes for arg0] [string bytes for arg1] ...
///   [&str array: (ptr0, len0), (ptr1, len1), ...]
///   32-bit only: [dummy return addr] [argc] [argv_ptr]
fn setup_user_stack(args: &[alloc::vec::Vec<u8>], want_64: bool, word: usize) -> StackSetup {
    let stack_top = elf::USER_STACK_TOP;
    let mut sp = stack_top;

    // 1. Write string data at top of stack
    let mut string_addrs: alloc::vec::Vec<usize> = alloc::vec::Vec::with_capacity(args.len());
    for arg in args.iter() {
        sp -= arg.len();
        unsafe { core::ptr::copy_nonoverlapping(arg.as_ptr(), sp as *mut u8, arg.len()); }
        string_addrs.push(sp);
    }

    // 2. Align to word boundary
    sp &= !(word - 1);

    // 3. Write &str array: [(ptr, len), (ptr, len), ...]
    // Layout must match Rust's &str representation
    sp -= args.len() * 2 * word;
    let argv_base = sp;
    for (i, (arg, &addr)) in args.iter().zip(string_addrs.iter()).enumerate() {
        let entry_addr = argv_base + i * 2 * word;
        if want_64 {
            unsafe {
                *(entry_addr as *mut u64) = addr as u64;       // ptr
                *((entry_addr + 8) as *mut u64) = arg.len() as u64; // len
            }
        } else {
            unsafe {
                *(entry_addr as *mut u32) = addr as u32;       // ptr
                *((entry_addr + 4) as *mut u32) = arg.len() as u32; // len
            }
        }
    }

    if want_64 {
        // 64-bit: _start(argc, argv) via System V ABI — argc in RDI, argv in RSI
        // Caller sets these in the CpuState. SP just needs to be below the data.
        sp &= !0xF; // 16-byte align
        StackSetup { sp, argc: args.len(), argv: argv_base }
    } else {
        // 32-bit: _start(argc, argv) via cdecl — args on the stack
        // Stack: [dummy_ret_addr] [argc] [argv_ptr]
        sp -= 4;
        unsafe { *(sp as *mut u32) = argv_base as u32; } // argv
        sp -= 4;
        unsafe { *(sp as *mut u32) = args.len() as u32; } // argc
        sp -= 4;
        unsafe { *(sp as *mut u32) = 0; } // dummy return address
        StackSetup { sp, argc: args.len(), argv: argv_base }
    }
}

/// Open syscall (6)
/// Opens a file and returns its size (or -1 if not found)
/// RDX = path pointer (null-terminated)
fn sys_open(regs: &mut Regs) -> i32 {
    let path_ptr = regs.rdx as *const u8;

    // Get path as slice
    let path = unsafe {
        let mut len = 0;
        let mut p = path_ptr;
        while *p != 0 && len < 256 {
            len += 1;
            p = p.add(1);
        }
        core::slice::from_raw_parts(path_ptr, len)
    };

    // Print path for debugging
    print!("Open: ");
    for &c in path {
        vga::vga().putchar(c);
    }
    println!();

    // Find the file in TAR and return its size
    match startup::find_file(path) {
        Some(size) => size as i32,
        None => ENOENT,
    }
}

/// Waitpid syscall (7)
/// Waits for a child process to exit
/// RDX = pid (-1 for any child)
/// Returns: child tid (or negative error)
fn sys_wait(regs: &mut Regs) -> i32 {
    let pid = regs.rdx as i32;
    let (tid, _code) = thread::waitpid(pid);
    if tid >= 0 || tid == -10 {
        return tid;
    }
    // EAGAIN: children exist but none exited yet — yield
    // Userspace must retry (busy-wait with yield)
    0x7fff_ffff // sentinel: "try again"
}

/// Read syscall (8)
/// Reads from a file descriptor
fn sys_read(regs: &mut Regs) -> i32 {
    let fd = regs.rdx;
    let _buf = regs.rcx as *mut u8;
    let _len = regs.rbx as usize;

    if fd == 0 {
        // stdin - TODO: implement keyboard buffer
        0
    } else {
        // TODO: Read from file
        ENOSYS
    }
}

/// Write syscall (9)
/// Writes to a file descriptor
fn sys_write(regs: &mut Regs) -> i32 {
    let fd = regs.rdx;
    let buf = regs.rcx as *const u8;
    let len = regs.rbx as usize;

    if fd == 1 || fd == 2 {
        // stdout or stderr - write to VGA
        unsafe {
            for i in 0..len {
                vga::vga().putchar(*buf.add(i));
            }
        }
        len as i32
    } else {
        ENOSYS
    }
}
