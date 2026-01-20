//! System call implementations
//!
//! Syscall numbers (via INT 0x80):
//! - 0: Exit
//! - 1: Yield
//! - 4: Fork
//! - 5: Exec
//! - 6: Open
//! - 8: Read
//! - 9: Write
//!
//! Arguments passed in: EDX, ECX, EBX, ESI, EDI
//! Return value in: EAX

use crate::{SCRATCH, elf};
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
    None,             // 7
    Some(sys_read),   // 8
    Some(sys_write),  // 9
];

/// Dispatch a syscall
pub fn dispatch(regs: &mut Regs) {
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

    regs.rax = result as u32 as u64;  // Sign-extend for 32-bit compatibility
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
        thread::schedule(current.tid, false);
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

    // Copy CPU state from parent to child
    child.cpu_state = current.cpu_state;

    // Child returns 0
    thread::set_return(child, 0);

    // Parent returns child's TID
    child.tid
}

/// Exec syscall (5)
/// Replaces current process with a new program
/// RDX = path pointer (null-terminated)
fn sys_exec(regs: &mut Regs) -> i32 {
    let path = unsafe { &*core::ptr::slice_from_raw_parts(regs.rdx as *const u8, regs.rcx as usize) };

    // Print path for debugging
    let Ok(path) = core::str::from_utf8(path) else {
        return ENOENT;
    };
    println!("Exec: {}", path);

    // Find the file in TAR
    let size = match startup::find_file(path.as_bytes()) {
        Some(s) => s,
        None => return ENOENT,
    };

    println!("File size {}", size);

    let mut buffer = alloc::vec![0; size];

    // Read the file into scratch buffer
    startup::read_file(&mut buffer);

    // Free current user pages
    paging2::free_user_pages();
    paging2::flush_tlb();

    // Load the ELF
    let entry = match elf::load_elf(&buffer) {
        Ok(e) => e,
        Err(_) => return ENOEXEC,
    };

    // Extract symbols for debugging (before buffer is dropped)
    let symbols = SymbolData::new(buffer.into_boxed_slice());

    // Update current thread's EIP to the new entry point
    // Stack is demand-paged on first access
    if let Some(current) = thread::current() {
        current.symbols = symbols;
        thread::init_process_thread(current, entry, elf::USER_STACK_TOP as u32);
        thread::exit_to_thread(current);
    }

    ENOSYS
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
