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
//! - 10: Close
//! - 11: Seek
//!
//! Arguments passed in: EDX, ECX, EBX, ESI, EDI
//! 64-bit ABI: RDI, RSI, RDX, R10, R8 (remapped to canonical layout)
//! Return value in: EAX

use crate::kernel::elf;
use crate::kernel::stacktrace::SymbolData;
use crate::kernel::startup;
use crate::kernel::thread;
use crate::kernel::vfs;
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

/// Syscall result: return value + optional switch target
pub struct SyscallResult {
    pub retval: i32,
    pub switch_to: Option<usize>,
}

impl SyscallResult {
    fn val(retval: i32) -> Self { Self { retval, switch_to: None } }
    fn switch(switch_to: Option<usize>) -> Self { Self { retval: 0, switch_to } }
}

/// Syscall handler type
type SyscallFn = fn(&mut Regs) -> SyscallResult;

/// Syscall table
const SYSCALL_TABLE: [Option<SyscallFn>; 14] = [
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
    Some(sys_close),  // 10
    Some(sys_seek),   // 11
    Some(sys_chdir),  // 12
    Some(sys_getcwd), // 13
];

/// Dispatch a syscall. Returns Some(idx) if a context switch is needed.
pub fn dispatch(regs: &mut Regs) -> Option<usize> {
    // 64-bit syscall ABI uses different registers: rdi=arg0, rsi=arg1, rdx=arg2, r10=arg3, r8=arg4
    // Remap to the canonical layout (rdx=arg0, rcx=arg1, rbx=arg2, rsi=arg3, rdi=arg4)
    // so handlers don't need to know which mode the caller is in.
    let is_64bit = regs.mode() == crate::UserMode::Mode64;
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
            SyscallResult::val(ENOSYS)
        }
    } else {
        SyscallResult::val(ENOSYS)
    };

    regs.rax = result.retval as u32 as u64;
    result.switch_to
}

/// Exit syscall (0)
/// Terminates the current process
fn sys_exit(regs: &mut Regs) -> SyscallResult {
    let exit_code = regs.rdx as i32;
    SyscallResult::switch(Some(thread::exit_thread(exit_code)))
}

/// Yield syscall (1)
/// Yields CPU to another thread
fn sys_yield(regs: &mut Regs) -> SyscallResult {
    // Save current state and schedule another thread
    let current = thread::current();
    thread::save_state(current, regs);
    thread::set_return(current, 0);  // Yield returns 0 when resumed
    current.state = thread::ThreadState::Ready;
    SyscallResult::switch(thread::schedule())
}

/// Fork syscall (4)
/// Creates a copy of the current process
fn sys_fork(regs: &mut Regs) -> SyscallResult {
    let current = thread::current();
    let mut child_root = crate::RootPageTable::empty();
    startup::arch_user_fork(&mut child_root);

    // Create child thread with the pre-filled root page table
    let child = match thread::create_thread(Some(current), child_root, true) {
        Some(t) => t,
        None => return SyscallResult::val(ENOMEM),
    };

    // Copy CPU state from REGS (running thread's state is in arch, not cpu_state)
    child.cpu_state = *regs;

    // Inherit open file descriptors (bumps refcounts in global file table)
    vfs::dup_fds(&current.fds, &mut child.fds);

    // Inherit current working directory
    child.cwd = current.cwd;
    child.cwd_len = current.cwd_len;

    // Child returns 0
    thread::set_return(child, 0);

    // Parent returns child's TID
    current.state = thread::ThreadState::Ready;
    let child_tid = child.tid;
    let child_idx = child_tid as usize;

    // Switch to child first so it can exec before parent triggers COW faults
    SyscallResult { retval: child_tid, switch_to: Some(child_idx) }
}

/// Exec syscall (5)
/// Replaces current process with a new program
/// arg0 (rdx) = path pointer
/// arg1 (rcx) = path length
/// arg2 (rbx) = argv pointer (array of &str = [(ptr, len), ...])
/// arg3 (rsi) = argc (number of &str elements)
fn sys_exec(regs: &mut Regs) -> SyscallResult {
    let path = unsafe { &*core::ptr::slice_from_raw_parts(regs.rdx as *const u8, regs.rcx as usize) };

    let Ok(path) = core::str::from_utf8(path) else {
        return SyscallResult::val(ENOENT);
    };
    // Detect DOS executable extensions (case-insensitive)
    let is_com = has_ext(path, b"COM");
    let is_exe = has_ext(path, b"EXE");

    // Read argv from caller's address space (before we free it)
    let argc = regs.rsi as usize;
    let argv_ptr = regs.rbx as usize;
    let caller_64bit = regs.mode() == crate::UserMode::Mode64;
    let args = read_argv(argv_ptr, argc, caller_64bit);

    // Close inherited file descriptors before loading the new program
    vfs::close_all_fds(&mut thread::current().fds);

    // Drop old SymbolData before allocating the new buffer. The old symbols
    // hold a Box<[u8]> with the entire previous ELF (~300-400K). Freeing it
    // first lets the heap free list absorb the space, so the new buffer
    // allocation can reuse it instead of extending the heap every iteration.
    thread::current().symbols = None;

    // Resolve path relative to cwd, then open via VFS
    let mut path_buf = [0u8; 164];
    let resolved = vfs::resolve(path.as_bytes(), &mut path_buf);
    let fd = vfs::open(resolved);
    if fd < 0 { return SyscallResult::val(ENOENT); }
    let size = vfs::file_size(fd) as usize;

    let mut buffer = alloc::vec![0; size];
    vfs::read(fd, &mut buffer);
    vfs::close(fd);

    let want_64 = match lib::elf::Elf::parse(&buffer) {
        Ok(e) => e.class() == lib::elf::ElfClass::Elf64,
        Err(_) => false,
    };

    // DOS executables use the VM86 exec path
    if is_com || is_exe {
        let tid = exec_dos(&buffer, is_exe, resolved);
        *regs = thread::current().cpu_state;
        // buffer and args dropped here by RAII
        return SyscallResult::switch(Some(tid));
    }

    // Free current user pages and load new ELF (point of no return)
    startup::arch_user_clean();

    let loaded = match elf::load_elf(&buffer) {
        Ok(e) => e,
        Err(_) => { return SyscallResult::switch(Some(thread::exit_thread(-ENOEXEC))); },
    };

    let symbols = SymbolData::new(buffer.into_boxed_slice());

    let current = thread::current();
    let tid = current.tid as usize;

    // Set up argv on the new user stack (demand-pages stack)
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

    current.symbols = symbols;

    // Sync new state to REGS (event loop works on REGS, not thread.cpu_state)
    *regs = current.cpu_state;
    // args and buffer dropped here by RAII
    SyscallResult::switch(Some(tid))
}

/// Execute a DOS program (.COM or .EXE) in VM86 mode.
/// Returns thread index to switch to.
fn exec_dos(data: &[u8], is_exe: bool, prog_name: &[u8]) -> usize {
    use crate::kernel::vm86;

    // Free current user pages + map first 1MB for VM86
    startup::arch_user_clean();
    startup::arch_map_low_mem();

    // Set up IVT
    vm86::setup_ivt();

    // Load binary
    let (cs, ip, ss, sp, end_seg) = if is_exe && vm86::is_mz_exe(data) {
        vm86::load_exe(data, prog_name).unwrap_or_else(|| {
            crate::println!("Invalid MZ EXE");
            (0, 0, 0, 0, 0)
        })
    } else {
        vm86::load_com(data, prog_name)
    };

    let current = thread::current();
    let tid = current.tid as usize;

    thread::init_process_thread_vm86(current, vm86::COM_SEGMENT, cs, ip, ss, sp);
    // init_process_thread_vm86 resets Vm86State; restore heap_seg and DTA
    current.vm86.heap_seg = end_seg;
    current.vm86.dta = (vm86::COM_SEGMENT as u32) * 16 + 0x80;
    current.symbols = None;

    tid
}

/// Check if path ends with ".EXT" (case-insensitive, 3-letter extension).
fn has_ext(path: &str, ext: &[u8; 3]) -> bool {
    let b = path.as_bytes();
    b.len() >= 4 && b[b.len() - 4] == b'.'
        && b[b.len() - 3].to_ascii_uppercase() == ext[0]
        && b[b.len() - 2].to_ascii_uppercase() == ext[1]
        && b[b.len() - 1].to_ascii_uppercase() == ext[2]
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
pub(crate) struct StackSetup {
    pub(crate) sp: usize,
    pub(crate) argc: usize,
    pub(crate) argv: usize,
}

/// Set up argv on the new process's user stack.
///
/// Stack layout (high to low):
///   [string bytes for arg0] [string bytes for arg1] ...
///   [&str array: (ptr0, len0), (ptr1, len1), ...]
///   32-bit only: [dummy return addr] [argc] [argv_ptr]
pub(crate) fn setup_user_stack(args: &[alloc::vec::Vec<u8>], want_64: bool, word: usize) -> StackSetup {
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
        // Caller sets these in the Regs. SP just needs to be below the data.
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
/// Opens a file and returns a file descriptor (or negative error)
/// RDX = path pointer (null-terminated)
fn sys_open(regs: &mut Regs) -> SyscallResult {
    let path_ptr = regs.rdx as *const u8;

    // Get path as slice (null-terminated)
    let path = unsafe {
        let mut len = 0;
        let mut p = path_ptr;
        while *p != 0 && len < 256 {
            len += 1;
            p = p.add(1);
        }
        core::slice::from_raw_parts(path_ptr, len)
    };

    SyscallResult::val(vfs::open(path))
}

/// Waitpid syscall (7)
/// Waits for a child process to exit
/// RDX = pid (-1 for any child)
/// Returns: child tid (or negative error)
fn sys_wait(regs: &mut Regs) -> SyscallResult {
    let pid = regs.rdx as i32;
    let (tid, _code) = thread::waitpid(pid);
    if tid >= 0 || tid == -10 {
        return SyscallResult::val(tid);
    }
    // EAGAIN: children exist but none exited yet — yield
    // Userspace must retry (busy-wait with yield)
    SyscallResult::val(0x7fff_ffff) // sentinel: "try again"
}

/// Read syscall (8)
/// Reads from a file descriptor
fn sys_read(regs: &mut Regs) -> SyscallResult {
    let fd = regs.rdx as i32;
    let buf = regs.rcx as *mut u8;
    let len = regs.rbx as usize;

    if fd == 0 {
        // stdin — read from global keyboard buffer
        let user_buf = unsafe { core::slice::from_raw_parts_mut(buf, len) };
        let n = crate::kernel::keyboard::read(user_buf);
        SyscallResult::val(n as i32)
    } else if fd >= 3 {
        let user_buf = unsafe { core::slice::from_raw_parts_mut(buf, len) };
        SyscallResult::val(vfs::read(fd, user_buf))
    } else {
        SyscallResult::val(ENOSYS)
    }
}

/// Write syscall (9)
/// Writes to a file descriptor
fn sys_write(regs: &mut Regs) -> SyscallResult {
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
        SyscallResult::val(len as i32)
    } else {
        SyscallResult::val(ENOSYS)
    }
}

/// Close syscall (10)
/// Closes a file descriptor
fn sys_close(regs: &mut Regs) -> SyscallResult {
    let fd = regs.rdx as i32;
    SyscallResult::val(vfs::close(fd))
}

/// Seek syscall (11)
/// Repositions file offset
/// RDX = fd, RCX = offset, RBX = whence (0=SET, 1=CUR, 2=END)
fn sys_seek(regs: &mut Regs) -> SyscallResult {
    let fd = regs.rdx as i32;
    let offset = regs.rcx as i32;
    let whence = regs.rbx as i32;
    SyscallResult::val(vfs::seek(fd, offset, whence))
}

/// Change current directory
/// RDX = pointer to path string, RCX = length
fn sys_chdir(regs: &mut Regs) -> SyscallResult {
    let ptr = regs.rdx as usize as *const u8;
    let len = regs.rcx as usize;
    let path = unsafe { core::slice::from_raw_parts(ptr, len) };
    SyscallResult::val(vfs::chdir(path))
}

/// Get current directory
/// RDX = pointer to buffer, RCX = buffer size
/// Returns length written or negative error
fn sys_getcwd(regs: &mut Regs) -> SyscallResult {
    let ptr = regs.rdx as usize as *mut u8;
    let size = regs.rcx as usize;
    let cwd = crate::kernel::thread::current().cwd_str();
    let len = cwd.len().min(size);
    unsafe { core::ptr::copy_nonoverlapping(cwd.as_ptr(), ptr, len); }
    SyscallResult::val(len as i32)
}
