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

/// Dispatch a syscall. Returns Some(idx) if a context switch is needed.
pub fn dispatch(regs: &mut Regs) -> Option<usize> {
    // 64-bit syscall ABI uses different registers: rdi=arg0, rsi=arg1, rdx=arg2, r10=arg3, r8=arg4
    // Remap to the canonical layout (rdx=arg0, rcx=arg1, rbx=arg2, rsi=arg3, rdi=arg4)
    // so handlers don't need to know which mode the caller is in.
    let is_64bit = thread::current().mode == thread::ThreadMode::Mode64;
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
    SyscallResult::switch(thread::exit_thread(exit_code))
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
    // Fork the address space
    let new_page_dir = match paging2::fork_current() {
        Some(pd) => pd,
        None => return SyscallResult::val(ENOMEM),
    };

    // Get current thread
    let current = thread::current();

    // Save current thread's state
    thread::save_state(current, regs);

    // Create child thread (init_fork extracts PDPT entries from new_page_dir)
    let child = match thread::create_thread(Some(current), new_page_dir, true) {
        Some(t) => t,
        None => return SyscallResult::val(ENOMEM),
    };

    // Free the child's root page table page — init_fork already extracted the
    // PDPT entries into the thread's RootPageTable, so the page itself is no
    // longer needed. Without this, it leaks 1 page per fork.
    crate::phys_mm::free_phys_page(new_page_dir);

    // Copy CPU state and mode from parent to child
    child.cpu_state = current.cpu_state;
    child.mode = current.mode;
    child.frame_format = current.frame_format;

    // Child returns 0
    thread::set_return(child, 0);

    // Parent returns child's TID
    SyscallResult::val(child.tid)
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
    crate::phys_mm::dump_stats();
    println!("Exec: {}", path);

    // Detect .COM extension (case-insensitive)
    let is_com = path.len() >= 4 && {
        let ext = &path.as_bytes()[path.len()-4..];
        (ext[0] == b'.' &&
         (ext[1] == b'c' || ext[1] == b'C') &&
         (ext[2] == b'o' || ext[2] == b'O') &&
         (ext[3] == b'm' || ext[3] == b'M'))
    };

    // Read argv from caller's address space (before we free it)
    let argc = regs.rsi as usize;
    let argv_ptr = regs.rbx as usize;
    let caller_64bit = thread::current().mode == thread::ThreadMode::Mode64;
    let hp0 = crate::heap::heap_pages();
    let args = read_argv(argv_ptr, argc, caller_64bit);
    let hp1 = crate::heap::heap_pages();

    // Drop old SymbolData before allocating the new buffer. The old symbols
    // hold a Box<[u8]> with the entire previous ELF (~300-400K). Freeing it
    // first lets the heap free list absorb the space, so the new buffer
    // allocation can reuse it instead of extending the heap every iteration.
    {
        let current = thread::current();
        if current.symbols.is_some() {
            println!("DROP-SYM: tid={} for {}", current.tid, path);
        }
        current.symbols = None;
    }
    let hp2 = crate::heap::heap_pages();

    // Find the file in TAR
    let size = match startup::find_file(path.as_bytes()) {
        Some(s) => s,
        None => return SyscallResult::val(ENOENT),
    };

    let mut buffer = alloc::vec![0; size];
    let hp3 = crate::heap::heap_pages();
    startup::read_file(&mut buffer);
    if hp3 > hp0 {
        println!("HEAP-EXEC: +{} (argv={} sym={} buf={}) size={}", hp3 - hp0, hp1 - hp0, hp2 - hp1, hp3 - hp2, size);
    }

    // .COM files use the VM86 exec path
    if is_com {
        let tid = exec_com(&buffer);
        // buffer and args dropped here by RAII
        return SyscallResult::switch(Some(tid));
    }

    // Free current user pages and load new ELF (point of no return)
    paging2::free_user_pages();
    paging2::flush_tlb();

    let loaded = match elf::load_elf(&buffer) {
        Ok(e) => e,
        Err(_) => { return SyscallResult::switch(thread::exit_thread(-ENOEXEC)); },
    };

    let want_64 = loaded.class == elf::ElfClass::Elf64;
    println!("exec: want_64={} entry={:#x}", want_64, loaded.entry);
    if want_64 && !paging2::cpu_supports_long_mode() {
        return SyscallResult::switch(thread::exit_thread(-ENOEXEC));
    }

    let symbols = SymbolData::new(buffer.into_boxed_slice());
    if symbols.is_none() {
        println!("SYM-NONE: {}", path);
    }

    let current = thread::current();
    let tid = current.tid as usize;

    // Toggle CPU mode if needed (PAE → Compat)
    // In compat mode, both 32/64-bit run without toggling.
    let want_mode = if want_64 { thread::ThreadMode::Mode64 } else { thread::ThreadMode::Mode32 };
    if want_mode != current.mode {
        let need_toggle = match paging2::cpu_mode() {
            paging2::CpuMode::Pae => want_64,
            paging2::CpuMode::Compat => want_mode == thread::ThreadMode::Mode16,
            _ => false,
        };
        if need_toggle {
            paging2::ensure_trampoline_mapped();
            if !want_64 {
                paging2::sync_hw_pdpt();
            }
            descriptors::toggle_mode(paging2::toggle_cr3(want_64));
        }
        current.mode = want_mode;
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

    current.symbols = symbols;
    // args and buffer dropped here by RAII
    SyscallResult::switch(Some(tid))
}

/// Execute a .COM file in VM86 mode. Returns thread index to switch to.
fn exec_com(data: &[u8]) -> usize {
    use crate::vm86;

    // Free current user pages
    paging2::free_user_pages();
    paging2::flush_tlb();

    // Map first 1MB user-accessible for VM86
    paging2::map_low_mem_user();

    // Set up IVT (all 256 entries → IRET stub)
    vm86::setup_ivt();

    // Load .COM binary
    let (cs, ip, ss, sp) = vm86::load_com(data);
    println!("exec_com: cs={:#06x} ip={:#06x} ss={:#06x} sp={:#06x}", cs, ip, ss, sp);

    let current = thread::current();
    let tid = current.tid as usize;

    // Initialize VM86 thread state
    thread::init_process_thread_vm86(current, cs, ip, ss, sp);
    current.symbols = None;

    tid
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
/// Opens a file and returns its size (or -1 if not found)
/// RDX = path pointer (null-terminated)
fn sys_open(regs: &mut Regs) -> SyscallResult {
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
        Some(size) => SyscallResult::val(size as i32),
        None => SyscallResult::val(ENOENT),
    }
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
    let fd = regs.rdx;
    let _buf = regs.rcx as *mut u8;
    let _len = regs.rbx as usize;

    if fd == 0 {
        // stdin - TODO: implement keyboard buffer
        SyscallResult::val(0)
    } else {
        // TODO: Read from file
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
