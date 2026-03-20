//! Freestanding C runtime for RetroOS userspace
//!
//! Provides _start, panic handler, and syscall wrappers.
//! Apps define: `#[unsafe(no_mangle)] pub fn main(args: &[&str]) { ... }`

#![no_std]

use core::panic::PanicInfo;

// Syscall numbers
const SYS_EXIT: u32 = 0;
const SYS_YIELD: u32 = 1;
const SYS_FORK: u32 = 4;
const SYS_EXEC: u32 = 5;
const SYS_OPEN: u32 = 6;
const SYS_WAIT: u32 = 7;
const SYS_READ: u32 = 8;
const SYS_WRITE: u32 = 9;

// RetroOS syscall ABI: int 0x80, eax=num, edx=arg0, ecx=arg1, ebx=arg2, esi=arg3

#[cfg(target_arch = "x86")]
#[inline(always)]
unsafe fn syscall(num: u32, a0: usize, a1: usize, a2: usize, a3: usize) -> i32 {
    let result: i32;
    unsafe { core::arch::asm!(
        "push esi",
        "mov esi, {a3:e}",
        "int 0x80",
        "pop esi",
        inout("eax") num => result,
        in("edx") a0 as u32,
        in("ecx") a1 as u32,
        in("ebx") a2 as u32,
        a3 = in(reg) a3 as u32,
    ); }
    result
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn syscall(num: u32, a0: usize, a1: usize, a2: usize, a3: usize) -> i32 {
    let result: i64;
    unsafe { core::arch::asm!(
        "int 0x80",
        inout("rax") num as u64 => result,
        in("rdi") a0,
        in("rsi") a1,
        in("rdx") a2,
        in("r10") a3,
        options(nostack, preserves_flags)
    ); }
    result as i32
}

pub fn write(fd: i32, buf: &[u8]) -> i32 {
    unsafe { syscall(SYS_WRITE, fd as usize, buf.as_ptr() as usize, buf.len(), 0) }
}

pub fn read(fd: i32, buf: &mut [u8]) -> i32 {
    unsafe { syscall(SYS_READ, fd as usize, buf.as_mut_ptr() as usize, buf.len(), 0) }
}

pub fn open(path: &str) -> i32 {
    unsafe { syscall(SYS_OPEN, path.as_ptr() as usize, path.len(), 0, 0) }
}

pub fn exit(code: i32) -> ! {
    unsafe { syscall(SYS_EXIT, code as usize, 0, 0, 0); }
    loop {}
}

pub fn yield_cpu() {
    unsafe { syscall(SYS_YIELD, 0, 0, 0, 0); }
}

pub fn fork() -> i32 {
    unsafe { syscall(SYS_FORK, 0, 0, 0, 0) }
}

pub fn exec(path: &str, args: &[&str]) -> i32 {
    unsafe { syscall(SYS_EXEC, path.as_ptr() as usize, path.len(),
                     args.as_ptr() as usize, args.len()) }
}

/// Wait for a child process. pid=-1 for any child. Returns child tid.
pub fn waitpid(pid: i32) -> i32 {
    loop {
        let r = unsafe { syscall(SYS_WAIT, pid as usize, 0, 0, 0) };
        if r != 0x7fff_ffff {
            return r;
        }
        yield_cpu();
    }
}

/// Wait for all children to exit
pub fn wait_all() {
    loop {
        let r = waitpid(-1);
        if r < 0 { break; }
    }
}

/// Print to stdout
pub fn print(s: &str) {
    write(1, s.as_bytes());
}

/// Print a decimal number
pub fn print_num(mut n: i32) {
    if n < 0 {
        print("-");
        n = -n;
    }
    if n >= 10 {
        print_num(n / 10);
    }
    let digit = [b'0' + (n % 10) as u8];
    write(1, &digit);
}

/// Parse a string as a decimal integer
pub fn parse_int(s: &str) -> i32 {
    let mut n: i32 = 0;
    for &b in s.as_bytes() {
        if b >= b'0' && b <= b'9' {
            n = n * 10 + (b - b'0') as i32;
        } else {
            break;
        }
    }
    n
}

/// Format an integer into a stack buffer, returns the used portion as &str.
pub fn format_int(n: i32, buf: &mut [u8; 12]) -> &str {
    let mut val = n;
    if val == 0 {
        buf[0] = b'0';
        return unsafe { core::str::from_utf8_unchecked(&buf[..1]) };
    }
    let mut i = 12;
    while val > 0 {
        i -= 1;
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    unsafe { core::str::from_utf8_unchecked(&buf[i..12]) }
}

unsafe extern "Rust" {
    fn main(args: &[&str]);
}

/// Entry point. Kernel sets up the calling convention so that _start receives
/// argc and a pointer to an array of &str (each is a (ptr, len) pair in memory).
#[unsafe(no_mangle)]
pub extern "C" fn _start(argc: usize, argv: usize) -> ! {
    let args: &[&str] = unsafe {
        core::slice::from_raw_parts(argv as *const &str, argc)
    };
    unsafe { main(args); }
    exit(0);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write(1, b"PANIC!\n");
    exit(1);
}
