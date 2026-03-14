//! Freestanding C runtime for RetroOS userspace
//!
//! Provides _start, panic handler, and syscall wrappers.
//! Apps just define: `#[unsafe(no_mangle)] pub extern "C" fn main() { ... }`

#![no_std]

use core::panic::PanicInfo;

// Syscall numbers
const SYS_EXIT: u32 = 0;
const SYS_YIELD: u32 = 1;
const SYS_FORK: u32 = 4;
const SYS_EXEC: u32 = 5;
const SYS_OPEN: u32 = 6;
const SYS_READ: u32 = 8;
const SYS_WRITE: u32 = 9;

// RetroOS syscall ABI: int 0x80, eax=num, edx=arg0, ecx=arg1, ebx=arg2
// Same registers in both 32-bit and 64-bit mode.

#[cfg(target_arch = "x86")]
#[inline(always)]
unsafe fn syscall(num: u32, a0: usize, a1: usize, a2: usize) -> i32 {
    let result: i32;
    unsafe { core::arch::asm!(
        "int 0x80",
        inout("eax") num => result,
        in("edx") a0 as u32,
        in("ecx") a1 as u32,
        in("ebx") a2 as u32,
        options(nostack, preserves_flags)
    ); }
    result
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn syscall(num: u32, a0: usize, a1: usize, a2: usize) -> i32 {
    let result: i64;
    unsafe { core::arch::asm!(
        "int 0x80",
        inout("rax") num as u64 => result,
        in("rdi") a0,
        in("rsi") a1,
        in("rdx") a2,
        options(nostack, preserves_flags)
    ); }
    result as i32
}

pub fn write(fd: i32, buf: &[u8]) -> i32 {
    unsafe { syscall(SYS_WRITE, fd as usize, buf.as_ptr() as usize, buf.len()) }
}

pub fn read(fd: i32, buf: &mut [u8]) -> i32 {
    unsafe { syscall(SYS_READ, fd as usize, buf.as_mut_ptr() as usize, buf.len()) }
}

pub fn open(path: &str) -> i32 {
    unsafe { syscall(SYS_OPEN, path.as_ptr() as usize, path.len(), 0) }
}

pub fn exit(code: i32) -> ! {
    unsafe { syscall(SYS_EXIT, code as usize, 0, 0); }
    loop {}
}

pub fn yield_cpu() {
    unsafe { syscall(SYS_YIELD, 0, 0, 0); }
}

pub fn fork() -> i32 {
    unsafe { syscall(SYS_FORK, 0, 0, 0) }
}

pub fn exec(path: &str) -> i32 {
    unsafe { syscall(SYS_EXEC, path.as_ptr() as usize, path.len(), 0) }
}

/// Print to stdout
pub fn print(s: &str) {
    write(1, s.as_bytes());
}

unsafe extern "C" {
    fn main();
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe { main(); }
    exit(0);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write(1, b"PANIC!\n");
    exit(1);
}
