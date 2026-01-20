//! Init process for RetroOS
//!
//! This is the first user-space process. It prints a message and loops.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use lib::println;

/// Syscall numbers
const SYS_EXIT: u32 = 0;
const SYS_YIELD: u32 = 1;
const SYS_WRITE: u32 = 9;
const SYS_EXEC: u32 = 5;

/// File descriptors
const STDOUT: u32 = 1;

/// Make a syscall with up to 3 arguments
#[inline(always)]
unsafe fn syscall3(num: u32, arg0: u32, arg1: u32, arg2: u32) -> i32 {
    let result: i32;
    core::arch::asm!(
        "int 0x80",
        inout("eax") num => result,
        in("edx") arg0,
        in("ecx") arg1,
        in("ebx") arg2,
        options(nostack, preserves_flags)
    );
    result
}

/// Write to stdout
fn write(s: &[u8]) -> i32 {
    unsafe { syscall3(SYS_WRITE, STDOUT, s.as_ptr() as u32, s.len() as u32) }
}

/// Exit the process
fn exit(code: i32) -> ! {
    unsafe {
        syscall3(SYS_EXIT, code as u32, 0, 0);
    }
    loop {}
}

/// Yield CPU
fn yield_cpu() {
    unsafe {
        syscall3(SYS_YIELD, 0, 0, 0);
    }
}

#[inline(never)]
fn exec(s: &str) -> i32 {
    unsafe {
        syscall3(SYS_EXEC, s.as_ptr() as u32, s.len() as u32, 0)
    }
}

/// Entry point
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write(b"Hello from init!\n");
    write(b"RetroOS userspace is running.\n");

    // Simple loop
    let mut counter = 0u32;
    loop {
        if counter % 1000000 == 0 {
            write(b".");
        }
        counter = counter.wrapping_add(1);
        if counter % 10000000 == 0 {
            if exec("printmsg.elf") != 0 {
                write(b"Exec failed\n");
            }
        }
    }
}

/// Panic handler
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write(b"PANIC in init!\n");
    exit(1);
}
