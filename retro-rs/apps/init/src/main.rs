//! Init process for RetroOS
//!
//! Forks and execs the stress test. Respawns when it exits.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

const SYS_EXIT: u32 = 0;
const SYS_YIELD: u32 = 1;
const SYS_FORK: u32 = 4;
const SYS_EXEC: u32 = 5;
const SYS_WAIT: u32 = 7;
const SYS_WRITE: u32 = 9;

#[inline(always)]
unsafe fn syscall(num: u32, a0: u32, a1: u32, a2: u32, a3: u32) -> i32 {
    let result: i32;
    unsafe { core::arch::asm!(
        "push esi",
        "mov esi, {a3:e}",
        "int 0x80",
        "pop esi",
        inout("eax") num => result,
        in("edx") a0,
        in("ecx") a1,
        in("ebx") a2,
        a3 = in(reg) a3,
    ); }
    result
}

fn write(s: &[u8]) -> i32 {
    unsafe { syscall(SYS_WRITE, 1, s.as_ptr() as u32, s.len() as u32, 0) }
}

fn exit(code: i32) -> ! {
    unsafe { syscall(SYS_EXIT, code as u32, 0, 0, 0); }
    loop {}
}

fn fork() -> i32 {
    unsafe { syscall(SYS_FORK, 0, 0, 0, 0) }
}

fn exec(path: &str, args: &[&str]) -> i32 {
    unsafe { syscall(SYS_EXEC, path.as_ptr() as u32, path.len() as u32,
                     args.as_ptr() as u32, args.len() as u32) }
}

fn yield_cpu() {
    unsafe { syscall(SYS_YIELD, 0, 0, 0, 0); }
}

fn waitpid(pid: i32) -> i32 {
    loop {
        let r = unsafe { syscall(SYS_WAIT, pid as u32, 0, 0, 0) };
        if r != 0x7fff_ffff { return r; }
        yield_cpu();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write(b"RetroOS init\n");

    loop {
        write(b"[init] spawning stress test...\n");
        let pid = fork();
        if pid == 0 {
            exec("stress.elf", &["stress.elf", "3"]);
            write(b"exec failed\n");
            exit(1);
        }
        waitpid(pid);
        write(b"[init] stress test exited, respawning\n");
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write(b"PANIC in init!\n");
    exit(1);
}
