#![no_std]
#![no_main]

use core::arch::asm;

// Replace ourselves with the system shell: execve("/bin/sh", ["sh", NULL], env).
//
// no_std (no Rust std) keeps the binary free of std's SSE2/cmov codegen, so —
// like the i386 busybox it launches — it runs on the base 486 CPU (`--arch
// 386`), not only SSE2-capable ones. The musl C runtime (crt0 →
// __libc_start_main → main, all i386/SSE2-free) does the process setup.
//
// We do NOT forward the inherited env: when DN/COMMAND.COM launch us it's the
// DOS environment (PATH=C:\…, COMSPEC, BLASTER=…), which is meaningless to a
// Unix shell and makes a strict shell like dash bail ("sh: 0: …"). Hand the
// shell a clean Linux environment with a real PATH so binaries/applets resolve.
// argv[0]="sh" lets /bin/sh (busybox's sh applet, or a native dash/bash) dispatch.
#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let path = b"PATH=/usr/bin:/bin:/usr/sbin:/sbin\0";
    let home = b"HOME=/\0";
    let term = b"TERM=linux\0";
    let envp: [*const u8; 4] = [path.as_ptr(), home.as_ptr(), term.as_ptr(), core::ptr::null()];
    let argv: [*const u8; 2] = [b"sh\0".as_ptr(), core::ptr::null()];
    unsafe {
        asm!(
            "int 0x80",
            inout("eax") 11i32 => _,        // SYS_execve (i386)
            in("ebx") b"/bin/sh\0".as_ptr(),
            in("ecx") argv.as_ptr(),
            in("edx") envp.as_ptr(),
            options(nostack),
        );
    }
    127 // only reached if execve failed (e.g. /bin/sh missing)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
