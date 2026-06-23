#![no_std]
#![no_main]

use core::arch::asm;

// Replace ourselves with the system shell: execve("/bin/sh", ["sh", NULL], envp).
//
// no_std (no Rust std) keeps the binary free of std's SSE2/cmov codegen, so —
// like the i386 busybox it launches — it runs on the base 486 CPU (`--arch
// 386`), not only SSE2-capable ones. The musl C runtime (crt0 →
// __libc_start_main → main, all i386/SSE2-free) still does the process setup and
// hands us `envp`, which we forward so the shell inherits PATH etc. argv[0]="sh"
// lets /bin/sh (busybox's sh-applet symlink, or a native distro shell) dispatch.
#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, envp: *const *const u8) -> i32 {
    let argv: [*const u8; 2] = [b"sh\0".as_ptr(), core::ptr::null()];
    unsafe {
        asm!(
            "int 0x80",
            inout("eax") 11i32 => _,        // SYS_execve (i386)
            in("ebx") b"/bin/sh\0".as_ptr(),
            in("ecx") argv.as_ptr(),
            in("edx") envp,
            options(nostack),
        );
    }
    127 // only reached if execve failed (e.g. /bin/sh missing)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
