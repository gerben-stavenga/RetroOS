//! `hello` — minimal dosrt payload: ordinary `no_std` 32-bit ELF.
//!
//! Smoke test for the stub→RLOADER→payload chain. Uses only *register-only*
//! INT 21h calls (AH=02 putc in DL, AH=4Ch exit in AL) so the payload itself
//! needs **no** PM transfer-buffer shim — a DPMI host reflects these to
//! real-mode DOS unchanged. The real MOD player payload will later add its
//! own runtime shim for pointer-passing calls; that is deliberately out of
//! scope here so this proves *only* the loader chain.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[inline]
unsafe fn dos_putc(c: u8) {
    // INT 21h AH=02h — output char in DL. Register-only ⇒ DPMI host
    // reflects PM→RM with no pointer translation needed.
    unsafe {
    core::arch::asm!(
        "int 0x21",
        in("ah") 2u8,
        in("dl") c,
        lateout("ah") _,
        clobber_abi("C"),
    );
    }
}

#[inline]
fn dos_exit(code: u8) -> ! {
    unsafe {
        core::arch::asm!("int 0x21", in("ah") 0x4Cu8, in("al") code, options(noreturn));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    for &b in b"dosrt: hello from a Rust no_std ELF payload\r\n" {
        unsafe { dos_putc(b) };
    }
    dos_exit(0);
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    dos_exit(1);
}
