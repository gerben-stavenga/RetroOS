//! RLOADER — the single, system-shared, pure-protected-mode ELF loader.
//!
//! Entered by the stub's asm thunk *already in 32-bit PM* (the stub did the
//! real-mode DPMI bring-up). RLOADER never returns and never frees itself
//! (see README handoff contract). It:
//!   1. reads the appended payload ELF out of the app `.EXE` via the stub's
//!      open DOS handle, using DPMI `AX=0300` + the stub's conventional
//!      transfer buffer (same process ⇒ no DPMI DOS-mem alloc needed),
//!   2. parses it with `lib::elf`,
//!   3. allocates payload memory via INT 31h `AX=0501`,
//!   4. copies PT_LOADs / zeroes BSS / applies relocs,
//!   5. far-jumps the payload entry.
//!
//! Status: skeleton. ELF parse + segment copy via `lib::elf` is real; the
//! `AX=0300` read loop and the final far-jump are written to the DPMI
//! services in `kernel/src/kernel/dos/dpmi.rs` and need on-target debug.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use lib::elf::Elf;

/// Handoff struct location: the stub passes registers per the README
/// contract. We capture them in `_start` (naked-ish) and pass down.
#[repr(C)]
struct Handoff {
    file_handle: u16, // EBX: open DOS handle of the app .EXE
    elf_off: u32,     // ECX: byte offset of payload ELF within the .EXE
    dpmi_entry: u32,  // EDX: DPMI INT 31h entry (0 ⇒ host reflects int 0x31)
    xfer_seg: u16,    // ESI hi: real-mode segment of stub xfer buffer
    xfer_off: u16,    // ESI lo: real-mode offset of stub xfer buffer
    xfer_len: u32,    // EDI: xfer buffer length
}

/// Raw handoff registers, stashed by the `_start` shim exactly as the
/// stub's PM thunk left them (the shim runs before any prologue, so the
/// values are intact). `#[no_mangle]` so global_asm can name it.
#[unsafe(no_mangle)]
static mut HANDOFF: [u32; 5] = [0; 5]; // [EBX, ECX, EDX, ESI, EDI]

// BRING-UP _start: isolate "did the stub's 32-bit far-jmp land and run
// 32-bit code here?" — pure register-only `INT 21h` AH=02 print 'R'
// (DPMI-reflected, PM-safe, same principle as the stub's geninterrupt),
// then halt-loop. NO memory refs (so it's independent of DS/relocation
// correctness — that's the next layer). Restore the real handoff shim
// (stash regs -> rloader_main) once this proves the transfer works.
core::arch::global_asm!(
    ".section .text._start,\"ax\"",
    ".globl _start",
    "_start:",
    "mov ah, 0x02",
    "mov dl, 0x52",          // 'R'
    "int 0x21",
    "2: hlt",
    "jmp 2b",
);

#[unsafe(no_mangle)]
extern "C" fn rloader_main() -> ! {
    let r = unsafe { core::ptr::addr_of!(HANDOFF).read() };
    let h = Handoff {
        file_handle: r[0] as u16,        // EBX: app .EXE DOS handle
        elf_off: r[1],                   // ECX: payload ELF offset
        dpmi_entry: r[2],                // EDX: INT 31h entry (0 ⇒ reflect)
        xfer_seg: (r[3] >> 16) as u16,   // ESI hi: xfer buf real segment
        xfer_off: r[3] as u16,           // ESI lo: xfer buf real offset
        xfer_len: r[4],                  // EDI: xfer buf length
    };
    run(&h)
}

fn run(h: &Handoff) -> ! {
    // Scratch buffer for the payload ELF image. Sized generously; a real
    // build will size from the .EXE file length. Lives in RLOADER's .bss.
    static mut ELF_BUF: [u8; 1 << 20] = [0; 1 << 20];
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(ELF_BUF) };

    let n = read_payload(h, buf);
    let elf = match Elf::parse(&buf[..n]) {
        Ok(e) => e,
        Err(_) => fail(b'E'),
    };

    // Place each PT_LOAD at its p_paddr (payload.ld picks a fixed base;
    // RLOADER honours the program headers, like boot/src/lib.rs does).
    for seg in elf.segments() {
        let dst = seg.paddr as *mut u8;
        unsafe {
            if let Some(data) = seg.data {
                core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
                // zero BSS tail [filesz, memsz)
                let bss = seg.memsz.saturating_sub(data.len());
                core::ptr::write_bytes(dst.add(data.len()), 0, bss);
            } else {
                core::ptr::write_bytes(dst, 0, seg.memsz);
            }
        }
    }
    let entry = elf.entry() as u32;

    // TODO(bring-up): if the payload links PIE, apply R_386_RELATIVE here
    // (lib::elf exposes headers; reloc iteration to be added).

    // Far-jump into the payload. 32-bit flat client ⇒ a plain indirect
    // jmp suffices (CS already a 32-bit flat selector from DPMI enter).
    unsafe {
        core::arch::asm!("jmp {0}", in(reg) entry, options(noreturn));
    }
}

/// Read the payload ELF from the stub's open file handle into `buf` using
/// DPMI `AX=0300` (simulate real-mode INT 21h) bouncing through the stub's
/// conventional transfer buffer. Returns bytes read.
///
/// TODO(bring-up): fill the DPMI 0300h real-mode register frame
/// (`kernel/src/kernel/dos/dpmi.rs` AX=0300). Sequence per chunk:
///   - INT 21h AH=42h (lseek, register-only) to `h.elf_off + done`
///   - INT 21h AH=3Fh (read) with DS:DX = xfer buffer real seg:off,
///     CX = min(chunk, xfer_len), via AX=0300 frame
///   - copy linear(xfer_seg<<4 + xfer_off) → buf[done..] (PM flat)
fn read_payload(h: &Handoff, buf: &mut [u8]) -> usize {
    let _ = (h, &buf); // skeleton: see TODO above
    fail(b'R')
}

/// Emit one diagnostic char via register-only INT 21h AH=02h and hang.
fn fail(code: u8) -> ! {
    unsafe {
        core::arch::asm!("int 0x21", in("ah") 2u8, in("dl") code);
    }
    loop {
        unsafe { core::arch::asm!("hlt") }
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    fail(b'P')
}
