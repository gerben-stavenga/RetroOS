//! `dosrt` — the shared Rust-on-DOS runtime *library*.
//!
//! A `no_std` library of the universal pieces: a console, the DPMI
//! services (sim-int, descriptor/memory alloc), and a small DOS libc.
//! It deliberately has **no `_start`** — entry/crt is per-program,
//! because the entry contracts differ: RLOADER is entered by the stub
//! *with a far-call (handle, offset)* and owns its own crt (it loads and
//! calls the payload); a payload is entered by RLOADER and owns its own
//! crt0. Both link this library for `dpmi`/`dos`/console.

#![no_std]

use core::panic::PanicInfo;

/// Minimal dosrt console: register-only INT 21h, DPMI-reflected (PM-safe;
/// not the TC int86 library, which #GPs in PM).
pub fn putc(c: u8) {
    unsafe { core::arch::asm!("int 0x21", in("ah") 2u8, in("dl") c) }
}
pub fn puts(s: &str) {
    for &b in s.as_bytes() { putc(b) }
}
pub fn puthex8(v: u8) {
    let h = b"0123456789ABCDEF";
    putc(h[(v >> 4) as usize]);
    putc(h[(v & 0xF) as usize]);
}
pub fn puthex32(v: u32) {
    let mut i = 4;
    while i > 0 { i -= 1; puthex8((v >> (i * 8)) as u8); }
}

/// dosrt DPMI layer: the PM-safe primitive for pointer-passing INT 21h.
/// We're a 32-bit DPMI client; the host does NOT translate pointers on
/// reflected INTs. `AX=0300` (simulate real-mode interrupt) runs the INT
/// with a real-mode register frame (RMCS). Our own data is conventional
/// memory (<1 MB), so the transfer buffer is just a static whose real-
/// mode seg:off we derive from DS's linear base (no AX=0100).
pub mod dpmi {
    /// DPMI 0.9 Real Mode Call Structure (0x32 bytes, packed).
    #[repr(C, packed)]
    #[derive(Default, Clone, Copy)]
    pub struct Rmcs {
        pub edi: u32, pub esi: u32, pub ebp: u32, pub _rsv: u32,
        pub ebx: u32, pub edx: u32, pub ecx: u32, pub eax: u32,
        pub flags: u16,
        pub es: u16, pub ds: u16, pub fs: u16, pub gs: u16,
        pub ip: u16, pub cs: u16, pub sp: u16, pub ss: u16,
    }

    /// INT 31h AX=0006: linear base of a selector. Returns CX:DX base.
    pub fn seg_base(sel: u16) -> u32 {
        let (cx, dx): (u16, u16);
        unsafe {
            core::arch::asm!(
                "int 0x31",
                in("ax") 0x0006u16, in("bx") sel,
                lateout("cx") cx, lateout("dx") dx,
                clobber_abi("C"),
            );
        }
        ((cx as u32) << 16) | (dx as u32)
    }

    /// Current DS selector value.
    pub fn ds_sel() -> u16 {
        let s: u16;
        unsafe { core::arch::asm!("mov {0:x}, ds", out(reg) s) };
        s
    }

    /// INT 31h AX=0000: allocate one LDT descriptor. Returns its selector.
    pub fn alloc_ldt() -> u16 {
        let sel: u16;
        unsafe {
            core::arch::asm!(
                "int 0x31",
                in("ax") 0x0000u16, in("cx") 1u16,
                lateout("ax") sel,
                clobber_abi("C"),
            );
        }
        sel
    }

    /// INT 31h AX=0007: set selector linear base.
    pub fn set_base(sel: u16, base: u32) {
        unsafe {
            core::arch::asm!(
                "int 0x31",
                in("ax") 0x0007u16, in("bx") sel,
                in("cx") (base >> 16) as u16, in("dx") base as u16,
                clobber_abi("C"),
            );
        }
    }

    /// INT 31h AX=0008: set selector limit (host picks granularity).
    pub fn set_limit(sel: u16, limit: u32) {
        unsafe {
            core::arch::asm!(
                "int 0x31",
                in("ax") 0x0008u16, in("bx") sel,
                in("cx") (limit >> 16) as u16, in("dx") limit as u16,
                clobber_abi("C"),
            );
        }
    }

    /// INT 31h AX=0009: set selector access rights (CX = rights word).
    pub fn set_ar(sel: u16, ar: u16) {
        unsafe {
            core::arch::asm!(
                "int 0x31",
                in("ax") 0x0009u16, in("bx") sel, in("cx") ar,
                clobber_abi("C"),
            );
        }
    }

    /// INT 31h AX=0501: allocate a memory block (`size` bytes). Returns
    /// its linear address, or `None` on failure. The block handle (SI:DI)
    /// is dropped — dosrt programs never free (process exit reclaims).
    pub fn alloc_mem(size: u32) -> Option<u32> {
        let (bx, cx): (u16, u16);
        let cf: u16;
        unsafe {
            core::arch::asm!(
                "int 0x31",
                "setc dl",            // CF -> DL (DX captured as u16)
                in("ax") 0x0501u16,
                in("bx") (size >> 16) as u16, in("cx") size as u16,
                lateout("bx") bx, lateout("cx") cx, out("dx") cf,
                clobber_abi("C"),
            );
        }
        if cf & 1 != 0 { None } else { Some(((bx as u32) << 16) | cx as u32) }
    }

    /// INT 31h AX=0300: simulate a real-mode interrupt. `r` is filled
    /// by the caller (RM register frame) and updated with results.
    /// ES:EDI points the host at the RMCS (PM memory — ES already = DS
    /// from crt0; EDI = the struct's address in our flat data).
    pub fn sim_int(int_no: u8, r: &mut Rmcs) {
        let p = r as *mut Rmcs as u32;
        unsafe {
            // edi can't be an asm operand (LLVM-reserved) — load it
            // inside. ES already = DS (crt0), so ES:EDI -> RMCS.
            core::arch::asm!(
                "mov edi, {p:e}",
                "int 0x31",
                p = in(reg) p,
                in("ax") 0x0300u16,
                in("bx") int_no as u16,   // BL=int#, BH=0
                in("cx") 0u16,            // no PM-stack copy
                out("edi") _,
                clobber_abi("C"),
            );
        }
    }
}

/// dosrt libc: DOS file I/O via INT 21h through `dpmi::sim_int` + one
/// conventional transfer buffer (a static; its real-mode seg:off is
/// derived from DS's linear base). Reusable by RLOADER and payloads.
pub mod dos {
    use super::dpmi::{self, Rmcs};

    const XFER_LEN: usize = 4096;
    static mut XFER: [u8; XFER_LEN] = [0; XFER_LEN];

    /// (real-mode segment, offset) of XFER. off < 16.
    fn xfer_segoff() -> (u16, u16) {
        let xb = core::ptr::addr_of_mut!(XFER) as u32;
        let lin = dpmi::seg_base(dpmi::ds_sel()) + xb;
        ((lin >> 4) as u16, (lin & 0x0F) as u16)
    }
    fn xfer_ptr() -> *mut u8 { core::ptr::addr_of_mut!(XFER) as *mut u8 }

    /// INT 21h AH=3Dh open, AL=0 read-only. `path` must be NUL-terminated.
    pub fn open(path: &[u8]) -> Option<u16> {
        let (seg, off) = xfer_segoff();
        unsafe {
            let xb = xfer_ptr();
            let mut i = 0;
            while i < path.len() && i < XFER_LEN { *xb.add(i) = path[i]; i += 1; }
        }
        let mut r = Rmcs::default();
        r.eax = 0x3D00;
        r.ds = seg; r.edx = off as u32;
        dpmi::sim_int(0x21, &mut r);
        let cf = r.flags & 1;
        if cf != 0 { None } else { Some(r.eax as u16) }
    }

    /// INT 21h AH=3Fh read, chunked through XFER. Returns bytes read.
    pub fn read(handle: u16, buf: &mut [u8]) -> usize {
        let (seg, off) = xfer_segoff();
        let mut done = 0usize;
        while done < buf.len() {
            let want = core::cmp::min(buf.len() - done, XFER_LEN) as u16;
            let mut r = Rmcs::default();
            r.eax = 0x3F00;
            r.ebx = handle as u32;
            r.ecx = want as u32;
            r.ds = seg; r.edx = off as u32;
            dpmi::sim_int(0x21, &mut r);
            if r.flags & 1 != 0 { break; }            // CF -> error
            let got = r.eax as u16 as usize;
            if got == 0 { break; }                    // EOF
            unsafe {
                let xb = xfer_ptr();
                let mut i = 0;
                while i < got { buf[done + i] = *xb.add(i); i += 1; }
            }
            done += got;
            if got < want as usize { break; }         // short read = EOF
        }
        done
    }

    /// INT 21h AH=42h lseek, AL=0 (SEEK_SET). Register-only.
    pub fn lseek(handle: u16, pos: u32) {
        let mut r = Rmcs::default();
        r.eax = 0x4200;
        r.ebx = handle as u32;
        r.ecx = pos >> 16;
        r.edx = pos & 0xFFFF;
        dpmi::sim_int(0x21, &mut r);
    }

    /// INT 21h AH=3Eh close.
    pub fn close(handle: u16) {
        let mut r = Rmcs::default();
        r.eax = 0x3E00;
        r.ebx = handle as u32;
        dpmi::sim_int(0x21, &mut r);
    }

    /// INT 21h AH=4Ch exit (register-only; reflects directly).
    pub fn exit(code: u8) -> ! {
        unsafe { core::arch::asm!("int 0x21", in("ax") 0x4C00u16 | code as u16) }
        loop { unsafe { core::arch::asm!("hlt") } }
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    putc(b'P');
    loop { unsafe { core::arch::asm!("hlt") } }
}
