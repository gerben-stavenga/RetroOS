//! RLOADER — the shared 32-bit DOS loader.
//!
//! RLOADER is *not* a generic dosrt program: the stub enters it via a
//! far-call carrying `(exe_handle, payload_off)`, so it owns its own crt
//! (`_start`, below). It links the `dosrt` crate only as a *library*
//! (console / DPMI / DOS libc). Job: read the payload ELF appended to
//! our own `.EXE`, parse it (`lib::elf`), give it its own DPMI memory +
//! selectors, copy PT_LOADs, and far-jump the payload — which then runs
//! under its own crt0.

#![no_std]
#![no_main]

use dosrt::{dos, dpmi, putc, puthex32, puthex8, puts};
use lib::elf::Elf;

/// RLOADER's own crt. The stub built a 32-bit CODE selector over the
/// RLOADER buffer (base = buf-0x1000) and far-called `_start` as
/// `go(unsigned exh, unsigned long poff)`. Build a matching 32-bit DATA
/// selector (alias of CS), load DS/ES, zero BSS, capture the far-call
/// args off the stub's (still-current) 16-bit PM stack, switch to our
/// own stack, then enter `rloader_main`. Register-only INT 31h until DS
/// is valid. Distinct from a payload crt0: only RLOADER is handed a
/// file handle.
core::arch::global_asm!(
    ".section .text._start,\"ax\"",
    ".code32",
    ".globl _start",
    "_start:",
    "mov bx, cs",                       // CS selector
    "mov ax, 0x0006",                   // DPMI get-segment-base -> CX:DX
    "int 0x31",
    "mov si, cx",                       // ESI = CS linear base
    "shl esi, 16",
    "mov si, dx",
    "mov ax, 0x0000",                   // alloc 1 LDT descriptor -> AX
    "mov cx, 1",
    "int 0x31",
    "mov bp, ax",                       // BP = new data selector
    "mov ax, 0x0007",                   // set base = ESI
    "mov bx, bp",
    "mov edx, esi",                     // DX = base[15:0]
    "mov ecx, esi",
    "shr ecx, 16",                      // CX = base[31:16]
    "int 0x31",
    "mov ax, 0x0008",                   // set limit = 0x000FFFFF (1 MB)
    "mov bx, bp",
    "mov cx, 0x000f",
    "mov dx, 0xffff",
    "int 0x31",
    "mov ax, 0x0009",                   // access: 32-bit data, P, DPL3, RW
    "mov bx, bp",
    "mov cx, 0x40f2",
    "int 0x31",
    "mov ax, bp",                       // DS/ES = data sel; keep sel in EBX
    "mov ds, ax",
    "mov es, ax",
    "movzx ebx, bp",                    // EBX = data selector (for SS later)
    "mov edi, offset __bss_start",      // zero BSS (DS valid; stub stack
    "mov ecx, offset __bss_end",        //   still current — args intact)
    "sub ecx, edi",
    "xor al, al",
    "cld",
    "rep stosb",
    // Capture the stub's far-call args off its (still-current) 16-bit PM
    // stack: go(unsigned exh, unsigned long poff) — cdecl, far CALL ⇒
    // [SP+0]=retIP(2) [SP+2]=retCS(2) [SP+4]=exh(2) [SP+6]=poff(4).
    // EBP-based ⇒ SS-relative; SS is still the stub stack here. Zero-
    // extend SP (32-bit code, 16-bit stub stack ⇒ ESP-hi undefined).
    "xor ebp, ebp",
    "mov bp, sp",
    "movzx ecx, word ptr [ebp+4]",      // exh
    "mov [HOFF_H], cx",
    "mov esi, [ebp+6]",                 // poff
    "mov [HOFF_OFF], esi",
    // Switch to RLOADER's own stack and enter the loader.
    "mov ss, bx",
    "mov esp, offset RLOADER_STACK + 0x4000",
    "call rloader_main",
    "1: hlt",
    "jmp 1b",
);

/// Stub→RLOADER handoff, captured by RLOADER's crt from the far-call
/// stack: `HOFF_H` = the `.EXE` DOS file handle, `HOFF_OFF` = byte
/// offset of the appended payload ELF within the `.EXE`.
#[unsafe(no_mangle)]
static mut HOFF_H: u16 = 0;
#[unsafe(no_mangle)]
static mut HOFF_OFF: u32 = 0;

/// RLOADER crt's stack (BSS). 16 KB; ESP starts at the top.
#[unsafe(no_mangle)]
static mut RLOADER_STACK: [u8; 0x4000] = [0; 0x4000];

#[unsafe(no_mangle)]
extern "C" fn rloader_main() -> ! {
    // Prove crt0: a data round-trip through a `static mut` (DATA selector
    // + addressing) and the entry call itself (the stack).
    static mut MARK: u32 = 0;
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(MARK), 0xC0DE_F00D);
        let v = core::ptr::read_volatile(core::ptr::addr_of!(MARK));
        puts("\r\ndosrt: crt0 ");
        putc(if v == 0xC0DE_F00D { b'K' } else { b'X' }); // K=ok, X=broken
        putc(b'\r');
        putc(b'\n');
    }

    // Prove the DPMI sim-int primitive: print a $-string via INT 21h
    // AH=09 through AX=0300 (exercises AX=0300 + the seg:off derivation
    // + RMCS layout — the basis for the libc).
    {
        static mut XFER: [u8; 32] = [0; 32];
        let msg = b"dosrt: simint OK\r\n$";
        unsafe {
            let xb = core::ptr::addr_of_mut!(XFER) as *mut u8;
            let mut i = 0;
            while i < msg.len() { *xb.add(i) = msg[i]; i += 1; }
            let lin = dpmi::seg_base(dpmi::ds_sel()) + xb as u32;
            let mut r = dpmi::Rmcs::default();
            r.eax = 0x0900;                       // AH=09 print $-string
            r.ds = (lin >> 4) as u16;             // DS = paragraph
            r.edx = lin & 0x0F;                   // DX = offset (<16)
            dpmi::sim_int(0x21, &mut r);
        }
    }

    // Pull the appended payload ELF out of our own .EXE. The stub
    // open()ed the .EXE and far-called us as go(exh, poff); crt0 captured
    // those args into HOFF_H / HOFF_OFF. lseek+read it, parse via
    // lib::elf.
    {
        let handle = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(HOFF_H)) };
        let poff = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(HOFF_OFF)) };
        static mut ELFBUF: [u8; 0x2000] = [0; 0x2000];
        dos::lseek(handle, poff);
        let nread = {
            let eb = unsafe { &mut *core::ptr::addr_of_mut!(ELFBUF) };
            dos::read(handle, eb)
        };
        puts("dosrt: payload h=");
        puthex8(handle as u8);
        puts(" off=");
        puthex32(poff);
        puts(" n=");
        puthex32(nread as u32);

        // Snapshot the program headers into plain Copy locals *before*
        // any DPMI/selector/asm work. Holding the `Elf` borrow (which
        // raw-casts into the `static mut ELFBUF`) live across the inline
        // asm that touches memory the compiler can't model is aliasing
        // UB — under -Oz it let the optimizer reorder the pure size math
        // (the `sz=0x50` instability). `src` is a linear addr into the
        // (still-live) static; the copy reads it via raw asm, no borrow.
        let mut segs = [Seg::default(); MAX_SEG];
        let mut nseg = 0usize;
        let entry;
        {
            let buf: &[u8] = unsafe { &*core::ptr::addr_of!(ELFBUF) };
            let e = match Elf::parse(&buf[..nread]) {
                Ok(e) => e,
                Err(_) => { puts(" PARSE FAIL\r\n"); hang(); }
            };
            entry = e.entry() as u32;
            for s in e.segments() {
                if nseg >= MAX_SEG { break; }
                segs[nseg] = Seg {
                    vaddr: s.vaddr as u32,
                    memsz: s.memsz as u32,
                    src: s.data.map(|d| d.as_ptr() as u32).unwrap_or(0),
                    fsz: s.data.map(|d| d.len() as u32).unwrap_or(0),
                };
                nseg += 1;
            }
        }
        puts(" entry=");
        puthex32(entry);
        puts(" nseg=");
        puthex8(nseg as u8);
        puts(" v=");
        puthex32(segs[0].vaddr);
        puts(" m=");
        puthex32(segs[0].memsz);
        puts(" f=");
        puthex32(segs[0].fsz);
        puts(" s=");
        puthex32(segs[0].src);
        puts("\r\n");
        load_and_run(&segs[..nseg], entry);
    }
}

/// One PT_LOAD, snapshotted to plain Copy locals (no `Elf`/`static mut`
/// borrow held across the loader's inline asm). `src` is the linear
/// address of the file bytes inside our still-live ELF buffer.
#[derive(Clone, Copy, Default)]
struct Seg { vaddr: u32, memsz: u32, src: u32, fsz: u32 }

const MAX_SEG: usize = 8;

/// Give the payload its own DPMI memory + selectors, copy PT_LOADs, zero
/// BSS, then far-jump its entry. The selector base = alloc_lin -
/// min_vaddr (selector-base trick) so the payload's link addresses
/// resolve verbatim; limit is flat 4 GB. Never returns.
#[inline(never)]
fn load_and_run(segs: &[Seg], entry: u32) -> ! {
    // Span [min_vaddr, max_end) over all PT_LOADs.
    let mut min_v = u32::MAX;
    let mut max_e = 0u32;
    for s in segs {
        if s.vaddr < min_v { min_v = s.vaddr; }
        let end = s.vaddr + s.memsz;
        if end > max_e { max_e = end; }
    }
    if min_v == u32::MAX { puts("dosrt: no PT_LOAD\r\n"); hang(); }

    const STACK: u32 = 0x4000;
    let span = (max_e - min_v + 0xFFF) & !0xFFF;
    // black_box: keep the size computation from being sunk/reordered
    // past the alloc+copy by the optimizer.
    let size = core::hint::black_box(span + STACK);

    let lin = match dpmi::alloc_mem(size) {
        Some(l) => l,
        None => { puts("dosrt: AX=0501 FAIL\r\n"); hang(); }
    };
    // selector-base trick: base + p_vaddr == lin + (p_vaddr - min_v)
    let base = lin.wrapping_sub(min_v);
    let code = dpmi::alloc_ldt();
    let data = dpmi::alloc_ldt();
    for s in [code, data] {
        dpmi::set_base(s, base);
        dpmi::set_limit(s, 0xFFFF_FFFF);
    }
    dpmi::set_ar(code, 0x40FA);          // 32-bit code, P, DPL3, exec/read
    dpmi::set_ar(data, 0x40F2);          // 32-bit data, P, DPL3, RW

    puts("dosrt: load lin=");
    puthex32(lin);
    puts(" sz=");
    puthex32(size);
    puts(" base=");
    puthex32(base);
    puts("\r\n");

    // Copy each PT_LOAD into the payload image (dest = data:p_vaddr,
    // src = our ELF buffer, addressed via DS), then zero the BSS tail.
    // ES = payload data selector for the duration; DS stays ours.
    for s in segs {
        let dst = s.vaddr;                    // selector-relative offset
        if s.fsz != 0 {
            unsafe {
                core::arch::asm!(
                    "push esi",              // esi can't even be a clobber
                    "mov es, {sel:x}",       //   (LLVM-reserved) — save it
                    "mov esi, {src:e}",
                    "mov edi, {dst:e}",
                    "cld",
                    "rep movsb",             // ES:EDI <- DS:ESI (DS = ours)
                    "pop esi",
                    sel = in(reg) data,
                    src = in(reg) s.src,
                    dst = in(reg) dst,
                    in("ecx") s.fsz,
                    out("edi") _, lateout("ecx") _,
                );
            }
        }
        let zbytes = s.memsz - s.fsz;
        if zbytes != 0 {
            unsafe {
                core::arch::asm!(
                    "mov es, {sel:x}",       // ES = payload data sel
                    "mov edi, {dst:e}",      // edi LLVM-reserved as operand
                    "cld",
                    "xor al, al",
                    "rep stosb",             // zero ES:EDI (BSS tail)
                    sel = in(reg) data,
                    dst = in(reg) dst + s.fsz,
                    in("ecx") zbytes,
                    out("edi") _, lateout("ecx") _, out("al") _,
                );
            }
        }
    }

    let sp_top = min_v + size;               // selector-relative; grows down
    puts("dosrt: jmp payload\r\n");
    // The SS/ESP/segment-reg/retf transfer MUST NOT be inline asm inside
    // this function: rewriting SS:ESP and never-returning is UB the -Oz
    // optimizer spreads over the whole fn, corrupting the pure size math
    // above. It lives in a dedicated global_asm symbol (like crt0), fed
    // the already-computed values.
    unsafe { enter_payload(code as u32, data as u32, sp_top, entry) }
}

/// Final far-transfer into the payload. A real asm symbol (cdecl args on
/// RLOADER's stack), NOT inline asm in a Rust fn — so the SS:ESP switch
/// and `retf` can't poison optimizer codegen for the loader.
core::arch::global_asm!(
    ".section .text._enter_payload,\"ax\"",
    ".code32",
    ".globl enter_payload",
    "enter_payload:",
    "mov ecx, [esp+4]",                  // arg0: code selector
    "mov edx, [esp+8]",                  // arg1: data selector
    "mov eax, [esp+12]",                 // arg2: sp_top
    "mov ebx, [esp+16]",                 // arg3: entry
    "mov ss, dx",
    "mov esp, eax",                      // (mov-ss shadow covers next insn)
    "mov ds, dx",
    "mov es, dx",
    "push ecx",                          // CS
    "push ebx",                          // EIP
    "retf",                              // -> code:entry
);

unsafe extern "C" {
    fn enter_payload(code: u32, data: u32, sp_top: u32, entry: u32) -> !;
}

fn hang() -> ! {
    loop {
        unsafe { core::arch::asm!("hlt") }
    }
}
