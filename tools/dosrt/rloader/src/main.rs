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
use lib::elf::{Elf, Elf32Dyn, Elf32Rel, DT_NULL, DT_REL, DT_RELSZ, R_386_RELATIVE};

// RLOADER's own crt. The stub built a 32-bit CODE selector over the
// RLOADER buffer (base = buf-0x1000) and far-called `_start` as
// `go(unsigned exh, unsigned long poff)`. Build a matching 32-bit DATA
// selector (alias of CS), load DS/ES, zero BSS, capture the far-call
// args off the stub's (still-current) 16-bit PM stack, switch to our
// own stack, then enter `rloader_main`. Register-only INT 31h until DS
// is valid. Distinct from a payload crt0: only RLOADER is handed a
// file handle.
core::arch::global_asm!(
    ".section .text.rloader_entry,\"ax\"",
    ".code32",
    ".globl rloader_entry",
    "rloader_entry:",
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
    "mov ax, 0x0009",                   // access: 32-bit data, P, DPL3, RW,
    "mov bx, bp",                       //   G=1 so limit 0xFFFFF means 4 GB
    "mov cx, 0xC0f2",                   //   (CWSDPMI: high byte clobbers G).
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
    // stack: go(unsigned exh, unsigned long poff, unsigned long arg_lin)
    // — cdecl, far CALL ⇒ [SP+0]=retIP(2) [SP+2]=retCS(2) [SP+4]=exh(2)
    // [SP+6]=poff(4) [SP+10]=arg_lin(4, already a linear addr). EBP-based
    // ⇒ SS-relative; SS is still the stub stack here. Zero-extend SP
    // (32-bit code, 16-bit stub stack ⇒ ESP-hi undefined).
    "xor ebp, ebp",
    "mov bp, sp",
    "movzx ecx, word ptr [ebp+4]",      // exh
    "mov [HOFF_H], cx",
    "mov esi, [ebp+6]",                 // poff
    "mov [HOFF_OFF], esi",
    "mov eax, [ebp+10]",                // argblk LINEAR addr (u32; stub
    "mov [HOFF_ARG], eax",              //   passes it directly, no seg<<4)
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
/// Linear address of the stub's command-tail (Borland `argv[1]`) string,
/// passed to the payload (ESI) so dosrt's `_start` builds `app_main`'s
/// args without the PSP/AH=62h path (empty for a PM client here).
#[unsafe(no_mangle)]
static mut HOFF_ARG: u32 = 0;

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
    // those args into HOFF_H / HOFF_OFF. Read only the ELF + program
    // headers into a tiny buffer; the PT_LOAD bytes are streamed directly
    // into the payload's allocation in `load_and_run`.
    {
        let handle = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(HOFF_H)) };
        let poff = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(HOFF_OFF)) };
        // Just headers — ELF header + program headers fit comfortably in
        // 1 KB. Payload section bytes are read straight into their final
        // home by `load_and_run`, so this buffer's size doesn't scale
        // with payload size.
        static mut ELFBUF: [u8; 0x400] = [0; 0x400];
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

        // Snapshot program headers into plain Copy locals; the parsed
        // `Elf` borrows `ELFBUF`, which we let drop before re-using the
        // disk for the streaming PT_LOAD reads.
        let mut segs = [Seg::default(); MAX_SEG];
        let mut nseg = 0usize;
        let entry;
        // PT_DYNAMIC's `(vaddr, memsz)` for a PIE payload; `(0, 0)` for a
        // plain ET_EXEC — the relocation pass then no-ops.
        let mut dyn_vaddr = 0u32;
        let mut dyn_size = 0u32;
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
                    foff: poff + s.file_offset as u32,
                    fsz: s.filesz as u32,
                };
                nseg += 1;
            }
            if let Some((dv, ds)) = e.dynamic() {
                dyn_vaddr = dv as u32;
                dyn_size = ds as u32;
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
        puts("\r\n");
        load_and_run(handle, &segs[..nseg], entry, dyn_vaddr, dyn_size);
    }
}

/// One PT_LOAD, snapshotted to plain Copy locals (no `Elf`/`static mut`
/// borrow held across the loader's later disk reads / inline asm).
/// `foff` is the absolute file offset of the segment's filesz bytes;
/// `fsz` is the filesz; `memsz - fsz` is the BSS tail to zero.
#[derive(Clone, Copy, Default)]
struct Seg { vaddr: u32, memsz: u32, foff: u32, fsz: u32 }

const MAX_SEG: usize = 8;

/// Give the payload its own DPMI memory + selectors, stream each PT_LOAD
/// from disk straight into its destination, zero BSS, then far-jump the
/// entry. The selector base = alloc_lin - min_vaddr (selector-base trick)
/// so the payload's link addresses resolve verbatim; limit is flat 4 GB.
/// Never returns.
#[inline(never)]
fn load_and_run(handle: u16, segs: &[Seg], entry: u32,
                dyn_vaddr: u32, dyn_size: u32) -> ! {
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
    // Payloads are PIE: their selectors are base=0 flat, and the
    // `R_386_RELATIVE` fixups (applied below) bias every absolute slot by
    // the load address. `load_bias = lin - min_v` is what the fixups add;
    // for a PIE linked at 0 that is just `lin`.
    let load_bias = lin.wrapping_sub(min_v);
    let code = dpmi::alloc_ldt();
    let data = dpmi::alloc_ldt();
    for s in [code, data] {
        dpmi::set_base(s, 0);
        dpmi::set_limit(s, 0xFFFF_FFFF);
    }
    // G=1 so the limit-field 0xFFFFF set above means 4 GB - 1, not 1 MB - 1.
    // (Our DPMI host's AX=0009 clobbers the G bit set by AX=0008.)
    dpmi::set_ar(code, 0xC0FA);          // 32-bit code, P, DPL3, exec/read, G=1
    dpmi::set_ar(data, 0xC0F2);          // 32-bit data, P, DPL3, RW, G=1

    puts("dosrt: load lin=");
    puthex32(lin);
    puts(" sz=");
    puthex32(size);
    puts(" bias=");
    puthex32(load_bias);
    puts("\r\n");

    // Stream each PT_LOAD straight from disk into payload memory.
    // RLOADER's own DS is 4 GB-flat (crt0 bumped it), so we can dereference
    // a linear address as a plain `*mut u8` after subtracting our DS base.
    let ds_base = dpmi::seg_base(dpmi::ds_sel());
    for s in segs {
        let dst_lin = lin + (s.vaddr - min_v);
        let dst = dst_lin.wrapping_sub(ds_base) as *mut u8;
        if s.fsz != 0 {
            dos::lseek(handle, s.foff);
            let dst_slice = unsafe {
                core::slice::from_raw_parts_mut(dst, s.fsz as usize)
            };
            let n = dos::read(handle, dst_slice);
            if n != s.fsz as usize { puts("dosrt: short read\r\n"); hang(); }
        }
        let zbytes = s.memsz - s.fsz;
        if zbytes != 0 {
            unsafe { core::ptr::write_bytes(dst.add(s.fsz as usize), 0, zbytes as usize); }
        }
    }

    // Apply PIE relocations: patch each `R_386_RELATIVE` slot by
    // `load_bias`. A plain ET_EXEC has no PT_DYNAMIC, `dyn_size == 0`,
    // and this is skipped.
    if dyn_size != 0 {
        let nreloc = apply_relocations(load_bias, ds_base, dyn_vaddr, dyn_size);
        puts("dosrt: relocs=");
        puthex32(nreloc);
        puts("\r\n");
    }

    // Payload selectors are base=0 flat, so SS:ESP and CS:EIP are plain
    // linear addresses. Stack grows down from the top of the allocation;
    // the entry vaddr is biased onto the load address.
    let sp_top = lin + size;
    let entry_lin = load_bias.wrapping_add(entry);
    puts("dosrt: jmp payload\r\n");
    // The SS/ESP/segment-reg/retf transfer MUST NOT be inline asm inside
    // this function: rewriting SS:ESP and never-returning is UB the -Oz
    // optimizer spreads over the whole fn, corrupting the pure size math
    // above. It lives in a dedicated global_asm symbol (like crt0), fed
    // the already-computed values.
    let arg = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(HOFF_ARG)) };
    unsafe { enter_payload(code as u32, data as u32, sp_top, entry_lin, arg) }
}

/// Walk the payload's `.dynamic` table (already streamed into memory at
/// `base + dyn_vaddr`), find the `.rel.dyn` REL table via DT_REL/DT_RELSZ,
/// and add the load bias `base` to every `R_386_RELATIVE` slot. All
/// addresses are linear; RLOADER's DS is 4 GB-flat with base `ds_base`,
/// so a linear `X` is dereferenced as the pointer `X - ds_base`. Returns
/// the number of relocations applied.
fn apply_relocations(base: u32, ds_base: u32, dyn_vaddr: u32, dyn_size: u32) -> u32 {
    let dyn_ptr = (base.wrapping_add(dyn_vaddr).wrapping_sub(ds_base)) as *const Elf32Dyn;
    let mut rel_off = 0u32;
    let mut rel_sz = 0u32;
    for i in 0..(dyn_size as usize / core::mem::size_of::<Elf32Dyn>()) {
        let d = unsafe { *dyn_ptr.add(i) };
        match d.tag {
            DT_NULL => break,
            DT_REL => rel_off = d.val,
            DT_RELSZ => rel_sz = d.val,
            _ => {}
        }
    }
    if rel_sz == 0 { return 0; }
    let rel_ptr = (base.wrapping_add(rel_off).wrapping_sub(ds_base)) as *const Elf32Rel;
    let mut applied = 0u32;
    for i in 0..(rel_sz as usize / core::mem::size_of::<Elf32Rel>()) {
        let r = unsafe { *rel_ptr.add(i) };
        if r.r_type() == R_386_RELATIVE {
            let slot = (base.wrapping_add(r.r_offset).wrapping_sub(ds_base)) as *mut u32;
            unsafe { *slot = (*slot).wrapping_add(base); }
            applied += 1;
        }
    }
    applied
}

// Final far-transfer into the payload. A real asm symbol (cdecl args on
// RLOADER's stack), NOT inline asm in a Rust fn — so the SS:ESP switch
// and `retf` can't poison optimizer codegen for the loader.
core::arch::global_asm!(
    ".section .text._enter_payload,\"ax\"",
    ".code32",
    ".globl enter_payload",
    "enter_payload:",
    "mov ecx, [esp+4]",                  // arg0: code selector
    "mov edx, [esp+8]",                  // arg1: data selector
    "mov eax, [esp+12]",                 // arg2: sp_top
    "mov ebx, [esp+16]",                 // arg3: entry
    "mov esi, [esp+20]",                 // arg4: arg_lin (→ dosrt _start)
    "mov ss, dx",
    "mov esp, eax",                      // (mov-ss shadow covers next insn)
    "mov ds, dx",
    "mov es, dx",
    "push ecx",                          // CS
    "push ebx",                          // EIP
    "retf",                              // -> code:entry, ESI = arg_lin
);

unsafe extern "C" {
    fn enter_payload(code: u32, data: u32, sp_top: u32, entry: u32, arg_lin: u32) -> !;
}

fn hang() -> ! {
    loop {
        unsafe { core::arch::asm!("hlt") }
    }
}
