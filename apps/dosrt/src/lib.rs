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

extern crate alloc;

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

    /// INT 31h AX=0100: allocate a DOS (conventional, <1 MB) memory
    /// block. `paras` = 16-byte paragraphs. Returns `(rm_segment,
    /// pm_selector)` — the segment for real-mode INT 21h pointers, the
    /// selector to access the block from protected mode. The 8237/INT 21h
    /// transfer buffer MUST come from here: a payload's own image is
    /// AX=0501 (extended) memory, not real-mode addressable.
    pub fn alloc_dos_mem(paras: u16) -> Option<(u16, u16)> {
        let (ax, dx): (u16, u16);
        let cf: u16;
        unsafe {
            core::arch::asm!(
                "int 0x31",
                "setc cl",                 // CF -> CL (CX captured as u16)
                in("ax") 0x0100u16, in("bx") paras,
                lateout("ax") ax, lateout("dx") dx, out("cx") cf,
                clobber_abi("C"),
            );
        }
        if cf & 1 != 0 { None } else { Some((ax, dx)) }
    }

    /// INT 31h AX=0205: install a PM hardware-interrupt handler at
    /// vector `vec`. `sel:offset` is our handler. Returns Ok on success
    /// (CF=0); Err(ax) on failure.
    pub fn set_pm_int(vec: u8, sel: u16, offset: u32) -> Result<(), u16> {
        let ax: u16;
        let cf: u16;
        unsafe {
            core::arch::asm!(
                "mov edx, {off:e}",   // EDX = handler offset
                "int 0x31",
                "setc dl",            // DL = CF (DX captured as u16)
                off = in(reg) offset,
                in("ax") 0x0205u16,
                in("bx") vec as u16,  // BL = interrupt #, BH = 0
                in("cx") sel,
                lateout("ax") ax,
                lateout("dx") cf,
                clobber_abi("C"),
            );
        }
        if cf & 1 != 0 { Err(ax) } else { Ok(()) }
    }

    /// INT 31h AX=0300: simulate a real-mode interrupt. `r` is the RMCS,
    /// pointed at by `ES:EDI`. Do NOT assume a global `ES == DS` invariant
    /// — any code that touched ES (e.g. the conv-buffer copy) would break
    /// this. Set `ES = DS` here, at the single point that needs it.
    pub fn sim_int(int_no: u8, r: &mut Rmcs) {
        let p = r as *mut Rmcs as u32;
        unsafe {
            // edi can't be an asm operand (LLVM-reserved) — load it
            // inside. Force ES = DS so ES:EDI -> the RMCS in our data.
            core::arch::asm!(
                "push ds",                // ES = DS without a GP reg — a
                "pop es",                 //   scratch could clobber {p}
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

    // --- PM interrupt-handler installation --------------------------------
    //
    // A DPMI host enters a PM interrupt handler on a *locked* stack of
    // its own (DPMI 0.9 §1.8.2); that stack's SS need not be flat —
    // CWSDPMI runs handlers on its own `g_pdata` segment (base = the
    // host's data, not 0). Rust/LLVM flat-model codegen assumes
    // `SS.base == DS.base`, so a handler that takes the address of a
    // stack local forms an SS-relative offset and dereferences it
    // through our flat DS, missing. Every handler therefore runs on
    // dosrt's own flat interrupt stack; the per-vector→flat-stack switch
    // is the DOS-extender's job, what DJGPP's go32 does over CWSDPMI, so
    // a dosrt app's handlers work under any DPMI host.

    /// Per-vector handler table, indexed directly by interrupt vector.
    static mut HANDLERS: [Option<unsafe extern "C" fn()>; 256] = [None; 256];

    /// Flat stack every handler runs on (see the section comment above).
    const INT_STACK_SIZE: usize = 0x4000;
    static mut INT_STACK: [u8; INT_STACK_SIZE] = [0; INT_STACK_SIZE];

    /// Linear top-of-`INT_STACK`, filled by `install_handler` — PIE: the
    /// buffer address is only known after load-time relocation, so the
    /// asm reads it here instead of taking an `offset`.
    #[unsafe(no_mangle)]
    static mut INT_STACK_TOP: u32 = 0;

    /// Stride between entries in `dosrt_int_stubs`. Each stub is a
    /// 2-byte `push imm8` + a `jmp` (≤5 bytes), ≤7 total; `.p2align 3`
    /// rounds each to 8, so stub `v` is `dosrt_int_stubs + 8*v`.
    const STUB_STRIDE: usize = 8;

    unsafe extern "C" {
        // An asm label, declared as a byte so its address can be taken
        // without a function-pointer cast.
        static dosrt_int_stubs: u8;
    }

    // One stub per IDT vector (256), then the shared trampoline. Stub
    // `v` pushes `v` and jumps to `dosrt_int_common`. The push is kept
    // to the 2-byte `imm8` form by sign-extending `v` into [-128, 127]
    // (`(v ^ 128) - 128`) — the dispatcher reads only the low byte, so
    // pushing the negative imm8 for v ≥ 128 is equivalent and keeps
    // every stub ≤7 bytes, giving a uniform 8-byte `.p2align 3` stride.
    // `dosrt_int_common` preserves everything, loads our flat DS/ES,
    // parks the host SS:ESP in callee-saved EBX/ESI, switches SS:ESP
    // onto the flat interrupt stack, calls the dispatcher with the
    // vector, restores SS:ESP from EBX/ESI (the C ABI guarantees the
    // call preserves them), and `iretd`s. The `cs:[...]` reads reach our
    // statics through CS (CS & DS share base); the `mov ss` / `mov esp`
    // pairs sit in the mov-ss interrupt shadow.
    core::arch::global_asm!(
        ".section .text.dosrt_int,\"ax\"",
        ".code32",
        ".globl dosrt_int_stubs",
        ".p2align 3",
        "dosrt_int_stubs:",
        ".set vec, 0",
        ".rept 256",
        "  push ((vec ^ 128) - 128)",
        "  jmp dosrt_int_common",
        "  .p2align 3",
        "  .set vec, vec + 1",
        ".endr",
        "dosrt_int_common:",
        "pushad",
        // vector the stub pushed, just above the architecturally-fixed
        // 32-byte pushad frame. Read it before push ds/es so the offset
        // doesn't depend on their assembler-chosen operand size (LLVM
        // encodes a 32-bit-mode segment push as 16-bit + a 66 prefix).
        "mov ebp, [esp + 32]",
        "push ds",
        "push es",
        "mov ax, cs:[OUR_DS]",
        "mov ds, ax",
        "mov es, ax",
        "mov ebx, esp",               // host ESP -> EBX (callee-saved)
        "mov si, ss",                 // host SS  -> ESI (callee-saved)
        "mov ss, ax",
        "mov esp, cs:[INT_STACK_TOP]",
        "push ebp",                   // dosrt_int_dispatch(vector)
        "call dosrt_int_dispatch",
        "mov ss, si",                 // EBX/ESI survived the call
        "mov esp, ebx",
        "pop es",
        "pop ds",
        "popad",
        "add esp, 4",                 // discard the stub's pushed vector
        "iretd",
    );

    /// Called by `dosrt_int_common` on the flat interrupt stack with the
    /// vector of the stub that fired.
    #[unsafe(no_mangle)]
    extern "C" fn dosrt_int_dispatch(vector: u8) {
        let h = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(HANDLERS[vector as usize])) };
        if let Some(h) = h {
            unsafe { h() }
        }
    }

    /// Install `handler` as the protected-mode handler for interrupt
    /// `vector` (DPMI 0.9 AX=0205). The handler runs on dosrt's flat
    /// interrupt stack with DS/ES = our flat data selector, so it may
    /// freely take the address of stack locals; the trampoline preserves
    /// all registers, so the handler need not. A hardware-IRQ handler
    /// must ack the device + EOI the PIC and must not enable interrupts.
    pub fn install_handler(vector: u8, handler: unsafe extern "C" fn()) -> Result<(), u16> {
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(HANDLERS[vector as usize]),
                Some(handler),
            );
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(INT_STACK_TOP),
                core::ptr::addr_of!(INT_STACK) as u32 + INT_STACK_SIZE as u32,
            );
        }
        let cs: u16;
        unsafe {
            core::arch::asm!("mov {0:x}, cs", out(reg) cs,
                options(nomem, nostack, preserves_flags));
        }
        let stub = core::ptr::addr_of!(dosrt_int_stubs) as usize + vector as usize * STUB_STRIDE;
        set_pm_int(vector, cs, stub as u32)
    }
}

/// Port I/O. At CPL3 `in`/`out` #GP and RetroOS's machine layer emulates
/// them for the DOS process (same path the VM86 DOS games use), so a PM
/// dosrt payload can drive the SB/8237/PIC ports directly.
pub mod io {
    #[inline]
    pub fn inb(port: u16) -> u8 {
        let v: u8;
        unsafe { core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack, preserves_flags)) };
        v
    }
    #[inline]
    pub fn outb(port: u16, v: u8) {
        unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags)) };
    }
}

/// Flat pointer, in our own DS, aliasing a conventional block at real-
/// mode segment `seg`. Our selectors are flat, so linear `seg<<4` is
/// reachable at DS offset `seg<<4 - DS_base`. Used for the SB DMA ring
/// (the 8237 needs a conventional <1 MB physical buffer).
pub fn conv_flat_ptr(seg: u16) -> *mut u8 {
    ((seg as u32) << 4).wrapping_sub(dpmi::seg_base(dpmi::ds_sel())) as *mut u8
}

/// dosrt libc: DOS file I/O via INT 21h through `dpmi::sim_int`. The
/// pointer-passing transfer buffer is a *real conventional* DOS block
/// (DPMI AX=0100), lazily allocated on first use — a payload's own image
/// is AX=0501 extended memory and is NOT real-mode addressable, so the
/// old "derive seg:off from DS base" trick only worked for conventional
/// clients (RLOADER) and produced a garbage pointer for real payloads.
pub mod dos {
    use super::dpmi::{self, Rmcs};

    const XFER_PARAS: u16 = 256;                 // 256 * 16 = 4096 bytes
    const XFER_LEN: usize = XFER_PARAS as usize * 16;
    static mut XFER_SEG: u16 = 0;                 // RM segment (0 = unalloc)

    /// Lazily allocate the conventional transfer block (AX=0100). We only
    /// need its real-mode segment for the INT 21h `DS:DX` pointer — our
    /// own selectors are flat (RLOADER 1 MB, payload 4 GB), so the
    /// block's linear address is directly reachable from our DS.
    fn xfer_seg() -> u16 {
        unsafe {
            if XFER_SEG == 0 {
                let (seg, _sel) = dpmi::alloc_dos_mem(XFER_PARAS)
                    .expect("dosrt: AX=0100 conv buffer");
                XFER_SEG = seg;
            }
            XFER_SEG
        }
    }

    /// A plain pointer, *in our own DS*, that aliases the conventional
    /// block. Our selector is flat, so `linear == DS_base + offset` ⇒
    /// `offset = conv_linear - DS_base` (mod 2^32); a normal
    /// `copy_nonoverlapping` then reaches it — no second selector / asm.
    fn conv_ptr(seg: u16) -> *mut u8 {
        let conv_lin = (seg as u32) << 4;
        let ds_base = dpmi::seg_base(dpmi::ds_sel());
        conv_lin.wrapping_sub(ds_base) as *mut u8
    }

    /// INT 21h AH=3Dh open, AL=0 read-only. `path` must be NUL-terminated.
    pub fn open(path: &[u8]) -> Option<u16> {
        let seg = xfer_seg();
        let n = core::cmp::min(path.len(), XFER_LEN);
        unsafe { core::ptr::copy_nonoverlapping(path.as_ptr(), conv_ptr(seg), n); }
        let mut r = Rmcs::default();
        r.eax = 0x3D00;
        r.ds = seg; r.edx = 0;                     // DS:DX -> conv block
        dpmi::sim_int(0x21, &mut r);
        if r.flags & 1 != 0 { None } else { Some(r.eax as u16) }
    }

    /// INT 21h AH=3Fh read, chunked through the conv block. Bytes read.
    pub fn read(handle: u16, buf: &mut [u8]) -> usize {
        let seg = xfer_seg();
        let cp = conv_ptr(seg);
        let mut done = 0usize;
        while done < buf.len() {
            let want = core::cmp::min(buf.len() - done, XFER_LEN) as u16;
            let mut r = Rmcs::default();
            r.eax = 0x3F00;
            r.ebx = handle as u32;
            r.ecx = want as u32;
            r.ds = seg; r.edx = 0;
            dpmi::sim_int(0x21, &mut r);
            if r.flags & 1 != 0 { break; }            // CF -> error
            let got = r.eax as u16 as usize;
            if got == 0 { break; }                    // EOF
            unsafe {
                core::ptr::copy_nonoverlapping(cp, buf.as_mut_ptr().add(done), got);
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

    /// The DOS command tail (argv) of *this* process. The whole
    /// stub→RLOADER→payload chain runs in one DOS process, so its PSP
    /// carries the original command line. INT 21h AH=62h → PSP segment;
    /// `PSP:0x80` = length byte, `PSP:0x81..` = the tail (CR-terminated).
    /// Conventional memory, reached via our flat selector. Empty slice
    /// if no args.
    pub fn cmdline() -> &'static [u8] {
        let mut r = Rmcs::default();
        r.eax = 0x6200;                       // get PSP segment -> BX
        dpmi::sim_int(0x21, &mut r);
        let psp = r.ebx as u16;
        if psp == 0 {
            return &[];
        }
        let base = crate::conv_flat_ptr(psp); // flat ptr to PSP:0
        unsafe {
            let len = (*base.add(0x80) as usize).min(126);
            core::slice::from_raw_parts(base.add(0x81) as *const u8, len)
        }
    }

    /// INT 21h AH=4Ch exit (register-only; reflects directly).
    pub fn exit(code: u8) -> ! {
        unsafe { core::arch::asm!("int 0x21", in("ax") 0x4C00u16 | code as u16) }
        loop { unsafe { core::arch::asm!("hlt") } }
    }
}

/// Process-wide global allocator: a single bump arena carved out of one
/// 4 MB DPMI extended-memory block (AX=0501). Lazy-init on first
/// `alloc`; `dealloc` is a no-op (we never free — process exit reclaims
/// everything). Sufficient for payloads that want `Vec`/`Box` without
/// pulling in a real free-list allocator.
mod heap {
    use super::dpmi;
    use core::alloc::{GlobalAlloc, Layout};
    use core::cell::UnsafeCell;
    const HEAP_SIZE: u32 = 4 * 1024 * 1024;
    struct State { next: u32, end: u32 }
    pub struct DpmiBump { state: UnsafeCell<State> }
    // Single-threaded DOS payload — no actual concurrency.
    unsafe impl Sync for DpmiBump {}
    impl DpmiBump {
        pub const fn new() -> Self {
            Self { state: UnsafeCell::new(State { next: 0, end: 0 }) }
        }
        unsafe fn ensure(s: &mut State) -> bool {
            if s.end != 0 { return true; }
            let lin = match dpmi::alloc_mem(HEAP_SIZE) {
                Some(l) => l,
                None => return false,
            };
            let off = lin.wrapping_sub(dpmi::seg_base(dpmi::ds_sel()));
            s.next = off;
            s.end = off.wrapping_add(HEAP_SIZE);
            true
        }
    }
    unsafe impl GlobalAlloc for DpmiBump {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            let s = unsafe { &mut *self.state.get() };
            unsafe { if !Self::ensure(s) { return core::ptr::null_mut(); } }
            let m = (l.align() - 1) as u32;
            let a = s.next.wrapping_add(m) & !m;
            let n = a.wrapping_add(l.size() as u32);
            if n > s.end || n < a { return core::ptr::null_mut(); }
            s.next = n;
            a as *mut u8
        }
        unsafe fn dealloc(&self, _p: *mut u8, _l: Layout) {}
    }
    #[global_allocator]
    pub static ALLOCATOR: DpmiBump = DpmiBump::new();
}

/// Universal app crt0. RLOADER's `enter_payload` already set the
/// payload's CS/DS/SS/ESP and zeroed its BSS, and left **ESI = the
/// linear address of the command-tail string** (Borland `argv[1]`,
/// piped stub→RLOADER→here — the PSP/AH=62h path is empty for a PM
/// client). `_start` forwards ESI to `rt_entry`, which resolves it to a
/// flat pointer and hands the app its args. The app provides `app_main`.
/// RLOADER is not an app (own entry `rloader_entry`); this `_start` is
/// unreferenced there and gc-sectioned away.
core::arch::global_asm!(
    ".section .text._start,\"ax\"",
    ".code32",
    ".globl _start",
    "_start:",
    "mov ax, ds",               // stash our data sel so PM ISRs can
    "mov [OUR_DS], ax",         //   reach it via cs:[OUR_DS] (CS&DS
                                //   share base in our flat setup)
    "push esi",                 // arg_lin → rt_entry(arg_lin)
    "call rt_entry",
    "1: hlt",
    "jmp 1b",
);

/// Our data selector, captured by `_start`. PM ISRs (which enter with
/// DS/ES undefined per DPMI HW-IRQ delivery) load DS/ES from
/// `cs:[OUR_DS]` — our CS and DS share base, so a CS-relative read of
/// this symbol resolves to the same linear address as a DS-relative one.
#[unsafe(no_mangle)]
pub static mut OUR_DS: u16 = 0;

unsafe extern "Rust" {
    fn app_main(argc: usize, argv: &[&[u8]]);
}

/// Max argv the runtime reconstructs.
const ARGV_MAX: usize = 16;

/// Rebuild `argc`/`argv` from the stub's conventional block
/// (`[u8 argc][argv0 \0][argv1 \0]...`), reached via our flat DS at
/// `arg_lin - DS_base`, then enter the app.
#[unsafe(no_mangle)]
extern "C" fn rt_entry(arg_lin: u32) -> ! {
    let mut argv: [&[u8]; ARGV_MAX] = [&[]; ARGV_MAX];
    let dsb = dpmi::seg_base(dpmi::ds_sel());
    let argc = if arg_lin == 0 {
        0
    } else {
        let p = arg_lin.wrapping_sub(dsb) as *const u8;
        unsafe {
            let n = (*p as usize).min(ARGV_MAX);
            let mut q = p.add(1);
            for slot in argv.iter_mut().take(n) {
                let start = q;
                let mut l = 0usize;
                while *q != 0 && l < 255 {
                    q = q.add(1);
                    l += 1;
                }
                *slot = core::slice::from_raw_parts(start, l);
                q = q.add(1); // skip the NUL
            }
            n
        }
    };
    unsafe { app_main(argc, &argv[..argc]) }
    dos::exit(0)
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    putc(b'P');
    loop { unsafe { core::arch::asm!("hlt") } }
}
