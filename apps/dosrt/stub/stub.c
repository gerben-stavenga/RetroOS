/* dosrt stub -- Turbo C 2.01, small model (-ms). MZ EXE.
 *
 * Flow (the agreed architecture): in REAL mode detect DPMI and read the
 * shared RLOADER.BIN into a conventional buffer; switch to protected
 * mode (16-bit DPMI client); FAR-JUMP into RLOADER. The stub does NO
 * protected-mode C (TC 2.01's int86 library is not PM-safe — it far-
 * calls the real-mode IVT vector, which #GPs in PM). All PM work is
 * RLOADER's job (Rust, its own PM-safe asm).
 *
 * Pure C, no `asm`: the automated build path (fw_cfg launcher, no shell)
 * can't run TCC's asm-restart. The mode-switch FAR CALL uses a TC far
 * function pointer + _ES/_AX/_FLAGS pseudo-registers.
 *
 * Stage CRLF + ASCII (TCC 2.01 aborts on LF) -- qemu_tcc.sh does that.
 */
#include <dos.h>

static unsigned ent_off, ent_seg;      /* DPMI mode-switch entry (ES:DI) */
static char rloader[16384];            /* RLOADER.BIN -> conventional buf */

/* FAR CALL the mode-switch entry: ES=host data seg, AX=0 (16-bit
 * client). Pure C only — inline `asm` is unbuildable via the TCC
 * genrule (no working TASM/TLINK pair in the fw_cfg path). */
static int dpmi_switch(unsigned host_seg)
{
    void (far *go)() = (void (far *)()) MK_FP(ent_seg, ent_off);
    _ES = host_seg;
    _AX = 0;
    (*go)();
    return (int)(_FLAGS & 1);          /* CF=1 => mode switch failed */
}

static void rm_puts(char *dollar)      /* real-mode INT 21h AH=09h */
{
    union REGS r; struct SREGS s;
    segread(&s);
    r.h.ah = 0x09;
    r.x.dx = (unsigned)dollar;
    int86x(0x21, &r, &r, &s);
}

/* PM-safe INT 21h via geninterrupt(): emits a literal `INT 21h` opcode
 * (TC intrinsic, no `asm` keyword -> builds via the genrule). A real
 * INT in PM is reflected by the DPMI host, unlike TC's int86 library
 * (which far-calls the RM IVT vector and #GPs in PM). Register-only
 * (AH=02h DL=char) so no pointer translation is needed. */
static void pm_putc(char c) { _DL = c; _AH = 0x02; geninterrupt(0x21); }
static void pm_puts(char *s) { while (*s) pm_putc(*s++); }
static void pm_exit(unsigned char code) { _AL = code; _AH = 0x4C; geninterrupt(0x21); }

int main(void)
{
    union REGS r; struct SREGS s;
    unsigned host_si, host_seg, fh, got;
    void (far *go)();

    /* 1. DPMI present?  INT 2Fh AX=1687h */
    r.x.ax = 0x1687;
    int86x(0x2F, &r, &r, &s);
    if (r.x.ax != 0) { rm_puts("dosrt: no DPMI host\r\n$"); return 1; }
    host_si = r.x.si;
    ent_off = r.x.di;
    ent_seg = s.es;

    /* 2. Real mode: open + read RLOADER.BIN into the conventional buffer
     *    (cwd=host/). Real-mode pointers, so int86x DS:DX is fine. */
    segread(&s);
    r.h.ah = 0x3D; r.h.al = 0;                 /* open, read-only */
    r.x.dx = (unsigned)"RLOADER.BIN";
    int86x(0x21, &r, &r, &s);
    if (r.x.cflag) { rm_puts("dosrt: RLOADER.BIN open failed\r\n$"); return 1; }
    fh = r.x.ax;
    segread(&s);
    r.h.ah = 0x3F; r.x.bx = fh;                /* read */
    r.x.cx = sizeof(rloader);
    r.x.dx = (unsigned)rloader;
    int86x(0x21, &r, &r, &s);
    got = r.x.cflag ? 0 : r.x.ax;
    { union REGS c; c.h.ah = 0x3E; c.x.bx = fh; int86(0x21, &c, &c); }  /* close */
    if (got == 0) { rm_puts("dosrt: RLOADER.BIN read failed\r\n$"); return 1; }

    /* 3. Allocate the host private data block (SI paragraphs), if any. */
    if (host_si != 0) {
        r.h.ah = 0x48; r.x.bx = host_si;
        int86(0x21, &r, &r);
        if (r.x.cflag) { rm_puts("dosrt: host-block alloc failed\r\n$"); return 1; }
        host_seg = r.x.ax;
    } else {
        segread(&s);
        host_seg = s.ds;
    }

    /* 4. Enter protected mode (16-bit DPMI client). */
    if (dpmi_switch(host_seg)) {
        rm_puts("dosrt: DPMI mode switch failed\r\n$");
        return 2;
    }

    /* 5. Hand off to RLOADER: build a 32-bit CODE selector whose BASE is
     *    the linear address of the `rloader` buffer (selector-base trick;
     *    RLOADER is linked at 0), then far-jmp it. DPMI INT 31h via
     *    geninterrupt() — PM-safe, pure C. */
    pm_puts("dosrt: handoff\r\n");
    {
        unsigned ds_sel, sel, bhi, blo, off;
        unsigned long lin;

        off = (unsigned) rloader;
        ds_sel = _DS;

        _AX = 0x0006; _BX = ds_sel; geninterrupt(0x31);   /* get DS base */
        bhi = _CX; blo = _DX;
        lin = (((unsigned long)bhi << 16) | blo) + off;

        _AX = 0x0000; _CX = 1; geninterrupt(0x31);         /* alloc 1 desc */
        sel = _AX;

        _AX = 0x0007; _BX = sel;                           /* set base */
        _CX = (unsigned)(lin >> 16); _DX = (unsigned)(lin & 0xFFFF);
        geninterrupt(0x31);

        _AX = 0x0008; _BX = sel; _CX = 0; _DX = 0xFFFF;    /* set limit 64K */
        geninterrupt(0x31);

        _AX = 0x0009; _BX = sel; _CX = 0x40FA;             /* 32-bit code, P, DPL3 */
        geninterrupt(0x31);

        go = (void (far *)()) MK_FP(sel, 0);               /* far-jmp sel:0 */
        (*go)();
    }

    pm_puts("dosrt: RLOADER returned?!\r\n");
    pm_exit(3);
    return 0;
}
