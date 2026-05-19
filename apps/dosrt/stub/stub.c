/* dosrt stub -- Turbo C 2.01, small model (-ms). MZ EXE.
 *
 * Clean C: load RLOADER.BIN with the C library; only the DPMI bits use
 * int86x/geninterrupt (no libc for those). DPMI detect, mode-switch as
 * a 32-bit client (AX=1 -- CWSDPMI-correct; per DPMI 0.9 post-switch CS
 * is 16-bit regardless, so this C keeps running), then geninterrupt
 * (0x31) builds a 32-bit CODE selector whose base is the linear addr of
 * the malloc'd RLOADER buffer (selector-base trick; RLOADER linked at 0)
 * and far-jmps it. RLOADER then runs as 32-bit code.
 *
 * Stage CRLF + ASCII (TCC 2.01 aborts on LF) -- qemu_tcc.sh does that.
 */
#include <stdio.h>
#include <stdlib.h>
#include <dos.h>

static unsigned ent_off, ent_seg;      /* DPMI mode-switch entry (ES:DI) */

/* Mode-switch: ES=host data seg, AX=1 (32-bit client). CF=fail. */
static int dpmi_switch(unsigned host_seg)
{
    void (far *go)() = (void (far *)()) MK_FP(ent_seg, ent_off);
    _ES = host_seg;
    _AX = 1;
    (*go)();
    return (int)(_FLAGS & 1);
}

int main(int argc, char **argv)
{
    FILE *f;
    long sz;
    char *buf;
    size_t n;
    union REGS r;
    struct SREGS s;
    unsigned host_si, host_seg, seg, ds_sel, sel, bhi, blo, off;
    unsigned long lin;
    void (far *go)();

    (void) argc; (void) argv;

    /* Load the shared loader with the C library. */
    f = fopen("RLOADER.BIN", "rb");
    if (!f) { printf("dosrt: cannot open RLOADER.BIN\n"); return 1; }
    fseek(f, 0L, SEEK_END); sz = ftell(f); fseek(f, 0L, SEEK_SET);
    buf = (char *) malloc((size_t) sz);
    if (!buf) { printf("dosrt: malloc(%ld) failed\n", sz); fclose(f); return 1; }
    n = fread(buf, 1, (size_t) sz, f);
    fclose(f);
    if (n != (size_t) sz) { printf("dosrt: short read %u/%ld\n", n, sz); return 1; }

    /* DPMI present?  INT 2Fh AX=1687h (no libc for this). */
    r.x.ax = 0x1687;
    int86x(0x2F, &r, &r, &s);
    if (r.x.ax != 0) { printf("dosrt: no DPMI host\n"); return 1; }
    host_si = r.x.si;
    ent_off = r.x.di;
    ent_seg = s.es;

    /* Host data block (SI paras), if any. _dos_allocmem is the libc
     * wrapper for the DOS segment alloc. ES ignored when SI==0. */
    host_seg = 0;
    if (host_si != 0) {
        if (_dos_allocmem(host_si, &seg) != 0) {
            printf("dosrt: host-block alloc failed\n");
            return 1;
        }
        host_seg = seg;
    }

    if (dpmi_switch(host_seg)) {
        printf("dosrt: DPMI mode switch failed\n");
        return 2;
    }

    /* 16-bit PM. Build a 32-bit CODE selector over the buffer, far-jmp
     * -> RLOADER runs as 32-bit code. geninterrupt() = literal INT
     * (PM-safe; host-reflected/serviced). */
    { _DL = '!'; _AH = 0x02; geninterrupt(0x21); }   /* PM reached marker */

    off = (unsigned) buf;
    ds_sel = _DS;

    _AX = 0x0006; _BX = ds_sel; geninterrupt(0x31);          /* DS base */
    bhi = _CX; blo = _DX;
    lin = (((unsigned long)bhi << 16) | blo) + off;

    _AX = 0x0000; _CX = 1; geninterrupt(0x31);                /* alloc desc */
    sel = _AX;

    _AX = 0x0007; _BX = sel;                                  /* set base */
    _CX = (unsigned)(lin >> 16); _DX = (unsigned)(lin & 0xFFFF);
    geninterrupt(0x31);

    _AX = 0x0008; _BX = sel; _CX = 0; _DX = 0xFFFF;           /* limit 64K */
    geninterrupt(0x31);

    _AX = 0x0009; _BX = sel; _CX = 0x40FA;                    /* 32-bit code */
    geninterrupt(0x31);

    go = (void (far *)()) MK_FP(sel, 0);
    (*go)();                                                  /* -> RLOADER */

    return 0;                                                 /* not reached */
}
