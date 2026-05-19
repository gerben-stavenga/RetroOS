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
#include <fcntl.h>
#include <io.h>

/* Handoff to RLOADER is via the natural C far-call ABI: the stub calls
 * the 32-bit entry as go(unsigned exh, unsigned long poff). TC pushes the
 * args (right-to-left, cdecl) onto the stub's PM stack and the far CALL
 * pushes the return CS:IP; RLOADER's crt0 reads them off that stack
 * (SS-relative, before it repoints SS:ESP). No fixed buffer slot, no
 * register-survival assumptions. */
typedef void (far *rloader_fn)(unsigned, unsigned long, unsigned long);

/* Borland-parsed argv, repacked into one self-describing conventional
 * block: [u8 argc][argv0 \0][argv1 \0]...  RLOADER captures its far
 * pointer and pipes it to the payload, whose dosrt crt0 rebuilds
 * argc/argv (the PSP/AH=62h path is empty for a PM client, so the
 * stub's Borland argv is the source). */
static char argblk[512];

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
    rloader_fn go;
    int exh;
    unsigned char mz[6];
    unsigned long poff;

    (void) argc;

    /* Load the shared loader. The buffer must hold RLOADER's whole image
     * incl. BSS+stack (crt0 zeroes/uses BSS past the file bytes), not
     * just the file. Allocate a fixed block big enough; read the file
     * into the front. (Small-model heap cap ~64 KB — fine while RLOADER
     * + payload-scratch stay modest.) */
    #define DOSRT_BUFSZ 0xE000U      /* ~56 KB: file + BSS + stack       */
    f = fopen("RLOADER.BIN", "rb");
    if (!f) { printf("dosrt: cannot open RLOADER.BIN\n"); return 1; }
    fseek(f, 0L, SEEK_END); sz = ftell(f); fseek(f, 0L, SEEK_SET);
    if (sz <= 0 || (unsigned long) sz > DOSRT_BUFSZ) {
        printf("dosrt: RLOADER.BIN size %ld > buf\n", sz); fclose(f); return 1;
    }
    buf = (char *) malloc(DOSRT_BUFSZ);
    if (!buf) { printf("dosrt: malloc failed\n"); fclose(f); return 1; }
    n = fread(buf, 1, (size_t) sz, f);
    fclose(f);
    if (n != (size_t) sz) { printf("dosrt: short read %u/%ld\n", n, sz); return 1; }

    /* Open our own .EXE (argv[0] = full path; RetroOS fills the DOS-3 env
     * program-path, so TC's startup populates it). Keep it open — RLOADER
     * reads the appended payload ELF through this handle. The payload
     * begins right after the MZ load module; derive that size from the MZ
     * header: pages*512, minus the unused tail of the last page. */
    /* Repack argv → [u8 argc][argv0 \0][argv1 \0]... in conventional mem. */
    {
        unsigned p = 0, a, j;
        unsigned char na = (unsigned char)(argc > 255 ? 255 : argc);
        argblk[p++] = (char) na;
        for (a = 0; a < na; a++) {
            j = 0;
            while (argv[a][j] != '\0' && p < sizeof(argblk) - 1)
                argblk[p++] = argv[a][j++];
            argblk[p++] = '\0';
        }
    }

    exh = open(argv[0], O_RDONLY | O_BINARY);
    if (exh < 0) { printf("dosrt: cannot open self '%s'\n", argv[0]); return 1; }
    if (read(exh, mz, 6) != 6 || mz[0] != 'M' || mz[1] != 'Z') {
        printf("dosrt: self is not MZ\n"); return 1;
    }
    {
        unsigned e_cblp = mz[2] | ((unsigned) mz[3] << 8);   /* bytes/last pg */
        unsigned e_cp   = mz[4] | ((unsigned) mz[5] << 8);   /* 512-byte pgs  */
        poff = (unsigned long) e_cp * 512UL;
        if (e_cblp) poff = poff - 512UL + e_cblp;
    }

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
    /* selector base = buffer_linear - __link_base (rloader.ld 0x1000),
     * so RLOADER's link addresses (0x1000+) resolve via this selector. */
    lin = (((unsigned long)bhi << 16) | blo) + off - 0x1000UL;

    _AX = 0x0000; _CX = 1; geninterrupt(0x31);                /* alloc desc */
    sel = _AX;

    _AX = 0x0007; _BX = sel;                                  /* set base */
    _CX = (unsigned)(lin >> 16); _DX = (unsigned)(lin & 0xFFFF);
    geninterrupt(0x31);

    _AX = 0x0008; _BX = sel; _CX = 0x000F; _DX = 0xFFFF;      /* limit 1MB */
    geninterrupt(0x31);

    _AX = 0x0009; _BX = sel; _CX = 0x40FA;                    /* 32-bit code */
    geninterrupt(0x31);

    go = (rloader_fn) MK_FP(sel, 0x1000);        /* RLOADER _start @ __link_base */
    /* By now the stub is a 16-bit DPMI PM client: _DS is a SELECTOR, not
     * a paragraph, so a far seg:off is wrong (RLOADER would do seg<<4).
     * Pass argblk's LINEAR address, computed from the DS base we already
     * fetched via AX=0006 (bhi:blo). */
    (*go)((unsigned) exh, poff,
          (((unsigned long) bhi << 16) | blo) + (unsigned long)(unsigned) argblk);

    return 0;                                                 /* not reached */
}
