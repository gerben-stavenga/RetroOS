/*
 * bios.c -- a small PC BIOS for the RetroOS interpreter backend, in 16-bit C.
 *
 * On metal/QEMU the ROM BIOS owns INT 08/10/11/16/1A and the BIOS Data Area;
 * the interpreter has no ROM, so DOS guests (DN) that call these vectors land
 * on a null IVT and self-corrupt. Rather than hand-assemble stubs, we compile
 * this with our own in-OS Turbo C (the same TCC that builds the dosrt stub) and
 * load it as firmware at segment 0xF000.
 *
 * Constraints (Turbo C 2.01, automated/headless build):
 *   - PURE C, no `asm` -- the automated TCC path has no COMMAND.COM, so TCC's
 *     asm-restart (spawning TASM via INT 21h EXEC) hangs. We use only intrinsics
 *     (MK_FP, far pointers, geninterrupt, outportb) and `interrupt` functions.
 *   - Handlers are DS-independent: every access is a far pointer to the BDA
 *     (seg 0x40) or video memory (seg 0xB800), never a near global, so they work
 *     regardless of the caller's DS.
 *
 * Loading: the interpreter NEVER runs this program's C startup (a COM drags in
 * Turbo C's C0 startup, which does DOS calls -- INT 21h AH=4A resize, version,
 * PSP/env parsing -- that would fault at firmware-POST time). Instead it treats
 * the compiled blob as pure handler code: it scans for the `bios_vectors`
 * signature below and wires IVT[vec] = F000:offset for each entry. The handlers
 * then run as ordinary ISRs. The BDA is seeded by the interpreter (Rust) side,
 * since main() never executes.
 */

#include <dos.h>

/* --- BIOS Data Area (segment 0x40) field accessors -------------------------*/
#define BDA_B(off)  (*(unsigned char far *)MK_FP(0x40, (off)))
#define BDA_W(off)  (*(unsigned far *)MK_FP(0x40, (off)))
#define BDA_L(off)  (*(unsigned long far *)MK_FP(0x40, (off)))

/* Keyboard ring buffer: head/tail are offsets (0x1E..0x3D) into segment 0x40. */
#define KB_HEAD 0x1A
#define KB_TAIL 0x1C
#define KB_RING 0x1E
#define KB_END  0x3E

/* Video: current page's cursor position word lives at 0040:0050 + page*2
 * (low byte = column, high byte = row). */
#define VGA_SEG 0xB800

/* --- INT 16h: keyboard ---------------------------------------------------- */
void interrupt int16(unsigned bp, unsigned di, unsigned si, unsigned ds,
                     unsigned es, unsigned dx, unsigned cx, unsigned bx,
                     unsigned ax, unsigned ip, unsigned cs, unsigned flags)
{
    unsigned ah = ax >> 8;
    unsigned head;

    switch (ah) {
    case 0x00: /* read key (blocking) */
    case 0x10:
        while (BDA_W(KB_HEAD) == BDA_W(KB_TAIL))
            ;                       /* spin; the host fills the ring */
        head = BDA_W(KB_HEAD);
        ax = BDA_W(head);           /* scancode:ascii word */
        head += 2;
        if (head >= KB_END)
            head = KB_RING;
        BDA_W(KB_HEAD) = head;
        break;
    case 0x01: /* key status (peek) */
    case 0x11:
        if (BDA_W(KB_HEAD) == BDA_W(KB_TAIL)) {
            flags |= 0x40;          /* ZF=1: no key */
        } else {
            flags &= ~0x40;         /* ZF=0: key available */
            ax = BDA_W(BDA_W(KB_HEAD));
        }
        break;
    case 0x02: /* shift flag status */
    case 0x12:
        ax = (ax & 0xFF00) | BDA_B(0x17);
        break;
    default:
        break;
    }
}

/* --- INT 10h: video ------------------------------------------------------- */
void interrupt int10(unsigned bp, unsigned di, unsigned si, unsigned ds,
                     unsigned es, unsigned dx, unsigned cx, unsigned bx,
                     unsigned ax, unsigned ip, unsigned cs, unsigned flags)
{
    unsigned ah = ax >> 8;
    unsigned page;

    switch (ah) {
    case 0x00: /* set video mode -- record it; we only model text mode 3 */
        BDA_B(0x49) = (unsigned char)(ax & 0x7F);
        break;
    case 0x01: /* set cursor shape (CX) */
        BDA_W(0x60) = cx;
        break;
    case 0x02: /* set cursor position (BH=page, DH=row, DL=col) */
        page = bx >> 8;
        BDA_W(0x50 + page * 2) = dx;
        break;
    case 0x03: /* get cursor position/shape */
        page = bx >> 8;
        dx = BDA_W(0x50 + page * 2);
        cx = BDA_W(0x60);
        break;
    case 0x05: /* select active display page */
        BDA_B(0x62) = (unsigned char)(ax & 0xFF);
        break;
    case 0x0E: /* teletype output (AL=char) -- write at cursor, advance */
        {
            unsigned char ch = (unsigned char)(ax & 0xFF);
            page = BDA_B(0x62);
            {
                unsigned pos = BDA_W(0x50 + page * 2);
                unsigned row = pos >> 8, col = pos & 0xFF;
                unsigned cols = BDA_W(0x4A);
                if (ch == '\r') {
                    col = 0;
                } else if (ch == '\n') {
                    row++;
                } else if (ch == 8) {
                    if (col) col--;
                } else {
                    unsigned off = (row * cols + col) * 2;
                    *(unsigned char far *)MK_FP(VGA_SEG, off) = ch;
                    col++;
                    if (col >= cols) { col = 0; row++; }
                }
                if (row > 24) row = 24;     /* (scroll handled by direct writers) */
                BDA_W(0x50 + page * 2) = (row << 8) | col;
            }
        }
        break;
    case 0x0F: /* get video mode: AL=mode, AH=columns, BH=page */
        ax = (BDA_W(0x4A) << 8) | BDA_B(0x49);
        bx = (BDA_B(0x62) << 8) | (bx & 0xFF);
        break;
    default:
        break;
    }
}

/* --- INT 11h: equipment list ---------------------------------------------- */
void interrupt int11(unsigned bp, unsigned di, unsigned si, unsigned ds,
                     unsigned es, unsigned dx, unsigned cx, unsigned bx,
                     unsigned ax, unsigned ip, unsigned cs, unsigned flags)
{
    ax = BDA_W(0x10);
}

/* --- INT 1Ah: system timer ------------------------------------------------ */
void interrupt int1a(unsigned bp, unsigned di, unsigned si, unsigned ds,
                     unsigned es, unsigned dx, unsigned cx, unsigned bx,
                     unsigned ax, unsigned ip, unsigned cs, unsigned flags)
{
    unsigned ah = ax >> 8;
    unsigned long ticks;

    switch (ah) {
    case 0x00: /* read tick count: CX:DX = ticks, AL = midnight flag */
        ticks = BDA_L(0x6C);
        cx = (unsigned)(ticks >> 16);
        dx = (unsigned)(ticks & 0xFFFF);
        ax = ax & 0xFF00;           /* AL = 0 (no rollover) */
        break;
    case 0x01: /* set tick count from CX:DX */
        BDA_L(0x6C) = ((unsigned long)cx << 16) | dx;
        break;
    default:
        break;
    }
}

/* --- INT 08h: timer IRQ0 -------------------------------------------------- */
void interrupt int08(void)
{
    BDA_L(0x6C) += 1;               /* advance BIOS tick at 0040:006C */
    geninterrupt(0x1C);             /* chain user timer tick */
    outportb(0x20, 0x20);          /* PIC EOI */
}

/* --- INT 09h: keyboard IRQ1 ----------------------------------------------- *
 * The kernel raises IRQ1 with a scancode readable at port 0x60 (its virtual
 * 8042). We translate to ASCII, track shift/ctrl in the BDA flag byte, and push
 * a (scancode:ascii) word into the BDA ring for INT 16h. Extended keys (arrows,
 * F-keys) push ascii=0 with their scancode preserved. The scancode tables are
 * read through CS far pointers (the BIOS is at CS=0xF000), so the handler stays
 * DS-independent like the rest. */
static unsigned char kb_lc[] = {
    0, 27, '1','2','3','4','5','6','7','8','9','0','-','=', 8, 9,
    'q','w','e','r','t','y','u','i','o','p','[',']', 13, 0,
    'a','s','d','f','g','h','j','k','l',';', 39, '`', 0, 92,
    'z','x','c','v','b','n','m',',','.','/', 0, '*', 0, ' '
};
static unsigned char kb_uc[] = {
    0, 27, '!','@','#','$','%','^','&','*','(',')','_','+', 8, 9,
    'Q','W','E','R','T','Y','U','I','O','P','{','}', 13, 0,
    'A','S','D','F','G','H','J','K','L',':', '"', '~', 0, '|',
    'Z','X','C','V','B','N','M','<','>','?', 0, '*', 0, ' '
};

void interrupt int09(void)
{
    unsigned char sc = inportb(0x60);
    unsigned char key = sc & 0x7F;
    unsigned char flags = BDA_B(0x17);
    unsigned char asc;
    unsigned char far *tab;
    unsigned tail, next;

    /* Shift / Ctrl are modifiers: update the BDA flag byte, don't enqueue. */
    if (key == 0x2A) { flags = (sc & 0x80) ? (flags & ~0x02) : (flags | 0x02); BDA_B(0x17) = flags; outportb(0x20, 0x20); return; }
    if (key == 0x36) { flags = (sc & 0x80) ? (flags & ~0x01) : (flags | 0x01); BDA_B(0x17) = flags; outportb(0x20, 0x20); return; }
    if (key == 0x1D) { flags = (sc & 0x80) ? (flags & ~0x04) : (flags | 0x04); BDA_B(0x17) = flags; outportb(0x20, 0x20); return; }
    if (sc & 0x80) { outportb(0x20, 0x20); return; }     /* other key releases */

    asc = 0;
    if (key < sizeof(kb_lc)) {
        tab = (flags & 0x03) ? (unsigned char far *)MK_FP(_CS, (unsigned)kb_uc)
                             : (unsigned char far *)MK_FP(_CS, (unsigned)kb_lc);
        asc = tab[key];
        if ((flags & 0x04) && ((unsigned char)(asc | 0x20) >= 'a') && ((unsigned char)(asc | 0x20) <= 'z'))
            asc &= 0x1F;                                 /* Ctrl-letter */
    }

    tail = BDA_W(KB_TAIL);
    next = tail + 2;
    if (next >= KB_END)
        next = KB_RING;
    if (next != BDA_W(KB_HEAD)) {                        /* ring not full */
        BDA_W(tail) = ((unsigned)key << 8) | asc;
        BDA_W(KB_TAIL) = next;
    }
    outportb(0x20, 0x20);                               /* EOI */
}

/* --- Self-describing vector table ----------------------------------------
 * The interpreter scans the compiled blob for the 0xF00D 0xB105 signature, then
 * reads (vector, handler-offset) pairs until a zero vector, and wires the IVT.
 * The handler offsets are link-time constants (the functions' offsets within
 * the F000 segment), so no MAP file or running code is needed. */
unsigned bios_vectors[] = {
    0xF00D, 0xB105,                 /* signature */
    0x08, (unsigned)int08,
    0x09, (unsigned)int09,
    0x10, (unsigned)int10,
    0x11, (unsigned)int11,
    0x16, (unsigned)int16,
    0x1A, (unsigned)int1a,
    0x00, 0x0000,                   /* terminator (vector 0) */
};

/* The COM needs an entry point to link, but it is never executed (see header).
 * Reference the table so the linker can't drop it. */
void main(void)
{
    volatile unsigned keep = bios_vectors[0];
    (void)keep;
}
