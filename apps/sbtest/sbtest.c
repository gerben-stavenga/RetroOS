/* sbtest.c -- Sound Blaster DMA test, one binary, mode by CLI flag:
 *
 *   SBTEST            (default) single-cycle + Dune2-style CLI BIOS-
 *                     tick wait (deterministic virtual-IF freeze repro)
 *   SBTEST cli        same
 *   SBTEST auto       auto-init ring            (Doom/Raptor mode)
 *   SBTEST sing       single-cycle blocks       (Dune2 speech mode)
 *
 * Shared: a continuous PCM stream (public-domain "Ode to Joy",
 * Beethoven 1824) produced off a global sample clock, independent of
 * DMA chunking. Stock SB16 layout (BLASTER A220 I5 D1 H5).
 * Turbo C 2.01, tiny model (-mt -lt), ASCII + CRLF.
 */

#include <dos.h>
#include <stdio.h>

#define SB_BASE   0x220
#define SB_RESET  (SB_BASE + 0x6)
#define SB_READ   (SB_BASE + 0xA)
#define SB_WRITE  (SB_BASE + 0xC)
#define SB_WSTAT  (SB_BASE + 0xC)
#define SB_RSTAT  (SB_BASE + 0xE)

#define SB_IRQ    7
#define SB_VEC    0x0F
#define PIC_CMD   0x20
#define PIC_MASK  0x21

#define SRATE     11000U
#define SEGSZ     256U             /* auto-init: bytes per IRQ        */
#define NSEG      16U              /* auto-init: ring depth           */
#define NSAMP     (SEGSZ * NSEG)   /* = 4096, also the single block   */

#define M_AUTO 0
#define M_SING 1
#define M_CLI  2
static int mode = M_CLI;          /* default: the virtual-IF freeze repro */

static unsigned char buf[NSAMP];
static void interrupt (*old_vec)(void);
static volatile unsigned cur_seg = 0;
static volatile unsigned irqs    = 0;
static volatile int      done    = 0;
/* 8237 ch1 current count, sampled at ISR entry exactly the way Dune2's
 * speech ISR does to identify its completion IRQ (expects 0xFFFF). */
static volatile unsigned isr_count = 0;

/* ---- continuous music stream (independent of DMA chunking) -------- */

#define NC 262
#define ND 294
#define NE 330
#define NF 349
#define NG 392
static unsigned mel_f[] = {
    NE,NE,NF,NG, NG,NF,NE,ND, NC,NC,ND,NE, NE,ND,ND,
    NE,NE,NF,NG, NG,NF,NE,ND, NC,NC,ND,NE, ND,NC,NC
};
static unsigned mel_d[] = {
    1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,2,
    1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,2
};
#define MEL_LEN  (sizeof(mel_f) / sizeof(mel_f[0]))
#define SAMP_Q   (SRATE * 2U / 5U)
#define GAP_SAMP 350U

static unsigned long samp = 0, note_start = 0, note_end = 0;
static unsigned note_idx = 0, cur_freq = 0, pacc = 0;
static volatile int finished = 0;

static unsigned char sample(void)
{
    if (!finished && samp >= note_end) {
        if (note_idx >= MEL_LEN) finished = 1;
        else {
            cur_freq   = mel_f[note_idx];
            note_start = samp;
            note_end   = samp + (unsigned long) mel_d[note_idx] * SAMP_Q;
            note_idx++;
        }
    }
    samp++;
    if (finished) return 0x80;
    if (samp - note_start <= GAP_SAMP) return 0x80;
    pacc += cur_freq;
    if (pacc >= SRATE) pacc -= SRATE;
    return (pacc < SRATE / 2) ? 0xC0 : 0x40;
}

static void fill(unsigned base, unsigned n)
{
    unsigned i;
    for (i = 0; i < n; i++) buf[base + i] = sample();
}

/* ---- SB / DMA transport ------------------------------------------ */

static void interrupt sb_isr(void)
{
    unsigned lo, hi;
    /* Dune2's speech ISR identifies its IRQ by reading the 8237 ch1
     * current count and testing == 0xFFFF (terminal count). Sample it
     * here, at IRQ entry, the exact same way, BEFORE acking. */
    outportb(0x0C, 0x00);                    /* clear ch0-3 flip-flop */
    lo = inportb(0x03);
    hi = inportb(0x03);
    isr_count = (hi << 8) | lo;

    inportb(SB_RSTAT);                       /* ack SB 8-bit DMA IRQ */
    if (mode == M_AUTO) {
        fill(cur_seg * SEGSZ, SEGSZ);        /* refill consumed segment */
        cur_seg = (cur_seg + 1) % NSEG;
    }
    done = 1;
    irqs++;
    outportb(PIC_CMD, 0x20);                 /* EOI master PIC */
}

static int dsp_reset(void)
{
    int i;
    outportb(SB_RESET, 1);
    for (i = 0; i < 1000; i++) inportb(SB_RESET);
    outportb(SB_RESET, 0);
    for (i = 0; i < 10000; i++)
        if ((inportb(SB_RSTAT) & 0x80) && inportb(SB_READ) == 0xAA)
            return 1;
    return 0;
}

static void dsp_write(unsigned char v)
{
    while (inportb(SB_WSTAT) & 0x80) ;
    outportb(SB_WRITE, v);
}

static void phys_of(unsigned char *p, unsigned *page, unsigned *off)
{
    unsigned char far *fp = (unsigned char far *) p;
    unsigned long ph = ((unsigned long) FP_SEG(fp) << 4) + FP_OFF(fp);
    *page = (unsigned)(ph >> 16);
    *off  = (unsigned)(ph & 0xFFFF);
}

/* Program 8237 ch1; auto-init (mode 0x59) over span, or single (0x49). */
static void dma_program(unsigned span, int autoinit)
{
    unsigned page, off;
    phys_of(buf, &page, &off);
    disable();
    outportb(0x0A, 0x05);
    outportb(0x0C, 0x00);
    outportb(0x0B, autoinit ? 0x59 : 0x49);
    outportb(0x02, off & 0xFF);
    outportb(0x02, off >> 8);
    outportb(0x83, page);
    outportb(0x03, (span - 1) & 0xFF);
    outportb(0x03, (span - 1) >> 8);
    outportb(0x0A, 0x01);
    enable();
}

int main(int argc, char *argv[])
{
    unsigned char oldmask, tc;
    unsigned drain, blocks = 0;
    unsigned long t0, t;

    if (argc > 1) {
        char c = argv[1][0];
        if (c == 'a' || c == 'A') mode = M_AUTO;
        else if (c == 's' || c == 'S') mode = M_SING;
        else mode = M_CLI;
    }
    printf("sbtest: mode=%s\n",
           mode == M_AUTO ? "auto-init" : mode == M_SING ? "single-cycle"
                                                         : "single+CLI-wait");

    if (!dsp_reset()) { printf("sbtest: DSP reset FAILED\n"); return 1; }
    printf("sbtest: DSP reset OK\n");

    old_vec = getvect(SB_VEC);
    setvect(SB_VEC, sb_isr);
    oldmask = inportb(PIC_MASK);
    outportb(PIC_MASK, oldmask & ~(1 << SB_IRQ));

    dsp_write(0xD1);
    tc = (unsigned char)(256U - (1000000UL / SRATE));
    dsp_write(0x40); dsp_write(tc);

    if (mode == M_AUTO) {
        unsigned s;
        for (s = 0; s < NSEG; s++) fill(s * SEGSZ, SEGSZ);
        cur_seg = 0;
        dma_program(NSAMP, 1);
        dsp_write(0x48);
        dsp_write((SEGSZ - 1) & 0xFF);
        dsp_write((SEGSZ - 1) >> 8);
        dsp_write(0x1C);                     /* 8-bit auto-init DMA */
        printf("sbtest: auto-init Ode to Joy @ %u B/IRQ ...\n", SEGSZ);
        while (!finished) ;
        drain = irqs + NSEG + 2;
        while (irqs < drain) ;
        dsp_write(0xDA);
    } else {
        while (!finished) {
            fill(0, NSAMP);
            dma_program(NSAMP, 0);
            done = 0;
            dsp_write(0x14);                 /* 8-bit single-cycle DMA */
            dsp_write((NSAMP - 1) & 0xFF);
            dsp_write((NSAMP - 1) >> 8);
            blocks++;
            printf("sbtest: block %u armed, waiting SB IRQ...\n", blocks);
            while (!done) ;                  /* SB IRQ (sbsing-proven OK) */
            printf("sbtest: block %u IRQ; 8237 count at ISR = %04X "
                   "(Dune2 expects FFFF)\n", blocks, isr_count);

            if (mode == M_CLI) {
                /* Dune2 post-speech shape: cli to read the BIOS tick
                 * atomically, sti, loop until the timer ISR bumps it.
                 * If virtual IF is stuck after the SB IRQ the timer is
                 * never delivered -> deadlock here (vpic pending=[08]). */
                printf("sbtest: block %u CLI tick-wait...\n", blocks);
                t0 = *((unsigned long far *) MK_FP(0x40, 0x6C));
                for (;;) {
                    disable();
                    t = *((unsigned long far *) MK_FP(0x40, 0x6C));
                    enable();
                    if (t - t0 >= 2UL) break;
                }
                printf("sbtest: block %u tick advanced\n", blocks);
            }
        }
    }

    dsp_write(0xD3);
    outportb(PIC_MASK, oldmask);
    setvect(SB_VEC, old_vec);
    printf("sbtest: done (irqs=%u blocks=%u)\n", irqs, blocks);
    return 0;
}
