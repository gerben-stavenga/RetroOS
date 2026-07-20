/* vbetest.c - VESA VBE bring-up / colour test for RetroOS.
 *
 * Real-mode Borland C (Turbo C 2.x / Borland C++ 3.1). Build, e.g.:
 *     tcc -ms vbetest.c            (small model)   -> VBETEST.EXE
 *  or bcc -ml vbetest.c
 *
 * A real-mode binary can't address a 32-bit linear framebuffer, so this uses
 * the *banked* window at A000:0000 with VBE function 4F05h to switch the 64 KB
 * bank. That exercises our personality VBE: 4F00 (controller info), 4F01 (mode
 * info), 4F02 (set mode) and 4F05 (window control).
 *
 * Usage:
 *     VBETEST            list the VBE modes the BIOS reports (run this first to
 *                        learn the mode numbers our BIOS exposes)
 *     VBETEST 105        set mode 0x105 and paint a colour test, key to exit
 *
 * The colour test:
 *   - 8bpp  : a 3:3:2 palette is loaded into the DAC and the screen is filled
 *             with an (x XOR y) plasma so every index is exercised in colour.
 *   - 15/16/24/32bpp : true-colour ramp - red across X, green down Y, blue 0x80
 *             - packed per the mode-info channel masks, so any format we report
 *             is honoured.
 */

#include <dos.h>
#include <conio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char  u8;
typedef unsigned int   u16;
typedef unsigned long  u32;

/* --- VBE mode info block (the fields we use) --------------------------
 * Compile with byte alignment (Turbo C / Borland default; do NOT pass -a),
 * so these offsets match the VBE spec exactly. */
struct vbe_mode_info {
    u16 attributes;          /* 0x00 */
    u8  win_a_attr;          /* 0x02 */
    u8  win_b_attr;          /* 0x03 */
    u16 win_granularity;     /* 0x04  KB */
    u16 win_size;            /* 0x06  KB */
    u16 win_a_segment;       /* 0x08 */
    u16 win_b_segment;       /* 0x0A */
    u32 win_func_ptr;        /* 0x0C */
    u16 bytes_per_line;      /* 0x10 */
    u16 x_res;               /* 0x12 */
    u16 y_res;               /* 0x14 */
    u8  x_char, y_char;      /* 0x16,0x17 */
    u8  planes;              /* 0x18 */
    u8  bpp;                 /* 0x19 */
    u8  banks;               /* 0x1A */
    u8  memory_model;        /* 0x1B  4=packed, 6=direct */
    u8  bank_size;           /* 0x1C */
    u8  image_pages;         /* 0x1D */
    u8  rsvd0;               /* 0x1E */
    u8  red_mask,  red_pos;  /* 0x1F,0x20 */
    u8  grn_mask,  grn_pos;  /* 0x21,0x22 */
    u8  blu_mask,  blu_pos;  /* 0x23,0x24 */
    u8  rsv_mask,  rsv_pos;  /* 0x25,0x26 */
    u8  direct_attr;         /* 0x27 */
    u32 phys_base;           /* 0x28  LFB (unused here) */
    u8  pad[256 - 0x2C];
};

/* --- VBE controller info block (subset) ------------------------------- */
struct vbe_info {
    u8  signature[4];        /* "VESA" */
    u16 version;             /* 0x0200 = 2.0 */
    u32 oem_ptr;             /* far ptr */
    u32 capabilities;
    u32 mode_ptr;            /* far ptr to u16 list, 0xFFFF-terminated */
    u16 total_memory;        /* in 64 KB blocks */
    u8  pad[256 - 0x14];
};

static struct vbe_mode_info mi;
static struct vbe_info      vi;

/* current banked-window state */
static u16 win_seg;
static u32 win_gran;     /* bank granule in bytes */
static int cur_bank = -1;

static int get_ctrl_info(void)
{
    union REGS r; struct SREGS s;
    void far *p = (void far *) &vi;
    memcpy(vi.signature, "VBE2", 4);   /* request VBE 2.0 extended block */
    segread(&s);
    r.x.ax = 0x4F00;
    s.es   = FP_SEG(p);
    r.x.di = FP_OFF(p);
    int86x(0x10, &r, &r, &s);
    return r.x.ax == 0x004F;
}

static int get_mode_info(u16 mode)
{
    union REGS r; struct SREGS s;
    void far *p = (void far *) &mi;
    segread(&s);
    r.x.ax = 0x4F01;
    r.x.cx = mode;
    s.es   = FP_SEG(p);
    r.x.di = FP_OFF(p);
    int86x(0x10, &r, &r, &s);
    return r.x.ax == 0x004F;
}

static int set_mode(u16 mode)
{
    union REGS r;
    r.x.ax = 0x4F02;
    r.x.bx = mode;            /* banked, clear memory (bits 14,15 = 0) */
    int86(0x10, &r, &r);
    return r.x.ax == 0x004F;
}

static void set_text_mode(void)
{
    union REGS r;
    r.x.ax = 0x0003;
    int86(0x10, &r, &r);
}

/* VBE 4F05h - set window A to 64 KB granule `bank`. */
static void set_bank(u16 bank)
{
    union REGS r;
    r.x.ax = 0x4F05;
    r.x.bx = 0x0000;         /* BH=0 set, BL=0 window A */
    r.x.dx = bank;
    int86(0x10, &r, &r);
}

/* Write one byte at linear framebuffer offset `lin`, banking as needed. */
static void put_b(u32 lin, u8 val)
{
    int bank = (int)(lin / win_gran);
    u16 off  = (u16)(lin % win_gran);
    if (bank != cur_bank) { set_bank((u16)bank); cur_bank = bank; }
    *((u8 far *) MK_FP(win_seg, off)) = val;
}

/* Pack r,g,b (0..255) into this mode's pixel per its channel masks. */
static u32 pack_rgb(int r, int g, int b)
{
    u32 v = 0;
    v |= ((u32)(r >> (8 - mi.red_mask))) << mi.red_pos;
    v |= ((u32)(g >> (8 - mi.grn_mask))) << mi.grn_pos;
    v |= ((u32)(b >> (8 - mi.blu_mask))) << mi.blu_pos;
    return v;
}

/* Load a 3:3:2 RGB palette into the VGA DAC (6-bit components). */
static void load_332_palette(void)
{
    int i;
    outportb(0x3C8, 0);
    for (i = 0; i < 256; i++) {
        outportb(0x3C9, (u8)(((i >> 5) & 7) * 9));   /* R: 3 bits */
        outportb(0x3C9, (u8)(((i >> 2) & 7) * 9));   /* G: 3 bits */
        outportb(0x3C9, (u8)((i & 3) * 21));         /* B: 2 bits */
    }
}

static void paint(void)
{
    u16 xr = mi.x_res, yr = mi.y_res;
    u16 pitch = mi.bytes_per_line;
    int bpp = mi.bpp ? mi.bpp : 8;
    int bytespp = (bpp + 7) / 8;
    u16 x, y;
    u32 lin;

    win_seg  = mi.win_a_segment ? mi.win_a_segment : 0xA000;
    win_gran = (u32) mi.win_granularity * 1024UL;
    if (win_gran == 0) win_gran = 65536UL;
    cur_bank = -1;

    if (bpp <= 8) load_332_palette();

    for (y = 0; y < yr; y++) {
        for (x = 0; x < xr; x++) {
            lin = (u32) y * pitch + (u32) x * bytespp;
            if (bpp <= 8) {
                put_b(lin, (u8)(x ^ y));             /* plasma through 3:3:2 */
            } else {
                int r = (int)((u32) x * 255 / xr);
                int g = (int)((u32) y * 255 / yr);
                u32 px = pack_rgb(r, g, 0x80);
                int k;
                for (k = 0; k < bytespp; k++)
                    put_b(lin + k, (u8)(px >> (8 * k)));
            }
        }
    }
}

static void list_modes(void)
{
    u16 far *list;
    u16 m;

    if (!get_ctrl_info()) { cprintf("4F00 (controller info) failed\r\n"); return; }
    cprintf("VBE %u.%u  sig=%c%c%c%c  vram=%lu KB\r\n",
            vi.version >> 8, vi.version & 0xFF,
            vi.signature[0], vi.signature[1], vi.signature[2], vi.signature[3],
            (u32) vi.total_memory * 64UL);

    list = (u16 far *) MK_FP((u16)(vi.mode_ptr >> 16), (u16) vi.mode_ptr);
    cprintf("mode  res        bpp model\r\n");
    while ((m = *list++) != 0xFFFF) {
        if (!get_mode_info(m)) continue;
        cprintf(" %03X  %4ux%-4u  %3u  %s\r\n",
                m, mi.x_res, mi.y_res, mi.bpp,
                mi.memory_model == 6 ? "direct" :
                mi.memory_model == 4 ? "packed" : "other");
    }
}

int main(int argc, char **argv)
{
    u16 mode;

    if (argc < 2) {
        list_modes();
        cprintf("\r\nrun  VBETEST <hex-mode>  to set a mode and paint\r\n");
        return 0;
    }

    mode = (u16) strtoul(argv[1], (char **) 0, 16);
    if (!get_mode_info(mode)) { cprintf("4F01 failed for mode %X\r\n", mode); return 1; }
    if (!set_mode(mode))      { cprintf("4F02 failed for mode %X\r\n", mode); return 1; }

    paint();
    getch();
    set_text_mode();
    return 0;
}
