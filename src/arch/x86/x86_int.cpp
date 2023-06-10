//
// Created by gerben stavenga on 6/9/23.
//
#include <stdint.h>

struct Regs {
    uint32_t ax;
    uint32_t bx;
    uint32_t cx;
    uint32_t dx;
    uint32_t si;
    uint32_t di;
    uint32_t bp;
    uint32_t flags;
    uint16_t ds;
    uint16_t es;
};

extern "C" Regs regs;
Regs regs;

void generate_real_interrupt(int interrupt) {
    asm volatile(
            ".extern x86_16_gen_interrupt\n\t"
            "movl (,%%eax, 4), %%eax\n\t"
            "lcall $0x18,$x86_16_gen_interrupt\n\t"
            :"+a"(interrupt):: "edx", "memory", "cc");
}

inline int min(int a, int b) { return a < b ? a : b; }

static bool read_disk(int drive, int lba, int count, void *buffer) {
    int sectors_per_track;
    int heads;

    if (drive & 0x80) {
        regs.ax = 0x200;
        regs.dx = drive;
        generate_real_interrupt(0x13);
        if ((regs.flags & 1) != 0) {
            return false;
        }
        sectors_per_track = regs.cx & 0x3F;
        heads = ((regs.dx >> 8) & 0xFF) + 1;
    } else {
        // Should probe
        sectors_per_track = 18;
        heads = 2;
    }

    // Use int 13 to read disk
    auto address = reinterpret_cast<uintptr_t>(buffer);
    do {
        int sector = lba % sectors_per_track;
        int head = lba / sectors_per_track;
        int cylinder = head / heads;
        head = head % heads;

        int nsectors = min(count, min(127, sectors_per_track - sector));

        regs.es = address >> 4;
        regs.di = address & 0xF;

        regs.ax = 0x0200 + nsectors;
        regs.bx = (drive << 8) | count;
        regs.cx = (cylinder << 8) | (sector + 1) | ((cylinder >> 2) & 0xC0);
        regs.dx = (head << 8) | drive;
        generate_real_interrupt(0x13);
        if ((regs.flags & 1) != 0) {
            return false;
        }
        lba += nsectors;
        address += 512 * nsectors;
        count -= nsectors;
    } while (count > 0);
    return true;
}
