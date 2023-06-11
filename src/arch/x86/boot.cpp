//
// Created by gerben stavenga on 6/11/23.
//

#include <stdint.h>

#include "src/freestanding/utils.h"

constexpr uintptr_t kKernelAddress = 0x1000;
constexpr int kKernelLBA = 6;
constexpr int kKernelSize = 20;

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

static Regs& regs = *reinterpret_cast<Regs*>(0x7c08);

void printhello() {
    char hello[] = "hello";
    uint16_t* video = reinterpret_cast<uint16_t*>(0xb8000);
    for (int i = 0; hello[i]; i++) {
        video[i] = hello[i] | 0x700;
    }
}

void generate_real_interrupt(int interrupt) {
    asm volatile(
            "movl (,%%eax, 4), %%eax\n\t"
            "lcall *(0x7c2c)\n\t"
            :"+a"(interrupt):: "edx", "memory", "cc");
}

__attribute__((noinline)) void hlt() {
    while (true) asm volatile ("hlt\n\t");
}

struct Out {
    void put(char c) {
        if (c == '\n') put(13);
        regs.ax = 0xe00 | c;
        regs.bx = 7;
        generate_real_interrupt(0x10);
    }

    int GetCursor() {
        regs.ax = 0x300;
        regs.bx = 0;
        generate_real_interrupt(0x10);
        return regs.dx;
    }
};

inline int min(int a, int b) { return a < b ? a : b; }

static bool read_disk(int drive, int lba, int count, void *buffer) {
    int sectors_per_track;
    int num_heads;

    if (drive & 0x80) {
        regs.ax = 0x800;
        regs.dx = drive;
        generate_real_interrupt(0x13);
        if ((regs.flags & 1) != 0) {
            return false;
        }
        sectors_per_track = regs.cx & 0x3F;
        num_heads = ((regs.dx >> 8) & 0xFF) + 1;
    } else {
        // Should probe
        sectors_per_track = 18;
        num_heads = 2;
    }
    Out out;
    print(out, "Disk params num_heads: {} sectors_per_track: {}\n", num_heads, sectors_per_track);

    // Use int 13 to read disk
    auto address = reinterpret_cast<uintptr_t>(buffer);
    while (count > 0) {
        int sector = lba % sectors_per_track;
        int head = lba / sectors_per_track;
        int cylinder = head / num_heads;
        head = head % num_heads;

        int nsectors = min(count, min(127, sectors_per_track * num_heads - sector));

        Out out;
        print(out, "sect {} head {} cyl {} nsectors {}\n", sector, head, cylinder, nsectors);

        regs.es = address >> 4;
        regs.bx = address & 0xF;

        regs.ax = 0x0200 + nsectors;
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

extern "C" void BootLoader(int drive) {
    Out out;
    print(out, "Booting from drive: {}\n", char(drive >= 0x80 ? 'c' + drive - 0x80 : 'a' + drive));
    void* buffer = reinterpret_cast<void*>(kKernelAddress);
    print(out, "Loading kernel at {}\n", buffer);
    read_disk(drive, kKernelLBA, kKernelSize, buffer);
    using KernelMain = void (*)(int cursor);
    reinterpret_cast<KernelMain>(buffer)(out.GetCursor());
}
