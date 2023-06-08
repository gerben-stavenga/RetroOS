//
// Created by gerben stavenga on 6/5/23.
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

struct DescriptorPtr {
    uint16_t limit;
    void* base;
} __attribute__((packed));

struct AccessWord {
    uint16_t base_mid: 8;
    uint16_t access: 1;
    uint16_t rw: 1;
    uint16_t dc: 1;
    uint16_t ex: 1;
    uint16_t special: 1;
    uint16_t dpl: 2;
    uint16_t present: 1;
};

constexpr AccessWord access_word(bool ex, bool special, uint8_t dpl, bool present) {
    return AccessWord{0, 0, 1, 0, ex, special, dpl, present};
}

constexpr auto kernel_access_cs = access_word(true, true, 0, true);
constexpr auto kernel_access_ds = access_word(false, true, 0, true);
constexpr auto user_access_cs = access_word(true, true, 3, true);
constexpr auto user_access_ds = access_word(false, true, 3, true);
constexpr auto null_access = AccessWord{0, 0, 0, 0, 0, 0, 0, 0};

struct FlagsWord {
    uint16_t limit_high: 4;
    uint16_t reserved: 2;
    uint16_t big: 1;
    uint16_t granularity: 1;
    uint16_t base_high: 8;
};

constexpr FlagsWord flags_word(bool big) {
    return FlagsWord{static_cast<uint16_t>(big ? 0xF : 0), 0, big, big, 0};
}

constexpr auto k32_flags = flags_word(true);
constexpr auto k16_flags = flags_word(false);
constexpr auto null_flags = FlagsWord{0, 0, 0, 0, 0};

struct GdtEntry {
    uint32_t limit_base_low;
    AccessWord access;
    FlagsWord flags;
} __attribute__((packed));

GdtEntry gdt[7] = {
        {0, null_access, null_flags},
        {0xFFFF, kernel_access_cs, k32_flags},  // cs = 0x8
        {0xFFFF, kernel_access_ds, k32_flags},  // ds = 0x10
        {0xFFFF, user_access_cs, k32_flags},  // cs = 0x18
        {0xFFFF, user_access_ds, k32_flags},  // ds = 0x20
        {0xFFFF, kernel_access_cs, k16_flags},  // cs = 0x28
        {0xFFFF, kernel_access_ds, k16_flags},  // ds = 0x30
};

struct IdtEntry {
    uint16_t offset_low;
    uint16_t selector;
    uint16_t flags;
    uint16_t offset_high;
} __attribute__((packed));

extern "C" IdtEntry idt[256];

void SetupIDT() {
    idt[0x80].flags |= 0x6000;  // User interrupt, so DPL = 3
}

extern "C" DescriptorPtr gdt_ptr;
DescriptorPtr gdt_ptr = {sizeof(gdt) - 1, gdt};
extern "C" DescriptorPtr idt_ptr;
DescriptorPtr idt_ptr = {sizeof(idt) - 1, 0};
extern "C" DescriptorPtr real_mode_idt_ptr;
DescriptorPtr real_mode_idt_ptr = { 0x3FF, 0 };

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

extern "C" void isr_handler() {
    asm volatile("hlt");
}

extern "C" void kmain(int drive) {
    SetupIDT();
    const char *msg = "Hello, world!\n";
    uint16_t *video = reinterpret_cast<uint16_t *>(0xB8000);
    for (int i = 0; i < 80 * 25; ++i) {
        video[i] = 0x0700 | ' ';
    }
    for (int i = 0; msg[i] != '\0'; ++i) {
        video[i] = 0x0700 | msg[i];
    }
    while (true) {
        asm volatile("hlt");
    }
}
