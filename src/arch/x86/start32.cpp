//
// Created by gerben stavenga on 6/5/23.
//
#include <stdint.h>
#include <stddef.h>

#include "src/freestanding/utils.h"

struct DescriptorPtr {
    uint16_t limit;
    const void* base;
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

constexpr int kKernelCS = 0x8;
constexpr int kKernelDS = 0x10;
constexpr int kUserCS = 0x18;
constexpr int kUserDS = 0x20;

const GdtEntry gdt[7] = {
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

IdtEntry idt[256];

extern "C" void int_vector();

void hlt() {
    while (true) {
        asm volatile("hlt\n\t");
    }
}

struct Screen {
    int cursor_x, cursor_y;

    void ClearScreen() {
        uint16_t *video = reinterpret_cast<uint16_t *>(0xB8000);
        memset(video, 0, 80 * 25 * 2);
        cursor_x = cursor_y = 0;
    }

    void put(char c) {
        uint16_t *video = reinterpret_cast<uint16_t *>(0xB8000);
        if (c == '\n') {
            cursor_x = 0;
            cursor_y++;
            if (cursor_y == 25) {
                memmove(video, video + 80, 80 * 24 * 2);
                memset(video + 80 * 24, 0, 80 * 2);
                cursor_y = 24;
            }
        } else {
            if (cursor_x < 80) {
                video[cursor_y * 80 + cursor_x] = 0x700 | c;
            }
            cursor_x++;
        }
    }
};

Screen screen;

inline void outb(uint16_t port, uint8_t data) {
    asm volatile("outb %0, %1" : : "a"(data), "d"(port));
}
inline uint8_t inb(uint16_t port) {
    uint8_t data;
    asm volatile("inb %1, %0" : "=a"(data) : "d"(port));
    return data;
}

// Matches the stack frame of the entry.asm
struct Regs {
    uint32_t gs, fs, es, ds;
    uint32_t edi, esi, ebp, temp_esp, ebx, edx, ecx, eax;
    uint32_t int_no, err_code;
    uint32_t eip, cs, eflags, esp, ss;
};

typedef void (*EntryHandler)(Regs*);

static const EntryHandler syscall_table[1] = {};

inline void DoIrq(int irq) {
    static int counter = 0;
    if (irq == 0) {
        if ((counter++) & 0xF) return;
    }
    print(screen, "IRQ: {} time counter {}\n", irq, counter);
}

static void divide_error(Regs*) {}
static void debug(Regs*) {}
static void nmi(Regs*) {}
static void int3(Regs*) {}
static void overflow(Regs*) {}
static void bounds(Regs*) {}
static void invalid_op(Regs*) {}
static void device_not_available(Regs*) {}
static void double_fault(Regs*) {}
static void coprocessor_segment_overrun(Regs*) {}
static void invalid_TSS(Regs*) {}
static void segment_not_present(Regs*) {}
static void stack_segment(Regs*) {}
static void general_protection(Regs*) {}
static void page_fault(Regs*) {}
static void coprocessor_error(Regs*) {}
static void reserved(Regs*) {}
static void alignment_check(Regs*) {}
static void unknown_exception_handler(Regs*) {}

static void MasterIrqHandler(Regs* regs) {
    int irq = regs->int_no - 32;
    uint8_t mask = 1 << irq;
    // Block IRQ
    outb(0x21, inb(0x21) | mask);
    // Acknowledge PIC
    outb(0x20, 0x20);

    DoIrq(irq);

    // Unblock IRQ
    outb(0x21, inb(0x21) & ~mask);
}

static void SlaveIrqHandler(Regs* regs) {
    int irq = regs->int_no - 32;
    uint8_t mask = 1 << (irq - 8);
    // Block IRQ
    outb(0xA1, inb(0xA1) | mask);
    // Acknowledge PIC
    outb(0x20, 0x20);
    outb(0xA0, 0x20);

    DoIrq(irq);

    // Unblock IRQ
    outb(0xA1, inb(0xA1) & ~mask);
}

static void Ignore(Regs*) {}

template <typename T, size_t N>
constexpr size_t array_size(const T (&)[N]) {
    return N;
}

constexpr int ENOSYS = 100;

static void SystemCall(Regs* regs) {
    if (regs->eax >= array_size(syscall_table) || !syscall_table[regs->eax]) {
        regs->eax = -ENOSYS;
        return;
    }
    syscall_table[regs->eax](regs);
}

struct IsrTable {
    EntryHandler entries[256];
};

constexpr EntryHandler IsrHandler(int i) {
    switch (i) {
        case 0: return divide_error;
        case 1: return debug;
        case 2: return nmi;
        case 3: return int3;	/* int3-5 can be called from all */
        case 4: return overflow;
        case 5: return bounds;
        case 6: return invalid_op;
        case 7: return device_not_available;
        case 8: return double_fault;
        case 9: return coprocessor_segment_overrun;
        case 10: return invalid_TSS;
        case 11: return segment_not_present;
        case 12: return stack_segment;
        case 13: return general_protection;
        case 14: return page_fault;
        case 15: return reserved;
        case 16: return coprocessor_error;
        case 17: return alignment_check;
        case 18 ... 31:
            return unknown_exception_handler;
        case 32 ... 39:  // IRQ0 ... IRQ7
            return MasterIrqHandler;
        case 40 ... 47:  // IRQ8 ... IRQ15
            return SlaveIrqHandler;
        case 0x80:
            return SystemCall;
        default:
            return Ignore;
    }
}

constexpr IsrTable MakeTable() {
    IsrTable table{};
    for (int i = 0; i < 256; i++) table.entries[i] = IsrHandler(i);
    return table;
}

const IsrTable isr_table = MakeTable();

void RemapInterrupts() {
    // Remap PIC such that IRQ 0 .. 15 are directed to interrupts 32 .. 47
    // INIT | ICW4
    outb(0x20, 0x11);
    outb(0xA0, 0x11);
    // Set interrupt offset master PIC starts at 32 (0x20) and slave PIC at 40 (0x28)
    outb(0x21, 0x20);
    outb(0xA1, 0x28);
    // Cascade identity, set irq 2 of master to slave
    outb(0x21, 0x04);
    outb(0xA1, 0x02);
    // ICW4 (8086 mode)
    outb(0x21, 0x01);
    outb(0xA1, 0x01);

    // Mask all interrupts
    outb(0x21, 0xFF);
    outb(0xA1, 0xFF);
}

void SetupDescriptorTables() {
    uintptr_t base = reinterpret_cast<uintptr_t>(int_vector);
    for (int i = 0; i < 256; i++) {
        uint16_t flags = i >= 32 && i < 48 ? 0x8E00 : 0x8F00;
        idt[i] = IdtEntry{static_cast<uint16_t >(base & 0xFFFF), 0x8, flags, static_cast<uint16_t>(base >> 16)};
        base += 8;
    }
    idt[0x80].flags |= 0x6000;  // User interrupt, so DPL = 3

    DescriptorPtr gdt_ptr = {sizeof(gdt) - 1, gdt};
    DescriptorPtr idt_ptr = {sizeof(idt) - 1, idt};

    asm volatile (
            "lidt %2\n\t"
            "lgdt %1\n\t"
            "mov %0, %%ds\n\t"
            "mov %0, %%es\n\t"
            "mov %0, %%fs\n\t"
            "mov %0, %%gs\n\t"
            "ljmpl $0x8, $1f\n\t"
            "1:\n\t"
            "sti\n\t"
            ::"r"(kKernelDS), "m"(gdt_ptr), "m"(idt_ptr):"memory");

    // UnMask all interrupts
    outb(0x21, 0);
    outb(0xA1, 0);
}

void SetupPaging() {
    /*asm volatile (
        // Load page table
            "mov %0, %%cr3\n\t"
            // Enable PAE
            "mov %%cr4, %%0\n\t"
            "or $0x20, %%0\n\t"
            "mov %%0, %%cr4\n\t"
            // Enable paging
            "mov %%cr0, %%0\n\t"
            "or $0x80000000, %%0\n\t"
            " mov %%0, %%cr0\n\t"
            // Set long mode
            "mov $0xC0000080, %%ecx\n\t"
            "rdmsr\n\t"
            "or $0x100, %%eax\n\t"
            "wrmsr\n\t"
            // Enable paging
            "mov %%cr0, %%0\n\t"
            "or $0x80000000, %%0\n\t"
            "mov %%0, %%cr0\n\t"
        // Compatibility mode
            : : "r"(pml4) : "%0");*/
}

extern "C" void isr_handler(Regs* regs) {
    regs->int_no &= 0xFF;
    isr_table.entries[regs->int_no](regs);
}

extern "C" void kmain(int pos) {
    screen.cursor_x = pos & 0xFF;
    screen.cursor_y = (pos >> 8) & 0xFF;
    print(screen, "Entering main kernel with stack at {}\n", &pos);

    RemapInterrupts();
    SetupDescriptorTables();

    print(screen, "Boot succeeded\n");
    hlt();
}
