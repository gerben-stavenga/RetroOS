//
// Created by gerben stavenga on 6/5/23.
//
#include <stdint.h>
#include <stddef.h>

#include "src/freestanding/utils.h"
#include "descriptors.h"
#include "x86_inst.h"

#define NOINLINE __attribute__((noinline))

constexpr int kKernelCS = 0x8;
constexpr int kKernelDS = 0x10;
constexpr int kUserCS = 0x18;
constexpr int kUserDS = 0x20;

DescriptorEntry gdt[6] = {
        {},
        MakeSegDesc(true, true, 0),  // cs = 0x8
        MakeSegDesc(true, false, 0),  // ds = 0x10
        MakeSegDesc(true, true, 3),  // cs = 0x18
        MakeSegDesc(true, false, 3),  // ds = 0x20
        {}, // TSS
//        {0xFFFF, kernel_access_cs, k16_flags},  // cs = 0x28
//        {0xFFFF, kernel_access_ds, k16_flags},  // ds = 0x30
};

constexpr int kIdtEntries = 0x81;
constexpr int kIsrEntries = 49;
IdtEntry idt[kIdtEntries];

struct InterruptEntry { uint8_t code[8]; };
extern "C"  InterruptEntry int_vector[];

NOINLINE static void hlt() {
    while (true) hlt_inst();
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

template<typename... Args>
void panic(string_view format, const Args&... args) {
    screen.ClearScreen();
    print(screen, "Kernel panic: ");
    print(screen, format, args...);
    hlt();
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
    static uint8_t key_state[16];
    switch (irq) {
        case 0:
            if ((counter++) & 0xF) return;
            break;
        case 1: {
            int key = inb(0x60);
            key_state[(key & 0x7f) >> 3] = (key >> 7) << (key & 7);
            print(screen, "Key: {} {}\n", key & 0x7F, key & 0x80 ? "released" : "pressed");
            break;
        }
        default:
            break;
    }
    print(screen, "IRQ: {} time counter {}\n", irq, counter);
}

enum Signals : int {
    SIGFPE, SIGTRAP, SIGSEGV, SIGILL, SIGBUS
};

struct GenericException {
    int signal;
    string_view name;
};
GenericException exceptions[32] = {
        {SIGFPE, "divide error"},  // 0
        {-1, "debug"},
        {-1, "non-maskable interrupt"},
        {SIGTRAP, "int3"},  // 3
        {SIGSEGV, "overflow"},  // 4
        {SIGSEGV, "bounds"},  // 5
        {SIGILL, "invalid operand"},  // 6
        {SIGSEGV, "device not available"},  // 7
        {SIGSEGV, "double fault"},  // 8
        {SIGFPE, "coprocessor segment overrun"},  // 9
        {SIGSEGV, "invalid TSS"},  // 10
        {SIGBUS, "segment not present"},  // 11
        {SIGBUS, "stack segment"},  // 12
        {-1, "general protection"},  // 13
        {-1, "page fault"},  // 14
        {SIGSEGV, "reserved"},  // 15
        {-1, "coprocessor error"},  // 16
        {SIGSEGV, "alignment check"},  // 17
};

static void generic_exception_handler(Regs* regs) {
    auto int_no = regs->int_no;
    auto signal = exceptions[int_no].signal;

    panic("An unsupported exception, signal = {} name = {}\n", signal, exceptions[regs->int_no].name);
}

static void unknown_exception_handler(Regs* regs) {
    panic("An unsupported exception {}", int(regs->int_no));
}

static void debug(Regs*) {
    panic("Debug");
}

static void coprocessor_error(Regs*) {
    panic("Coprocessor error");
}

static void nmi(Regs*) {
    // There are mainly two ways a non-maskable interrupt occurs
    // 1) Hardware failure (best to inform user and hang)
    // 2) Watchdog timer (not supported thus hang)
    panic("Non-maskable interrupt received, most likely hardware failure");
}

static void double_fault(Regs*) {
    // Only a kernel bug can trigger a double fault, hence we should die
    panic("Kernel bug: double_fault");
}

static void general_protection(Regs* regs) {
    panic("GP {}", regs->err_code);
}

static void page_fault(Regs* regs) {
    panic("page fault {}\n", regs->err_code);
}

static void IrqHandler(Regs* regs) {
    int irq = regs->int_no - 32;
    constexpr uint16_t kMasterPort = 0x20;
    constexpr uint16_t kSlavePort = 0xA0;
    uint8_t mask = 1 << (irq & 7);
    uint16_t pic_port = (irq >= 8 ? kSlavePort : kMasterPort) + 1;
    // Block IRQ
    outb(pic_port, inb(pic_port) | mask);
    // Acknowledge PIC
    if (irq >= 8) outb(kSlavePort, 0x20);
    outb(kMasterPort, 0x20);

    EnableIRQ();

    DoIrq(irq);

    DisableIRQ();

    // Unblock IRQ
    outb(pic_port, inb(pic_port) & ~mask);
}

constexpr int ENOSYS = 100;

static void SystemCall(Regs* regs) {
    print(screen, "Syscall {}", regs->eax);
    if (regs->eax >= array_size(syscall_table) || !syscall_table[regs->eax]) {
        regs->eax = -ENOSYS;
        return;
    }
    syscall_table[regs->eax](regs);
}

struct IsrTable {
    EntryHandler entries[kIsrEntries];
};

constexpr EntryHandler IsrHandler(int i) {
    switch (i) {
        case 1: return debug;
        case 2: return nmi;
        case 8: return double_fault;
        case 13: return general_protection;
        case 14: return page_fault;
        case 16: return coprocessor_error;

        case 0:
        case 3 ... 7:
        case 9 ... 12:
        case 17:
            return generic_exception_handler;

        case 15:
        case 18 ... 31:
            return unknown_exception_handler;

        case 32 ... 47:  // IRQ0 ... IRQ15
            return IrqHandler;
        case 48:
            return SystemCall;
        default:
            return nullptr;
    }
}

constexpr IsrTable MakeTable() {
    IsrTable table{};
    for (int i = 0; i < kIsrEntries; i++) table.entries[i] = IsrHandler(i);
    return table;
}

const IsrTable isr_table = MakeTable();

NOINLINE static void RemapInterrupts() {
    // Mask all interrupts
    outb(0x21, 0xFF);
    outb(0xA1, 0xFF);

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

    // Unmask all interrupts
    outb(0x21, 0);
    outb(0xA1, 0);
}

NOINLINE static void SetupDescriptorTables() {
    // CPU exceptions
    for (int i = 0; i < 48; i++) {
        int dpl = (i >= 3 && i <= 5) ? 3 : 0;  // int3, into and bounds exception may be generated by users
        idt[i] = MakeInterruptGate(int_vector + i, dpl);
    }
    // Set int 0x80 syscall
    idt[0x80] = MakeInterruptGate(int_vector + 48, 3);

    LoadGDT(gdt, sizeof(gdt));
    LoadIDT(idt, sizeof(idt));

    // Reload all segments 
    asm volatile (
            "mov %0, %%ds\n\t"
            "mov %0, %%es\n\t"
            "mov %0, %%fs\n\t"
            "mov %0, %%gs\n\t"
            "ljmpl $0x8, $1f\n\t"  // use jmp to reload cs
            "1:\n\t"
            ::"r"(kKernelDS));
}

struct PageEntry {
    uint32_t present : 1;
    uint32_t read_write : 1;
    uint32_t user_super : 1;
    uint32_t zero1 : 2;
    uint32_t accessed : 1;
    uint32_t dirty : 1;
    uint32_t zero2 : 2;
    uint32_t available : 3;
    uint32_t offset : 20;
} __attribute__((packed));

alignas(4096) PageEntry page_tables[4][1024];
alignas(4096) PageEntry page_dir[1024];

// Linear memory layout
// [0, 0x1000) null page (not present)
// [0x1000, 0xFF000000) user space (mapping dep
// [0xFF000000, 0xFFC00000) 16 mb kernel space (fixed mapping)
// [0xFFC00000, 0x100000000) 4 mb of 1m page tables entries covering the 4gb address space
// [0xFFFFF000, 0x100000000) page table covering [0xFFC00000, 0x100000000) and simultaneous page dir

constexpr uintptr_t kKernelBase = 0xFF000000;
constexpr uintptr_t kCurPageTab = 0xFFC00000;
constexpr uintptr_t kCurPageDir = 0xFFFFF000;

inline uintptr_t Cast(const void* p) {
    return reinterpret_cast<uintptr_t>(p);
}

inline uintptr_t CurrentCR3() {
    return *reinterpret_cast<uint32_t*>(-4);
}

inline uintptr_t PhysAddress(const void* p) {
    uintptr_t linear = reinterpret_cast<uintptr_t>(p);
    return (reinterpret_cast<const uint32_t*>(0xFFC00000)[linear >> 12] & -4096) + (linear & 4095);
}

inline constexpr PageEntry MakePageEntry(uintptr_t address) {
    return PageEntry{1, 1, 1, 0, 0, 0, 0, 0, address >> 12};
}

extern "C" void SetupPaging(uintptr_t phys_address) {
    auto ptables = reinterpret_cast<PageEntry (*)[1024]>(Cast(page_tables) - kKernelBase + phys_address);
    PageEntry* pdir = reinterpret_cast<PageEntry*>(Cast(page_dir) - kKernelBase + phys_address);

    // Identity map the lowest 4mb
    for (unsigned i = 0; i < 1024; i++) {
        ptables[0][i] = MakePageEntry(i << 12);
    }
    // stack is there for now so commented out
    // ptables[0][0] = PageEntry{};  // make nullptr an exception
    for (unsigned i = 0; i < 3; i++) {
        for (unsigned j = 0; j < 1024; j++) {
            ptables[i + 1][j] = MakePageEntry(((i * 1024 + j) << 12) + phys_address);
        }
    }
    pdir[0] = MakePageEntry(Cast(ptables[0]));
    pdir[0x3FC] = MakePageEntry(Cast(ptables[1]));
    pdir[0x3FD] = MakePageEntry(Cast(ptables[2]));
    pdir[0x3FE] = MakePageEntry(Cast(ptables[3]));
    pdir[0x3FF] = MakePageEntry(Cast(pdir));

    LoadPageDir(reinterpret_cast<uintptr_t>(pdir));

    // Enable paging and RW
    asm volatile (
        "mov %%cr0, %%eax\n\t"
        "or $0x80000000, %%eax\n\t"
        "mov %%eax, %%cr0\n\t"
        :::"ax");
}

extern "C" void isr_handler(Regs* regs) {
    // Convert pushed return address into interrupt number
    regs->int_no = (regs->int_no - reinterpret_cast<uintptr_t>(int_vector)) / 8;
    isr_table.entries[regs->int_no](regs);
}

NOINLINE static void VerifyA20Enabled() {
    print(screen, "Verifying A20\n");
    volatile uint32_t tmp;
    uint32_t volatile* a20_aliased = reinterpret_cast<uint32_t *>(reinterpret_cast<uintptr_t>(&tmp) ^ 0x100000);
    uint32_t cnt = 0;
    do {
        tmp = cnt++;
    } while (tmp == *a20_aliased);
    print(screen, "A20 enabled\n");
}

extern "C" void kmain(int pos) {
    screen.cursor_x = pos & 0xFF;
    screen.cursor_y = (pos >> 8) & 0xFF;

    auto ip = GetIP();
    print(screen, "Entering main kernel\nStack at {} and ip {} at phys address {}\n", &pos, ip, reinterpret_cast<void*>(PhysAddress(ip)));

    VerifyA20Enabled();
    RemapInterrupts();
    SetupDescriptorTables();
    EnableIRQ();

    print(screen, "Boot succeeded\n");
    hlt();
}
