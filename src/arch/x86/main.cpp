#include <algorithm>
#include <array>
#include <type_traits>

struct Regs {
    std::uint64_t gs;
    std::uint64_t fs;
    std::uint64_t r15, r14, r13, r12, r11, r10, r9, r8, rdi, rsi, rbp, rdx, rcx, rbx, rax;
    std::uint64_t int_no, err_code;
    std::uint64_t rip, cs, rflags, rsp, ss;
};

struct DescriptorPtr {
    std::uint16_t limit;
    void* base;
} __attribute__((packed));

struct GdtEntry {
    std::uint16_t limit_low;
    std::uint16_t base_low;
    std::uint8_t base_middle;
    std::uint8_t access;
    std::uint8_t granularity;
    std::uint8_t base_high;
} __attribute__((packed));

struct IdtEntry {
    std::uint16_t base_lo;
    std::uint16_t sel;
    std::uint8_t zero;
    std::uint8_t flags;
    std::uint16_t base_mid;
    std::uint32_t base_hi;
    std::uint32_t reserved;
} __attribute__((packed));

inline void outb(std::uint16_t port, std::uint8_t data) {
    asm volatile("outb %0, %1" : : "a"(data), "d"(port));
}
inline std::uint8_t inb(std::uint16_t port) {
    std::uint8_t data;
    asm volatile("outb %0, %1" : "=a"(data) : "d"(port));
    return data;
}

typedef void (*isr_t)(Regs*);

static const isr_t syscall_table[2] = {

};

template <typename T, size_t N>
constexpr size_t array_size(const T (&)[N]) {
    return N;
}

inline void DoIrq(Regs* regs, int irq) {
}

static void divide_error(Regs* regs) {}
static void debug(Regs* regs) {}
static void nmi(Regs* regs) {}
static void int3(Regs* regs) {}
static void overflow(Regs* regs) {}
static void bounds(Regs* regs) {}
static void invalid_op(Regs* regs) {}
static void device_not_available(Regs* regs) {}
static void double_fault(Regs* regs) {}
static void coprocessor_segment_overrun(Regs* regs) {}
static void invalid_TSS(Regs* regs) {}
static void segment_not_present(Regs* regs) {}
static void stack_segment(Regs* regs) {}
static void general_protection(Regs* regs) {}
static void page_fault(Regs* regs) {}
static void coprocessor_error(Regs* regs) {}
static void reserved(Regs* regs) {}
static void alignment_check(Regs* regs) {}
static void unknown_exception_handler(Regs* regs) {}

static void MasterIrqHandler(Regs* regs) {
    int irq = regs->int_no - 32;
    std::uint8_t mask = 1 << irq;
    // Block IRQ
    outb(0x21, inb(0x21) | mask);
    // Acknowledge PIC
    outb(0x20, 0x20);

    DoIrq(regs, irq);

    // Unblock IRQ
    outb(0x21, inb(0x21) & ~mask);
}

static void SlaveIrqHandler(Regs* regs) {
    int irq = regs->int_no - 32;
    std::uint8_t mask = 1 << (irq - 8);
    // Block IRQ
    outb(0xA1, inb(0xA1) | mask);
    // Acknowledge PIC
    outb(0x20, 0x20);
    outb(0xA0, 0x20);

    DoIrq(regs, irq);

    // Unblock IRQ
    outb(0xA1, inb(0xA1) & ~mask);
}

static void Ignore(Regs*) {}

constexpr int ENOSYS = 100;

static void SystemCall(Regs* regs) {
    if (regs->rax >= array_size(syscall_table) || !syscall_table[regs->rax]) {
        regs->rax = -ENOSYS;
        return;
    }
    syscall_table[regs->rax](regs);
}

constexpr isr_t IsrHandler(int i) {
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

template <size_t... seq>
constexpr std::array<isr_t, 256> MakeTable(std::index_sequence<seq...>) {
    return std::array<isr_t, 256>{IsrHandler(seq)...};
}

static const std::array<isr_t, 256> isr_table = MakeTable(std::make_index_sequence<256>{});

IdtEntry MakeEntry(std::uint64_t base, std::uint16_t sel, std::uint8_t flags) {
    IdtEntry entry{};
    base += 8 * i;
    entry.base_lo = base & 0xFFFF;
    entry.base_mid = (base >> 16) & 0xFFFF;
    entry.base_hi = (base >> 32) & 0xFFFFFFFF;
    entry.sel = sel;
    entry.ist = 0;
    entry.flags = flags;
}

static std::array<IdtEntry, 256> idt;

extern "C" void int_vector();

void InitInterrupts() {
    auto base = reinterpret_cast<std::uint64_t>(&int_vector);
    for (int i = 0; i < 256; ++i) {
        auto flags = i < 32 ? 0x8F : (0x8E + (i == 0x80 ? 0x60 : 0));

        idt[i] = MakeEntry(base + 8 * i, 0x8, flags);
    }


    DescriptorPtr idt_ptr{sizeof(idt) - 1, idt.data()};
    asm("lidt %0" : : "m"(idt_ptr));

    // Enable interrupts
    asm volatile("sti");
}

static std::uint64_t page_table[512] __attribute__((aligned(4096)));
static std::uint64_t page_dir[512] __attribute__((aligned(4096)));
static std::uint64_t pdp[512] __attribute__((aligned(4096)));
static std::uint64_t pml4[512] __attribute__((aligned(4096)));

// Map page 0 to not-present (NULL ptr)
//
void SetupPaging() {
    pml4[0] = reinterpret_cast<uint64_t >(pdp) | 3;
    pdp[0] = reinterpret_cast<uint64_t >(page_dir) | 3;
    page_dir[0] = reinterpret_cast<uint64_t >(page_table) | 3;

    // Identity map first 2MB
    for (int i = 0; i < 512; ++i) {
        page_table[i] = i * 0x1000 + 3;
    }

    // Map page table
    page_table[511] = reinterpret_cast<std::uint64_t>(page_table) + 3;

    asm volatile(
            "cli\n\t"
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
            : : "r"(pml4) : "%0");

    InitInterrupts();

}

extern "C" void isr_handler(Regs* regs) {
    isr_table[regs->int_no](regs);
}
