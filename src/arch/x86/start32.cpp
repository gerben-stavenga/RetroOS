//
// Created by gerben stavenga on 6/5/23.
//
#include <stdint.h>
#include <stddef.h>

#include "src/freestanding/utils.h"
#include "descriptors.h"
#include "x86_inst.h"

#define NOINLINE __attribute__((noinline))

#ifdef NDEBUG
constexpr bool kDebug = false;
#else
constexpr bool kDebug = true;
#endif

// Linear memory layout
// [0, 0x1000) null page (not present)
// [0x1000, 0xFF000000) user space (mapping dep
// [0xFF000000, 0xFFB00000) 15 mb kernel space (fixed mapping)
// [0xFFB00000, 0xFFC00000) 1 mb mapped to physical [0, 1mb)
// [0xFFC00000, 0x100000000) 4 mb of 1m page tables entries covering the 4gb address space
// [0xFFFFF000, 0x100000000) page table covering [0xFFC00000, 0x100000000) and simultaneous page dir

constexpr uintptr_t kKernelBase = 0xFF000000;
constexpr uintptr_t kLowMemBase = 0xFFB00000;
constexpr uintptr_t kCurPageTab = 0xFFC00000;
constexpr uintptr_t kCurPageDir = 0xFFFFF000;

struct Screen {
    int cursor_x, cursor_y;

    void ClearScreen() {
        uint16_t *video = reinterpret_cast<uint16_t *>(kLowMemBase + 0xB8000);
        memset(video, 0, 80 * 25 * 2);
        cursor_x = cursor_y = 0;
    }

    void put(char c) {
        uint16_t *video = reinterpret_cast<uint16_t *>(kLowMemBase + 0xB8000);
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

NOINLINE [[noreturn]] static void hlt() {
    while (true) hlt_inst();
}

template<typename... Args>
void panic(string_view format, const Args&... args) {
    //screen.ClearScreen();
    print(screen, "Kernel panic: ");
    print(screen, format, args...);
    hlt();
}

void kassert_impl(bool cond, string_view cond_str, string_view file, int line) {
    if (!cond && kDebug) panic("Kernel assert: Condition \"{}\" failed at {}:{}.\n", cond_str, file, line);
}

#define kassert(cond) kassert_impl((cond), #cond, __FILE__, __LINE__)

constexpr int kKernelCS = 0x8;
constexpr int kKernelDS = 0x10;
constexpr int kUserCS = 0x18;
constexpr int kUserDS = 0x20;
constexpr int kTSS = 0x28;

alignas(4096) uint8_t kernel_stack[4096];

TSS task_state_segment(kernel_stack + sizeof(kernel_stack), kKernelDS);

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
    static uint8_t key_state[16]; (void)key_state;
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
    // print(screen, "IRQ: {} time counter {}\n", irq, counter);
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

static void page_fault(Regs* regs);

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

    gdt[5] = MakeTSSDescriptor(&task_state_segment);

    LoadGDT(gdt, sizeof(gdt));
    LoadIDT(idt, sizeof(idt));
    LoadTR(kTSS);

    // Reload all segments
    asm volatile (
            "mov %0, %%ds\n\t"
            "mov %0, %%es\n\t"
            "mov %0, %%fs\n\t"
            "mov %0, %%gs\n\t"
            "ljmpl %1, $1f\n\t"  // use jmp to reload cs
            "1:\n\t"
            ::"r"(kKernelDS), "i"(kKernelCS));
}

constexpr unsigned kPageSize = 4096;
constexpr unsigned kNumPageEntries = kPageSize / sizeof(uint32_t);
constexpr int kNumPages = 1 << 20;   // 4GB address space has 1M 4K pages
constexpr int kNumWords = kNumPages / 32;

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

template <typename CharOut>
void print_val(CharOut& out, const PageEntry& e) {
    print(out, "{{p: {}, r/w: {}, u/s: {}, offset: {}}}", e.present, e.read_write, e.user_super, e.offset);
}

struct alignas(kPageSize) PageTable {
    PageEntry entries[kNumPageEntries];
};

static_assert(sizeof(PageTable) == kPageSize);

PageTable page_tables[5];
constexpr PageTable* zero_page = page_tables + 4;

inline uintptr_t Cast(const void* p) {
    return reinterpret_cast<uintptr_t>(p);
}

inline PageEntry* GetCurrentDir() {
    return reinterpret_cast<PageEntry*>(kCurPageDir);
}

inline uintptr_t CurrentCR3() {
    return *reinterpret_cast<uint32_t*>(-4) & -kPageSize;
}

inline uintptr_t PhysAddress(const void* p) {
    uintptr_t linear = reinterpret_cast<uintptr_t>(p);
    return (reinterpret_cast<const uint32_t*>(0xFFC00000)[linear >> 12] & -4096) + (linear & 4095);
}

inline constexpr PageEntry MakePageEntry(uintptr_t address, bool present, bool read_write, bool user_super) {
    return PageEntry{present, read_write, user_super, 0, 0, 0, 0, 0, address >> 12};
}

inline void FlushTLB() {
    LoadPageDir(CurrentCR3());
}

uint32_t available[kNumWords];  // 128KB bit mask

int AllocPhysPage() {
    for (int i = 0; i < kNumWords; i++) {
        if (available[i] != uint32_t (-1)) {
            int j = 0;
            while (available[i] & (1 << j)) j++;
            available[i] |= 1 << j;
            return i * 32 + j;
        }
    }
    return -1;
}

void FreePhysPage(unsigned page) {
    available[page / 32] &= ~(uint32_t{1} << (page & 31));
}

void MarkUsed(unsigned low, unsigned high) {
    if (low < (high & -32)) {
        available[low / 32] |= -(1 << (low & 31));
        if (high & 31) available[high / 32] |= (1 << (high & 31)) - 1;
        low = (low + 32) & -32;
        high &= -32;
        for (; low < high; low += 32) available[low / 32] = -1;
    } else {
        available[low / 32] |= ((1 << (high & 31)) - 1) & -(1 << (low & 31));
    }
}

PageEntry* GetPageEntry(int page) {
    return reinterpret_cast<PageEntry*>(kCurPageTab) + page;
}

// Add npages to the current address space
void *AllocPages(int npages) {
    // First 64kb of linear address space we leave unmapped, for null exception
    unsigned i;
    for (i = 16; i < kKernelBase / kPageSize - npages + 1; i++) {
        if (!GetPageEntry(i)->present) break;
    }
    if (i == kKernelBase / kPageSize - npages + 1) return nullptr;
    void* res = reinterpret_cast<void*>(uintptr_t{i} * kPageSize);
    for (int j = 0; j < npages; j++, i++) *GetPageEntry(i) = MakePageEntry(PhysAddress(page_tables + 4), 1, 0, 1);
    return res;
}

void SwitchPageDir(PageTable* new_dir) {
    LoadPageDir(PhysAddress(new_dir));
}

void InitializePageDir(PageTable* page_dir) {
    auto zp_address = PhysAddress(zero_page);
    auto kt_address = PhysAddress(page_tables);
    for (unsigned i = 0; i < kNumPageEntries - 4; i++) page_dir->entries[i] = MakePageEntry(zp_address, 1, 0, 1);
    for (int i = 0; i < 3; i++) page_dir->entries[i + kNumPageEntries - 4] = MakePageEntry(kt_address + i * kPageSize, 1, 1, 0);
    page_dir->entries[kNumPageEntries - 1] = MakePageEntry(PhysAddress(page_dir), 1, 1, 0);
}

PageTable* CreatePageDir() {
    auto zp_address = PhysAddress(zero_page);
    for (unsigned i = 0; i < kNumPageEntries - 256; i++) {
        if (page_tables[2].entries[i].offset == zp_address >> 12) {
            auto p = reinterpret_cast<PageTable*>((kNumPageEntries - 2) * kNumPageEntries * kPageSize + i * kPageSize);
            InitializePageDir(p);
            return p;
        }
    }
    return nullptr;
}

void DestroyPageDir(const PageTable* p) {
    auto cr3 = CurrentCR3();
    auto this_page = PhysAddress(p);
    if (cr3 != this_page) {
        LoadPageDir(this_page);
    } else {
        cr3 = PhysAddress(page_tables + 3);
    }
    for (unsigned i = 16; i < kKernelBase / kPageSize; i++) {
        if (!GetPageEntry(i)->present) break;
        unsigned page = GetPageEntry(i)->offset;
        if (page == PhysAddress(zero_page) / kPageSize) continue;
        FreePhysPage(page);
    }

    LoadPageDir(cr3);
}

extern "C" uint8_t _start[];
extern "C" uint8_t _edata[];
extern "C" uint8_t _end[];

void InitPaging() {
    for (unsigned i = 0; i < array_size(available); i++) {
        if (available[i]) {
            print(screen, "Huh! non zero available {} {}\n", i, reinterpret_cast<void*>(PhysAddress(available + i)));
            break;
        }
    }

    if (!CheckA20()) {
        // So far we only used < 1MB memory, so nothing is fucked yet as we haven't encountered aliased mem.
        // We can simply continue by marking all pages at an odd 1MB segment unavailable, this halves the available
        // memory.
        print(screen, "A20 disabled! Compensating but losing half the memory");
        constexpr int kWordsPerMB = (1 << 20) / kPageSize / 32;
        for (int i = 0; i < kNumWords; i += 2 * kWordsPerMB) {
            memset(available + i + kWordsPerMB, -1, sizeof(uint32_t) * kWordsPerMB);
        }
    }

    MarkUsed(0, 1);  // zero page is used by bios

    // Mark pages where kernel is loaded as used
    int num_kernel_pages = (Cast(_end) - Cast(_start) + kPageSize - 1) / kPageSize;
    print(screen, "Kernel pages {}\n", num_kernel_pages);
    int kernel_low = PhysAddress(_start) / kPageSize;
    MarkUsed(kernel_low, kernel_low + num_kernel_pages);

    // Mark extended bios area + UMB used
    int umb_low = (uintptr_t{*reinterpret_cast<uint16_t*>(kLowMemBase + 0x40e)} << 4) / kPageSize;
    int umb_high = 0x100000 / kPageSize;
    MarkUsed(umb_low, umb_high);

    // We are done with the identity mapping, make zero page zero
    memset(zero_page, 0, kPageSize);
    // Make page dir as it should be
    InitializePageDir(page_tables + 3);
    // Use COW for rest of kernel space
    for (unsigned i = kNumPages - 3 * kNumPageEntries; i < kNumPages - kNumPageEntries - 256; i++) {
        *GetPageEntry(i) = MakePageEntry(PhysAddress(zero_page), 1, 0, 0);
    }

    FlushTLB();
}

// This is a subtle function. The bootloader loads the kernel at some arbitrary physical address with unpaged
// memory, the kernel is compiled/linked expecting to be loaded at kKernelBase. When enabling paging the page tables
// can map the linear address at kKernelBase to the physical address where it's loaded, after which the code can
// execute at the right address. However this code is called before paging is enabled, so we have to be careful because
// access of globals will be at the wrong physical address. We compensate by passing in `delta` to offset the address
// of globals to the correct physical address. After paging is enabled we should switch to the right stack and right
// ip, this must be done in asm and will be handled in entry.asm. This function returns the address of the stack.
extern "C" void* EnablePaging(uintptr_t phys_address) {
    if ((phys_address & (kPageSize - 1)) != 0 || reinterpret_cast<uintptr_t>(_start) != kKernelBase) hlt();
    memset(reinterpret_cast<uint8_t*>(phys_address) + (_edata - _start), 0, _end - _edata);  // Zero bss

    auto delta = Cast(page_tables) - Cast(_start);
    if ((delta & (kPageSize - 1)) != 0) hlt();
    auto ptables = reinterpret_cast<PageTable*>(phys_address) + (delta / kPageSize);

    // Identity map the lowest 4mb, we use the zero-page to store the mapping as we don't use it yet
    // Map 4mb starting at the start of the kernel into kernel mem
    for (unsigned i = 0; i < 1024; i++) {
        ptables[4].entries[i] = MakePageEntry(i * kPageSize, 1, 1, 0);
        ptables[0].entries[i] = MakePageEntry(i * kPageSize + phys_address, 1, 1, 0);
    }

    ptables[3].entries[0] = MakePageEntry(Cast(ptables + 4), 1, 1, 0);
    for (int i = 0; i < 4; i++) ptables[3].entries[i + kNumPageEntries - 4] = MakePageEntry(Cast(ptables + i), 1, 1, 0);

    LoadPageDir(Cast(ptables + 3));

    // Enable paging and Write Protect bit
    asm volatile (
        "mov %%cr0, %%eax\n\t"
        "or $0x80010000, %%eax\n\t"
        "mov %%eax, %%cr0\n\t"
        :::"ax");

    // Map first MB into the end of kernel space.
    for (int i = 0; i < 256; i++) *GetPageEntry(kLowMemBase / kPageSize + i) = MakePageEntry(i * kPageSize,1,1,0);
    FlushTLB();
    return kernel_stack + sizeof(kernel_stack);
}

extern "C" void isr_handler(Regs* regs) {
    // Convert pushed return address into interrupt number
    regs->int_no = (regs->int_no - reinterpret_cast<uintptr_t>(int_vector)) / 8;
    isr_table.entries[regs->int_no](regs);
}

extern "C" void kmain(int pos) {
    screen.cursor_x = pos & 0xFF;
    screen.cursor_y = (pos >> 8) & 0xFF;

    auto ip = GetIP();
    print(screen, "Entering main kernel\nStack at {} and ip {} at phys address {}\n", &pos, ip, reinterpret_cast<void*>(PhysAddress(ip)));
    InitPaging();

    RemapInterrupts();
    SetupDescriptorTables();
    EnableIRQ();

    print(screen, "Boot succeeded\n");

    if (1) {
        auto p = static_cast<uint32_t *>(AllocPages(3));
        print(screen, "Got memory: {}\n", p);

        for (int i = 15; i < 20; i += 1) {
            print(screen, "Page {} loaded {}\n", i, *GetPageEntry(i));
        }

        print(screen, "Read {}\n", p[0]);

        p[0] = 10;

        print(screen, "Read {}\n", p[0]);

        for (int i = 15; i < 20; i += 1) {
            print(screen, "Page {} loaded {}\n", i, *GetPageEntry(i));
        }

        auto newp = CreatePageDir();
        print(screen, "Got page at {}\n", newp);

        SwitchPageDir(newp);

        for (int i = 15; i < 20; i += 1) {
            print(screen, "Page {} loaded {}\n", i, *GetPageEntry(i));
        }

        auto q = static_cast<uint32_t *>(AllocPages(3));
        print(screen, "Got memory: {}\n", q);

        for (int i = 15; i < 20; i += 1) {
            print(screen, "Page {} loaded {}\n", i, *GetPageEntry(i));
        }

        print(screen, "Read {}\n", q[0]);

        q[0] = 20;

        print(screen, "Read {}\n", q[0]);

        for (int i = 15; i < 20; i += 1) {
            print(screen, "Page {} loaded {}\n", i, *GetPageEntry(i));
        }

        DestroyPageDir(newp);

        // SwitchPageDir(page_tables + 3);

        print(screen, "Read {}\n", p[0]);
    }

    // *reinterpret_cast<uint32_t volatile*>(0x10);
    hlt();
}

static void page_fault(Regs* regs) {
    constexpr uintptr_t kPresent = 1; (void)kPresent;
    constexpr uintptr_t kWrite = 2;
    constexpr uintptr_t kUser = 4;

    auto error = regs->err_code;
    auto fault_address = LoadPageFaultAddress();
    int page_index = fault_address >> 12;

    if (fault_address < kKernelBase) {
        auto page_entry = *GetPageEntry(page_index);
        if (!page_entry.present) {
            // A bug-free kernel will not address memory outside of the allocation of the user
            kassert(error & kUser);
            panic("Seg fault, user outside allocation");
        }
        kassert(error & kWrite);
        // Must be write to zero-page
        int page = AllocPhysPage();
        if (page == -1) panic("OOM");
        *GetPageEntry(page_index) = MakePageEntry(uintptr_t(page) * kPageSize, 1, 1, 1);
        FlushTLB();
        memset(reinterpret_cast<void*>(fault_address & -kPageSize), 0, kPageSize);
        FlushTLB();
        return;
    }
    if (error & kUser) {
        panic("Seg fault, user addresses kernel space");
    }
    // The whole kernel mem area is readable by the kernel, so this must be a write
    kassert(error & kWrite);  // The whole area is always readable (COW)

    // Fault occurred in kernel space by the kernel
    if (fault_address >= kCurPageTab) {
        // The whole page_dir is present and readable, due to initialization with zero-page.
        // Kernel tried to access a non-existing page table
        int page = AllocPhysPage();
        if (page == -1) panic("OOM");
        auto page_dir_entry = (fault_address >> 12) & 1023;
        GetCurrentDir()[page_dir_entry] = MakePageEntry(uintptr_t(page) * kPageSize, 1, 1, 0);
        FlushTLB();
        memset(reinterpret_cast<void*>(fault_address & -kPageSize), 0, kPageSize);
        FlushTLB();
        return;
    }
    if (fault_address >= kKernelBase + (8 << 20)) {
        int page = AllocPhysPage();
        if (page == -1) panic("OOM");
        *GetPageEntry(page_index) = MakePageEntry(uintptr_t(page) * kPageSize, 1, 1, 0);
        return;
    }
    panic("Failure in kernel address {}\n", reinterpret_cast<void*>(fault_address));
}
