//
// Created by gerben stavenga on 6/25/23.
//

#include <stdint.h>

#include "entry.h"
#include "irq.h"
#include "kassert.h"
#include "paging.h"
#include "thread.h"
#include "x86_inst.h"
#include "src/freestanding/utils.h"

constexpr int ENOSYS = -100;

typedef void (*EntryHandler)(Regs*);

/*
 * Make a filesystem that combines all resources in a hierarchy.
 * /dev/xxx are devices (core, mem, dma, keyboard, mouse, timer, hd, etc)
 * /dev/core allows execution of code sharing the same address space
 * /dev/mem allows access to physical memory through paging
 * /dev/dma allows access to physical memory through DMA
 * /dev/keyboard allows access to the keyboard
 * /dev/mouse allows access to the mouse
 * /dev/timer allows access to the timer
 * /dev/hd allows access to the hard disk
 *
 * A implementation of this for a specific architecture provides the necessary interface layer for the kernel to
 * run. The kernel itself is architecture independent, in particular one can implement the devices on top of a
 */

void ShowRegs(Regs* regs) {
    kprint("ShowRegs: @{}:{} stack {}:{}\nkernel stack @{} ecx: {} edx: {}\n", Hex(regs->cs), Hex(regs->eip), Hex(regs->ss), Hex(regs->esp), Hex(regs->temp_esp), Hex(regs->ecx), Hex(regs->edx));
}

void Yield(Regs* regs) {
    Schedule(regs, true);
}

void ConsoleOut(Regs* regs) {
    kprint("{}", string_view(reinterpret_cast<char*>(regs->ecx), regs->edx));
}

void KeyboardIn(Regs* regs) {
//    regs->eax =
    (void) regs;
}

/*
void ReadSyscall(Regs* regs) {
    auto fd = regs->ecx;
    auto buf = reinterpret_cast<char*>(regs->edx);
    auto len = regs->esi;
    auto ret = Read(fd, buf, len);
    regs->eax = ret;
}

void WriteSyscall(Regs* regs) {
    auto fd = regs->ecx;
    auto buf = reinterpret_cast<char*>(regs->edx);
    auto len = regs->esi;
    auto ret = Write(fd, buf, len);
    regs->eax = ret;
}
*/
static const EntryHandler syscall_table[] = {
        SysExit,  // 0
        Yield,  // 1
        nullptr,
        nullptr,
        SysFork,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        ConsoleOut,  // 9
};

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

    panic("An unsupported exception, signal = {} name = {} @{}:{}\n", signal, exceptions[regs->int_no].name, Hex(regs->cs), Hex(regs->eip));
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
    panic("GP {} {}:{}", regs->err_code, Hex(regs->cs), Hex(regs->eip));
}

void page_fault(Regs* regs);

static void SystemCall(Regs* regs) {
    //kprint("SystemCall: {}\n", regs->eax);
    //hlt();
    if (regs->eax >= array_size(syscall_table) || !syscall_table[regs->eax]) {
        regs->eax = ENOSYS;
        return;
    }
    syscall_table[regs->eax](regs);
}

constexpr int kIsrEntries = 32 + 16 + 1;  // 32 exceptions, 16 IRQs, 1 syscall
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

extern "C" uint64_t int_vector[];

extern "C" void* isr_handler(Regs* regs) {
    EnableIRQ();
    regs->int_no = (regs->int_no - reinterpret_cast<uintptr_t>(int_vector)) / 8;
    isr_table.entries[regs->int_no](regs);
    DisableIRQ();
    if (should_yield && regs->cs & 3) {
        Schedule(regs, false);
        should_yield = false;
    }
    return regs;
}
