//
// Created by gerben stavenga on 6/25/23.
//

#include <cstdint>

#include "entry.h"
#include "irq.h"
#include "src/kernel/kassert.h"
#include "src/kernel/syscalls.h"
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
    auto frame = static_cast<Frame32*>(regs);
    kprint("ShowRegs: @{}:{} stack {}:{}\n ecx: {} edx: {}\n", Hex(frame->cs), Hex(frame->eip), Hex(frame->ss), Hex(frame->esp), Hex(regs->regs[RCX]), Hex(regs->regs[RDX]));
}

enum Signals : int {
    SIGFPE, SIGTRAP, SIGSEGV, SIGILL, SIGBUS
};

struct GenericException {
    int signal;
    std::string_view name;
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

    auto frame = static_cast<Frame32*>(regs);
    panic("An unsupported exception, signal = {} name = {} @{}:{}\n", signal, exceptions[regs->int_no].name, Hex(frame->cs), Hex(frame->eip));
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
    auto frame = static_cast<Frame32*>(regs);
    panic("GP {} {}:{}", regs->err_code, Hex(frame->cs), Hex(frame->eip));
}

void page_fault(Regs* regs);

extern uint8_t kernel_stack[4096 * 32];

__attribute__((noinline))
static void SystemCall(Regs* regs) {
    // kprint("SystemCall: {}\n", regs->eax);
    assert(regs == reinterpret_cast<Regs*>(kernel_stack + sizeof(kernel_stack) - sizeof(Regs)));
    if (regs->regs[RAX] >= array_size(syscall_table) || !syscall_table[regs->regs[RAX]]) {
        regs->regs[RAX] = ENOSYS;
        return;
    }
    regs->regs[RAX] = syscall_table[regs->regs[RAX]](regs->regs[RDX], regs->regs[RCX], regs->regs[RBX], regs->regs[RSI], regs->regs[RDI]);
}


extern "C" void isr_handler(Regs* regs) {
    if (reinterpret_cast<uintptr_t>(regs) - reinterpret_cast<uintptr_t>(kernel_stack) < 16 * 4096) {
        // kprint("Low stack");
        // StackTrace();
    } else {
        X86_sti();
    }
    switch (regs->int_no) {
        case 1: return debug(regs);
        case 2: return nmi(regs);
        case 8: return double_fault(regs);
        case 13: return general_protection(regs);
        case 14: return page_fault(regs);
        case 16: return coprocessor_error(regs);

        case 0:
        case 3 ... 7:
        case 9 ... 12:
        case 17:
            return generic_exception_handler(regs);

        case 15:
        case 18 ... 31:
            return unknown_exception_handler(regs);

        case 32 ... 47:  // IRQ0 ... IRQ15
            return IrqHandler(regs);
        case 48:
            return SystemCall(regs);
        default:
            __builtin_unreachable();
    }
}
