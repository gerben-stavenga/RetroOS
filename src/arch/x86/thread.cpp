//
// Created by gerben stavenga on 7/9/23.
//

#include "src/kernel/thread.h"

#include "src/kernel/kassert.h"
#include "irq.h"
#include "paging.h"
#include "descriptors.h"

void InitializeProcessThread(Thread* thread, const void* entry) {
    std::uint32_t ds = kUserDS | 3;
    std::uint32_t cs = kUserCS | 3;
    constexpr uint32_t kIFMask = 1 << 9;
    thread->cpu_state.GetCPUState<Regs>() = Regs {
        .gs = ds,
        .fs = ds,
        .es = ds,
        .ds = ds,
        .edi = 0,
        .esi = 0,
        .ebp = 0,
        .temp_esp = 0,
        .ebx = 0,
        .edx = 0,
        .ecx = 0,
        .eax = 0,
        .int_no = 0,
        .err_code = 0,
        .eip = (uint32_t)entry,
        .cs = cs,
        .eflags = kIFMask,
        .esp = (uint32_t)kKernelBase,
        .ss = ds,
    };
}

__attribute__((used))
void SaveState(Thread* thread) {
    auto* regs = reinterpret_cast<Regs*>(kernel_stack + sizeof(kernel_stack) - sizeof(Regs));
    thread->cpu_state.GetCPUState<Regs>() = *regs;
}

void SegvCurrentThread(Regs* regs, std::uintptr_t fault_address) {
    current_thread->cpu_state.GetCPUState<Regs>() = *regs;
    SignalThread(current_thread, fault_address);
}

__attribute__((used))
[[noreturn]] void ExitToThread(Thread* thread) {
    thread->state = THREAD_RUNNING;
    if (current_thread && current_thread->state == THREAD_UNUSED) {
        SwitchPageDirAndFreeOld(thread->page_dir, current_thread->page_dir);
    } else {
        SwitchPageDir(thread->page_dir);
    }
    current_thread = thread;
    // kprint("Exitting eax = {} eip = {}\n", thread->cpu_state.eax, Hex(thread->cpu_state.eip));
    exit_kernel(&thread->cpu_state.GetCPUState<Regs>());
}

__attribute__((used))
void SetReturn(Thread& thread, std::uintptr_t ret) {
    thread.cpu_state.GetCPUState<Regs>().eax = ret;
}
