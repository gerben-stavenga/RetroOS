//
// Created by gerben stavenga on 7/9/23.
//

#ifndef OS_THREAD_H
#define OS_THREAD_H

#include <cstdint>
#include <cstddef>

#include "entry.h"
#include "paging.h"

struct CPUState {
    uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp;
    uint32_t eip, eflags;
    uint16_t cs, ds, es, fs, gs, ss;
    // TODO: add floating point registers
};

enum ThreadState {
    THREAD_UNUSED = 0,
    THREAD_RUNNING,
    THREAD_READY,
    THREAD_BLOCKED,
    THREAD_ZOMBIE,
};

struct Thread {
    int tid;  // 0 is the init/idle thread
    int pid;
    int priority;
    int parent_tid;
    ThreadState state;
    int time;
    PageTable* page_dir;
    Regs cpu_state;
    int num_file_descriptors;
    int file_descriptors[16];
};

extern Thread* current_thread;

constexpr int kMaxThreads = 1024;
extern Thread threads[kMaxThreads];

[[noreturn]] void ExitToThread(Thread* thread);
Thread* CreateThread(Thread* parent, PageTable* page_dir, bool is_process);  // parent == nullptr means init thread
void Yield(Regs* regs);
void SysExit(Regs* regs);
void SysFork(Regs* regs);

#endif //OS_THREAD_H
