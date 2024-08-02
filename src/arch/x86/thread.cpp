//
// Created by gerben stavenga on 7/9/23.
//

#include "thread.h"

#include "kassert.h"
#include "irq.h"
#include "paging.h"

Thread* current_thread = nullptr;
Thread threads[kMaxThreads];

Thread* CreateThread(Thread* parent, PageTable* page_dir, bool is_process) {
    for (int i = 0; i < kMaxThreads; i++) {
        if (threads[i].state == THREAD_UNUSED) {
            threads[i].tid = i;
            threads[i].pid = is_process ? i : parent->pid;
            threads[i].priority = parent ? parent->priority : 0;
            threads[i].parent_tid = parent ? parent->tid : -1;
            threads[i].state = THREAD_READY;
            threads[i].time = GetTime();
            threads[i].page_dir = page_dir;
            constexpr uint32_t kIFMask = 1 << 9;
            threads[i].cpu_state = Regs {
                0x23, 0x23, 0x23, 0x23,  // gs, fs, es, ds;
                0, 0, 0, 0, 0, 0, 0, 0,  // edi, esi, ebp, temp_esp, ebx, edx, ecx, eax;
                0, 0,                    // int_no, err_code;
                0, 0x1B, kIFMask, 0, 0x23    // eip, cs, eflags, esp, ss
            };

            return &threads[i];
        }
    }
    return nullptr;
}

void SaveState(Thread* thread, Regs* regs) {
    thread->cpu_state = *regs;
}

constexpr uint64_t a = 0xdeadbeed;  // a - 1 is divisible by all prime factors of 2^64 and a - 1 is divisible by 4
constexpr uint64_t c = 0x12345679;  // c and 2^64 are relatively prime
uint64_t seed = 0xcafebabedeadbeef;

[[noreturn]] void ExitToThread(Thread* thread) {
    thread->state = THREAD_RUNNING;
    if (current_thread && current_thread->state == THREAD_UNUSED) {
        SwitchPageDirAndFreeOld(thread->page_dir, current_thread->page_dir);
    } else {
        SwitchPageDir(thread->page_dir);
    }
    current_thread = thread;
    // kprint("Exitting eax = {} eip = {}\n", thread->cpu_state.eax, Hex(thread->cpu_state.eip));
    exit_kernel(&thread->cpu_state);
}

void Schedule(int tid, bool must_switch) {
    Thread* next_thread = nullptr;
    seed = a * seed + c;
    int count = 0;
    // Skip 0 task
    for (int i = 1; i < kMaxThreads; i++) {
        if (i == tid) continue;
        if (threads[i].state == THREAD_READY) {
            count++;
            // resevoir sampling
            if (seed % count == 0) {
                next_thread = &threads[i];
            }
        }
    }
    if (next_thread == nullptr) {
        if (!must_switch || current_thread->tid == 0) {
            kprint("Schedule returning to caller\n");
            return;
        }
        next_thread = &threads[0];
    }
    kprint("Schedule returning to tid {}\n", next_thread->tid);
    ExitToThread(next_thread);
}

void SysFork(Regs* regs) {
    auto page_dir = ForkCurrent();
    assert(page_dir != nullptr);
    auto child_thread = CreateThread(current_thread, page_dir, true);
    SaveState(child_thread, regs);
    regs->eax = child_thread->tid;
    child_thread->cpu_state.eax = 0;
}

void Yield(Regs* regs) {
    SaveState(current_thread, regs);
    current_thread->state = THREAD_READY;
    Schedule(current_thread->tid, false);
}

// edx is exit code
void SysExit(Regs* regs) {
    assert(current_thread->tid != 0);
    kprint("Thread {} exited with code {} at @{}:{}\n", current_thread->tid, regs->edx, Hex(regs->cs), Hex(regs->eip));
    current_thread->state = THREAD_UNUSED;
    Schedule(current_thread->tid, true);
    // TODO send exit code to parent
    // Free file descriptors
}
