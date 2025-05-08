//
// Created by gerben stavenga on 7/9/23.
//

#include "thread.h"

#include "src/kernel/kassert.h"
#include "src/kernel/drv/basic.h"

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
            return &threads[i];
        }
    }
    return nullptr;
}

constexpr uint64_t a = 0xdeadbeed;  // a - 1 is divisible by all prime factors of 2^64 and a - 1 is divisible by 4
constexpr uint64_t c = 0x12345679;  // c and 2^64 are relatively prime
uint64_t seed = 0xcafebabedeadbeef;

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

void SignalThread(Thread* thread, std::uintptr_t fault_address) {
    if (thread->pid == 0) {
        panic("Segmentation fault in init thread {} at address {}\n", thread->tid, Hex(fault_address));
    } else {
        kprint("Segmentation fault in user thread {} at address {}\n", thread->tid, Hex(fault_address));
        if (current_thread == thread) {
            thread->state = THREAD_UNUSED;
            Schedule(current_thread->tid, true);
        } else {
            thread->state = THREAD_ZOMBIE;
        }
    }
}
