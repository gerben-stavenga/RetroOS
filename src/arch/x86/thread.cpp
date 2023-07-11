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
            return &threads[i];
        }
    }
    return nullptr;
}

void SaveState(Thread* thread, Regs* regs) {
    thread->cpu_state.eax = regs->eax;
    thread->cpu_state.ebx = regs->ebx;
    thread->cpu_state.ecx = regs->ecx;
    thread->cpu_state.edx = regs->edx;
    thread->cpu_state.esi = regs->esi;
    thread->cpu_state.edi = regs->edi;
    thread->cpu_state.ebp = regs->ebp;
    thread->cpu_state.esp = regs->esp;
    thread->cpu_state.eip = regs->eip;
    thread->cpu_state.eflags = regs->eflags;
    thread->cpu_state.cs = regs->cs;
    thread->cpu_state.ds = regs->ds;
    thread->cpu_state.es = regs->es;
    thread->cpu_state.fs = regs->fs;
    thread->cpu_state.gs = regs->gs;
    thread->cpu_state.ss = regs->ss;
}

void LoadState(Thread* thread, Regs* regs) {
    regs->eax = thread->cpu_state.eax;
    regs->ebx = thread->cpu_state.ebx;
    regs->ecx = thread->cpu_state.ecx;
    regs->edx = thread->cpu_state.edx;
    regs->esi = thread->cpu_state.esi;
    regs->edi = thread->cpu_state.edi;
    regs->ebp = thread->cpu_state.ebp;
    regs->esp = thread->cpu_state.esp;
    regs->eip = thread->cpu_state.eip;
    regs->eflags = thread->cpu_state.eflags;
    regs->cs = thread->cpu_state.cs;
    regs->ds = thread->cpu_state.ds;
    regs->es = thread->cpu_state.es;
    regs->fs = thread->cpu_state.fs;
    regs->gs = thread->cpu_state.gs;
    regs->ss = thread->cpu_state.ss;
}

constexpr uint64_t a = 0xdeadbeed;  // a - 1 is divisible by all prime factors of 2^64 and a - 1 is divisible by 4
constexpr uint64_t c = 0x12345679;  // c and 2^64 are relatively prime
uint64_t seed = 0xcafebabedeadbeef;

void Schedule(Regs* regs, bool must_switch) {
    Thread* next_thread = nullptr;
    seed = a * seed + c;
    int count = 0;
    // Skip 0 task
    for (int i = 1; i < kMaxThreads; i++) {
        if (i == current_thread->tid) continue;
        if (threads[i].state == THREAD_READY) {
            if (seed % (count + 1) == 0) {
                next_thread = &threads[i];
            }
            count++;
        }
    }
    if (next_thread == nullptr) {
        if (!must_switch) return;
        next_thread = &threads[0];
    }
    kassert(current_thread->state == THREAD_RUNNING);
    current_thread->state = THREAD_READY;
    SaveState(current_thread, regs);
    LoadState(next_thread, regs);
    current_thread = next_thread;
    current_thread->state = THREAD_RUNNING;
    SwitchPageDir(current_thread->page_dir);
}

void SysFork(Regs* regs) {
    auto page_dir = ForkCurrent();
    auto child_thread = CreateThread(current_thread, page_dir, true);
    if (1) {
        // Continue as the child thread.
        SwitchPageDir(page_dir);
        SaveState(current_thread, regs);
        current_thread->state = THREAD_READY;
        current_thread->cpu_state.eax = child_thread->tid;
        // Continue as the child thread.
        current_thread = child_thread;
        current_thread->state = THREAD_RUNNING;
        regs->eax = 0;
    } else {
        // Continue as the parent thread.
        SaveState(child_thread, regs);
        child_thread->cpu_state.eax = 0;
        regs->eax = child_thread->tid;
    }
}

// edx is exit code
void SysExit(Regs* regs) {
    if (regs->cs == 0x8) {
        // It's called from kernel mode, which is a special case meant to switch to the init task.
        regs->cs = 0x1B;
        regs->ds = 0x23;
        regs->es = 0x23;
        regs->fs = 0x23;
        regs->gs = 0x23;
        regs->ss = 0x23;
        regs->eip = regs->edx;
        regs->esp = regs->ecx;
        regs->eax = regs->ebx = regs->ecx = regs->edx = regs->esi = regs->edi = regs->ebp = regs->temp_esp = 0;
    } else {
        kprint("Thread {} exited with code {} at @{}:{}\n", current_thread->tid, regs->edx, Hex(regs->cs), Hex(regs->eip));
        auto old_thread = current_thread;
        Schedule(regs, true);
        // TODO send exit code to parent
        // Free file descriptors
        DestroyPageDir(old_thread->page_dir);
    }
}
