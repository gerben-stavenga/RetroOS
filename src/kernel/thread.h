//
// Created by gerben stavenga on 7/9/23.
//

#ifndef OS_THREAD_H
#define OS_THREAD_H

#include <cstdint>
#include <cstddef>

struct PageTable;

enum ThreadState {
    THREAD_UNUSED = 0,
    THREAD_RUNNING,
    THREAD_READY,
    THREAD_BLOCKED,
    THREAD_ZOMBIE,
};

struct CpuState {
    constexpr static size_t kSize = 26 * 8;
    constexpr static size_t kAlign = 16;
    alignas(kAlign) uint8_t opaque[kSize];  

    template <typename T>
    const T& GetCPUState() const {
        return GetCPUStateImpl<T>();
    }

    template <typename T>
    T& GetCPUState() {
        return GetCPUStateImpl<T>();
    }

private:
    template <typename T>
    T& GetCPUStateImpl() const {
        static_assert(sizeof(T) <= sizeof(CpuState), "Size of T exceeds CPU state size");
        static_assert(alignof(T) <= alignof(CpuState), "Alignment of T exceeds CPU state alignment");
        return *const_cast<T*>(reinterpret_cast<const T*>(opaque));
    }
};

struct Thread {
    int tid;  // 0 is the init/idle thread
    int pid;
    int priority;
    int parent_tid;
    ThreadState state;
    int time;
    PageTable* page_dir;
    int num_file_descriptors;
    int file_descriptors[16];
    CpuState cpu_state;
};

extern Thread* current_thread;

constexpr int kMaxThreads = 1024;
extern Thread threads[kMaxThreads];

Thread* CreateThread(Thread* parent, PageTable* page_dir, bool is_process);  // parent == nullptr means init thread
__attribute__((weak))
void InitializeProcessThread(Thread* thread, const void* entry);

__attribute__((weak))
[[noreturn]] void ExitToThread(Thread* thread);

// Attribute to make sure it's not null

__attribute__((weak, used))
void SaveState(Thread* thread);

__attribute__((weak))
PageTable* ForkCurrent();

void Schedule(int tid, bool must_switch);

__attribute__((weak))
void SetReturn(Thread& thread, std::uintptr_t ret);

void SignalThread(Thread* thread, std::uintptr_t fault_address);

#endif //OS_THREAD_H
