#include "syscalls.h"

#include "src/kernel/kassert.h"
#include "src/kernel/drv/basic.h"
#include "src/kernel/thread.h"

std::uintptr_t ReadSyscall(std::uintptr_t fd, std::uintptr_t buf_, std::uintptr_t  len, std::uintptr_t ,std::uintptr_t ) {
    char* buf = reinterpret_cast<char*>(buf_);
    if (fd != 0) {
        kprint("Non-stdin not supported\n");
        return -1;
    }
    return key_pipe.Read(buf, len);
}

std::uintptr_t WriteSyscall(std::uintptr_t fd, std::uintptr_t buf_, std::uintptr_t  len, std::uintptr_t ,std::uintptr_t) {
    const char* buf = reinterpret_cast<const char*>(buf_);
    if (fd != 1) {
        kprint("Non-stdout not supported\n");
        return -1;
    } else {
        kprint("{}", std::string_view(buf, len));
    }
    return len;
}

std::uintptr_t SysFork(std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t) {
    kprint("Forking thread {}\n", current_thread->tid);
    auto page_dir = ForkCurrent();
    assert(page_dir != nullptr);
    kprint("Forking thread {}\n", current_thread->tid);
    auto child_thread = CreateThread(current_thread, page_dir, true);
    kprint("Forking thread {}\n", current_thread->tid);
    SaveState(child_thread);
    kprint("Forking thread {}\n", current_thread->tid);
    SetReturn(*child_thread, 0);
    kprint("Forking thread {}\n", current_thread->tid);
    return child_thread->tid;
}

std::uintptr_t Yield(std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t) {
    SaveState(current_thread);
    current_thread->state = THREAD_READY;
    Schedule(current_thread->tid, false);
    return 0;
}

// edx is exit code
std::uintptr_t SysExit(std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t) {
    assert(current_thread->tid != 0);
    current_thread->state = THREAD_UNUSED;
    Schedule(current_thread->tid, true);
    // TODO send exit code to parent
    // Free file descriptors
    __builtin_unreachable();
}
