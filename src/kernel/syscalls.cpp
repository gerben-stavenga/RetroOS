#include "syscalls.h"

#include "src/kernel/kassert.h"
#include "src/kernel/drv/basic.h"
#include "src/kernel/thread.h"

void ReadFile(void* dst, std::size_t size);

std::uintptr_t ReadSyscall(std::uintptr_t fd, std::uintptr_t buf_, std::uintptr_t  len, std::uintptr_t ,std::uintptr_t ) {
    char* buf = reinterpret_cast<char*>(buf_);
    if (fd != 0) {
        ReadFile(buf, len);
        return len;
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
    auto page_dir = ForkCurrent();
    assert(page_dir != nullptr);
    auto child_thread = CreateThread(current_thread, page_dir, true);
    SaveState(child_thread);
    SetReturn(*child_thread, 0);
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

std::size_t Open(std::string_view path);

std::uintptr_t SysOpen(std::uintptr_t buf, std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t) {
    auto path = std::string_view(reinterpret_cast<const char*>(buf));
    kprint("SysOpen {}\n", path);
    auto size = Open(path);
    if (size == SIZE_MAX) {
        return -1;
    } else {
        return size;
    }
}

__attribute__((weak))
PageTable* SwitchFreshPageDirAndFreeOld(PageTable* old_dir);

std::uintptr_t Exec(std::uintptr_t path_, std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t) {
    const auto path = std::string_view(reinterpret_cast<const char*>(path_));
    auto size = Open(path);
    if (size == SIZE_MAX) {
        return -1;
    }
    auto buf = (char*)malloc(size);
    ReadFile(buf, size);

    current_thread->page_dir = SwitchFreshPageDirAndFreeOld(current_thread->page_dir);
    auto entry = LoadElf({buf, size}, +[](uintptr_t address, std::size_t sz, int type) { 
        std::memset(reinterpret_cast<void*>(address), 0, sz);
        return reinterpret_cast<void*>(address); 
    });
    free(buf);
    if (entry == nullptr) {
        return -1;
    }

    InitializeProcessThread(current_thread, entry);
    ExitToThread(current_thread);
    return 0;
}
