#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <cstdint>

typedef std::uintptr_t (*SysCall)(std::uintptr_t arg0, std::uintptr_t arg1, std::uintptr_t arg2, std::uintptr_t arg3, std::uintptr_t arg4);

std::uintptr_t SysExit(std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t);
std::uintptr_t Yield(std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t);
std::uintptr_t SysFork(std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t);
std::uintptr_t WriteSyscall(std::uintptr_t fd, std::uintptr_t buf, std::uintptr_t len, std::uintptr_t, std::uintptr_t);
std::uintptr_t ReadSyscall(std::uintptr_t fd, std::uintptr_t buf, std::uintptr_t len, std::uintptr_t, std::uintptr_t);
std::uintptr_t WriteSyscall(std::uintptr_t fd, std::uintptr_t buf, std::uintptr_t len, std::uintptr_t, std::uintptr_t);

constexpr SysCall syscall_table[] = {
    SysExit,  // 0
    Yield,  // 1
    nullptr,
    nullptr,
    SysFork,  // 4
    nullptr,
    nullptr,
    nullptr,
    ReadSyscall,  // 8
    WriteSyscall,  // 9
};

#endif  // SYSCALLS_H
