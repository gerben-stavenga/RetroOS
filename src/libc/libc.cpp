//
// Created by gerben stavenga on 6/27/23.
//

#include "libc.h"

[[noreturn]] void Exit(int code) {
    SysCall(0, code, 0, 0, 0, 0);
    __builtin_unreachable();
}

void StdFlush(int fd, std::string_view str) {
    Write(fd, str.data(), str.size());
}

void Yield() {
    SysCall(1, 0, 0, 0, 0, 0);
}

void* Alloc(std::size_t size) {
    return (void*) SysCall(2, size, 0, 0, 0, 0);
}

void Free(void* ptr) {
    SysCall(3, (uintptr_t) ptr, 0, 0, 0, 0);
}

int Fork() {
    return SysCall(4, 0, 0, 0, 0, 0);
}

void Exec(const char* path, char* const argv[], char* const envp[]) {
    SysCall(5, (uintptr_t) path, (uintptr_t) argv, (uintptr_t) envp, 0, 0);
}

int Open(const char* path, int flags, int mode) {
    return SysCall(6, (uintptr_t) path, flags, mode, 0, 0);
}

void Close(int fd) {
    SysCall(7, fd, 0, 0, 0, 0);
}

std::size_t Read(int fd, void* buf, std::size_t count) {
    return SysCall(8, fd, (uintptr_t) buf, count, 0, 0);
}

int Write(int fd, const void* buf, std::size_t count) {
    return SysCall(9, fd, (uintptr_t) buf, count, 0, 0);
}

int Seek(int fd, int offset, int whence) {
    return SysCall(10, fd, offset, whence, 0, 0);
}

char** envp;

[[noreturn]] void StartProgram(int (*main)(int, char *[], char *[]), int argc, char *argv[]) {
    envp = argv + argc + 1;
    Exit(main(argc, argv, envp));
}
