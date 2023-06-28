//
// Created by gerben stavenga on 6/27/23.
//

#include "libc.h"

uintptr_t SysCall(uintptr_t num, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4) {
    asm volatile("int $0x80"
                 : "+a"(num)
                 : "b"(arg0), "c"(arg1), "d"(arg2), "S"(arg3), "D"(arg4)
                 : "memory");
    return num;
}

void Exit(int code) {
    SysCall(1, code, 0, 0, 0, 0);
}

void* Alloc(size_t size) {
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

int Read(int fd, void* buf, size_t count) {
    return SysCall(8, fd, (uintptr_t) buf, count, 0, 0);
}

int Write(int fd, const void* buf, size_t count) {
    return SysCall(9, fd, (uintptr_t) buf, count, 0, 0);
}

int Seek(int fd, int offset, int whence) {
    return SysCall(10, fd, offset, whence, 0, 0);
}
