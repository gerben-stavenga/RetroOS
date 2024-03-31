//
// Created by gerben stavenga on 6/27/23.
//

#ifndef OS_LIBC_H
#define OS_LIBC_H

#include <stdint.h>
#include <stddef.h>

#include "src/freestanding/utils.h"

uintptr_t SysCall(uintptr_t num, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4);

inline void Exit(int code) {
    SysCall(0, code, 0, 0, 0, 0);
}

inline void Yield() {
    SysCall(1, 0, 0, 0, 0, 0);
}

#if 0
inline void* Alloc(size_t size) {
    return (void*) SysCall(2, size, 0, 0, 0, 0);
}

inline void Free(void* ptr) {
    SysCall(3, (uintptr_t) ptr, 0, 0, 0, 0);
}
#endif

inline int Fork() {
    return SysCall(4, 0, 0, 0, 0, 0);
}

inline void Exec(const char* path, char* const argv[], char* const envp[]) {
    SysCall(5, (uintptr_t) path, (uintptr_t) argv, (uintptr_t) envp, 0, 0);
}

inline int Open(const char* path, int flags, int mode) {
    return SysCall(6, (uintptr_t) path, flags, mode, 0, 0);
}

inline void Close(int fd) {
    SysCall(7, fd, 0, 0, 0, 0);
}

inline size_t Read(int fd, void* buf, size_t count) {
    return SysCall(8, fd, (uintptr_t) buf, count, 0, 0);
}

inline int Write(int fd, const void* buf, size_t count) {
    return SysCall(9, fd, (uintptr_t) buf, count, 0, 0);
}

inline int Seek(int fd, int offset, int whence) {
    return SysCall(10, fd, offset, whence, 0, 0);
}

class Reader : public InputStream {
public:
    Reader(int fd) : fd_(fd) {}

    size_t Pull(char* buf, size_t max_len) override {
        return Read(fd_, buf, max_len);
    }

private:
    int fd_;
};

class Writer : public OutputStream {
public:
    Writer(int fd) : fd_(fd) {}

    void Push(string_view s) override {
        Write(fd_,s.data(), s.size());
    }

private:
    int fd_;
};

template <typename... Args>
void uprint(string_view s, const Args&... args) {
    Writer w(1);
    print(w, s, args...);
}

#endif //OS_LIBC_H
