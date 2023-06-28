//
// Created by gerben stavenga on 6/27/23.
//

#ifndef OS_LIBC_H
#define OS_LIBC_H

#include <stdint.h>
#include <stddef.h>

#include "src/freestanding/utils.h"

uintptr_t SysCall(uintptr_t num, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4);

void Exit(int code);

void* Alloc(size_t size);
void Free(void* ptr);

int Fork();

void Exec(const char* path, char* const argv[], char* const envp[]);

int Open(const char* path, int flags, int mode);

void Close(int fd);

int Read(int fd, void* buf, size_t count);

int Write(int fd, const void* buf, size_t count);

int Seek(int fd, int offset, int whence);

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
