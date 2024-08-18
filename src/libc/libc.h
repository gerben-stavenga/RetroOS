//
// Created by gerben stavenga on 6/27/23.
//

#ifndef OS_LIBC_H
#define OS_LIBC_H

#include <cstdint>
#include <cstddef>

#include "src/freestanding/utils.h"

inline uintptr_t SysCall(uintptr_t num, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4) {
    asm volatile("int $0x80"
                 : "+a"(num), "+d"(arg0)
                 : "c"(arg1), "b"(arg2), "S"(arg3), "D"(arg4)
                 : "memory");
    return num;
}


[[noreturn]] void Exit(int code);
void Yield();
void* Alloc(std::size_t size);
void Free(void* ptr);
int Fork();
void Exec(const char* path, char* const argv[], char* const envp[]);
int Open(const char* path, int flags, int mode);
void Close(int fd);
std::size_t Read(int fd, void* buf, std::size_t count);
int Write(int fd, const void* buf, std::size_t count);
int Seek(int fd, int offset, int whence);

class Reader : public InputStream {
public:
    Reader(int fd) : fd_(fd) {}

    std::size_t Pull(char* buf, std::size_t max_len) override {
        return Read(fd_, buf, max_len);
    }

private:
    int fd_;
};

class Writer : public OutputStream {
public:
    Writer(int fd) : fd_(fd) {}

    void Push(std::string_view s) override {
        Write(fd_,s.data(), s.size());
    }

private:
    int fd_;
};

template <typename... Args>
void uprint(std::string_view s, const Args&... args) {
    Writer w(1);
    print(w, s, args...);
}

#endif //OS_LIBC_H
