//
// Created by gerben stavenga on 6/25/23.
//

#ifndef OS_KASSERT_H
#define OS_KASSERT_H

#include "src/freestanding/utils.h"

class KernelOutput : public OutputStream {
public:
    void Push(string_view str) override;
};

extern KernelOutput kout;

NOINLINE [[noreturn]] void terminate();

template <typename... Args>
void kprint(string_view fmt, Args... args) {
    print(kout, fmt, args...);
}

template<typename... Args>
void panic(string_view format, const Args&... args) {
    kprint("Kernel panic: ");
    kprint(format, args...);
    terminate();
}

#define kassert(cond) AssertImpl((cond), kout, #cond, __FILE__, __LINE__)

#endif //OS_KASSERT_H
