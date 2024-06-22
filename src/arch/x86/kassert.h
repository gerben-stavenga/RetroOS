//
// Created by gerben stavenga on 6/25/23.
//

#ifndef OS_KASSERT_H
#define OS_KASSERT_H

#include "src/freestanding/utils.h"

struct KernelOutput;

extern KernelOutput kout;

template <typename... Args>
void kprint(string_view fmt, Args... args) {
    print(reinterpret_cast<OutputStream&>(kout), fmt, args...);
}

template<typename... Args>
void panic(string_view format, const Args&... args) {
    kprint("Kernel panic: ");
    kprint(format, args...);
    terminate(-1);
}

#define kassert(cond) AssertImpl((cond), reinterpret_cast<OutputStream&>(kout), #cond, __FILE__, __LINE__)

#endif //OS_KASSERT_H
