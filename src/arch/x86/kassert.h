//
// Created by gerben stavenga on 6/25/23.
//

#ifndef OS_KASSERT_H
#define OS_KASSERT_H

#include "src/freestanding/utils.h"

struct KernelOutput;

extern KernelOutput kout;

template <typename... Args>
void kprint(std::string_view fmt, Args... args) {
    print(reinterpret_cast<OutputStream&>(kout), fmt, args...);
}

template<typename... Args>
void panic(std::string_view format, const Args&... args) {
    kprint("Kernel panic: ");
    kprint(format, args...);
    exit(-1);
}

void StackTrace();

#endif //OS_KASSERT_H
