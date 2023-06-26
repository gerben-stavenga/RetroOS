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

NOINLINE [[noreturn]] void hlt();

template <typename... Args>
void kprint(string_view fmt, Args... args) {
    print(kout, fmt, args...);
}

template<typename... Args>
void panic(string_view format, const Args&... args) {
    kprint("Kernel panic: ");
    kprint(format, args...);
    hlt();
}

[[noreturn]] void panic_assert(string_view str, string_view file, int line);

inline void AssertImpl(bool cond, string_view cond_str, string_view file, int line) {
    if (!cond && kDebug) panic_assert(cond_str, file, line);
}

#define kassert(cond) AssertImpl((cond), #cond, __FILE__, __LINE__)

#endif //OS_KASSERT_H
