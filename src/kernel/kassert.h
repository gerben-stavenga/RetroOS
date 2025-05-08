//
// Created by gerben stavenga on 6/25/23.
//

#ifndef OS_KASSERT_H
#define OS_KASSERT_H

#include "src/freestanding/utils.h"

template<typename... Args>
void panic(std::string_view format, const Args&... args) {
    kprint("Kernel panic: ");
    kprint(format, args...);
    Exit(-1);
}

void StackTrace();

#endif //OS_KASSERT_H
