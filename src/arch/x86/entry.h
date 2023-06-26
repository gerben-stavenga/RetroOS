//
// Created by gerben stavenga on 6/25/23.
//

#ifndef OS_ENTRY_H
#define OS_ENTRY_H

#include <stdint.h>

// Matches the stack frame of the entry.asm
struct Regs {
    uint32_t gs, fs, es, ds;
    uint32_t edi, esi, ebp, temp_esp, ebx, edx, ecx, eax;
    uint32_t int_no, err_code;
    uint32_t eip, cs, eflags, esp, ss;
};

#endif //OS_ENTRY_H
