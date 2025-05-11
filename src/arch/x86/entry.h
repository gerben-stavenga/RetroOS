//
// Created by gerben stavenga on 6/25/23.
//

#ifndef OS_ENTRY_H
#define OS_ENTRY_H

#include <cstdint>

#include "src/freestanding/utils.h"

// Matches the stack frame of the entry.asm
struct Regs {
    uint32_t gs, fs, es, ds;
    uint32_t edi, esi, ebp, temp_esp, ebx, edx, ecx, eax;
    uint32_t int_no, err_code;
    uint32_t eip, cs, eflags, esp, ss;

    ValuePrinter MakeValuePrinter() const {
        ValuePrinter res;
        res.p = this;
        res.print = Print;
        return res;
    }

    static char* Print(char* pos, BufferedOStream& out, const ValuePrinter& v) {
        auto p = static_cast<const Regs*>(v.p);
        return print(pos, out, "Regs eip: {}, esp: {}, eax: {}\n", p->eip, p->esp, p->eax);
    }
};

extern "C" uint64_t int_vector[];

extern "C" [[noreturn]] void exit_kernel(Regs* regs);

#endif //OS_ENTRY_H
