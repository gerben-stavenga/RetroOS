//
// Created by gerben stavenga on 6/25/23.
//

#ifndef OS_ENTRY_H
#define OS_ENTRY_H

#include <cstdint>

#include "src/freestanding/utils.h"

// The registers are ordered in machine encoding order. In entry.asm the registers are
// pushed to match this order.
enum RegisterIndex {
    RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
    R8,  R9,  R10, R11, R12, R13, R14, R15
};

// Matches the stack frame of the entry.asm
struct Regs {
    uint32_t gs, fs, es, ds;
    uint32_t entry_eip, entry_cs;  // cs can be used to check the mode of the CPU
    uint64_t regs[16];
    uint32_t int_no, err_code;
    
    ValuePrinter MakeValuePrinter() const {
        ValuePrinter res;
        res.p = this;
        res.print = Print;
        return res;
    }

    static char* Print(char* pos, BufferedOStream& out, const ValuePrinter& v) {
        auto p = static_cast<const Regs*>(v.p);
        // return print(pos, out, "Regs eip: {}, esp: {}, eax: {}\n", p->rip, p->rsp, p->rax);
        return print(pos, out, "Regs eax: {} ebx: {} ecx: {} edx: {}\n", p->regs[RAX], p->regs[RBX], p->regs[RCX], p->regs[RDX]);
    }
};

struct Frame32 : Regs {
    uint32_t eip, cs, eflags, esp, ss;
};

struct Frame64 : Regs {
    uint64_t rip, cs, eflags, rsp, ss;
};

extern "C" uint64_t int_vector[];

extern "C" [[noreturn]] void exit_kernel(Regs* regs);

#endif //OS_ENTRY_H
