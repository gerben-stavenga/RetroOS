#ifndef ARCH_X86_THREAD_H
#define ARCH_X86_THREAD_H

#include "entry.h"

void SegvCurrentThread(Regs* regs, std::uintptr_t fault_address);

#endif // ARCH_X86_THREAD_H