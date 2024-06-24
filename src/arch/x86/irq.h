//
// Created by gerben stavenga on 6/25/23.
//

#ifndef OS_IRQ_H
#define OS_IRQ_H

#include "entry.h"
#include "pipe.h"

extern PipeN<1024> key_pipe;

int GetTime();
void IrqHandler(Regs* regs);
void RemapInterrupts();

#endif //OS_IRQ_H
