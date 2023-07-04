//
// Created by gerben stavenga on 6/25/23.
//

#ifndef OS_IRQ_H
#define OS_IRQ_H

#include "entry.h"

void WaitKeypress();
void IrqHandler(Regs* regs);
void RemapInterrupts();

#endif //OS_IRQ_H
