//
// Created by gerben stavenga on 6/25/23.
//

#include "irq.h"

#include "kassert.h"
#include "x86_inst.h"

inline void DoIrq(int irq) {
    static int counter = 0;
    static uint8_t key_state[16]; (void)key_state;
    switch (irq) {
        case 0:
            if ((counter++) & 0xF) return;
            break;
        case 1: {
            int key = inb(0x60);
            key_state[(key & 0x7f) >> 3] = (key >> 7) << (key & 7);
            kprint("Key: {} {}\n", key & 0x7F, key & 0x80 ? "released" : "pressed");
            break;
        }
        default:
            break;
    }
    // kprint("IRQ: {} time counter {}\n", irq, counter);
}

void IrqHandler(Regs* regs) {
    constexpr uint16_t kMasterPort = 0x20;
    constexpr uint16_t kSlavePort = 0xA0;

    int irq = regs->int_no - 32;
    uint16_t pic_port = (irq >= 8 ? kSlavePort : kMasterPort) + 1;
    uint8_t pic_mask = 1 << (irq & 7);

    bool spurious_irq = pic_mask == 0x80;  // irq == 7 || irq == 15
    if (spurious_irq) {
        if ((inb(pic_port) & pic_mask) == 0) {
            kprint("Spurious IRQ: {}\n", irq);
            return;
        }
    }

    // Block IRQ
    outb(pic_port, inb(pic_port) | pic_mask);
    // Acknowledge PIC
    if (irq >= 8) outb(kSlavePort, 0x20);
    outb(kMasterPort, 0x20);

    EnableIRQ();

    DoIrq(irq);

    DisableIRQ();

    // Unblock IRQ
    outb(pic_port, inb(pic_port) & ~pic_mask);
}

void RemapInterrupts() {
    // Mask all interrupts
    outb(0x21, 0xFF);
    outb(0xA1, 0xFF);

    // Remap PIC such that IRQ 0 .. 15 are directed to interrupts 32 .. 47
    // INIT | ICW4
    outb(0x20, 0x11);
    outb(0xA0, 0x11);
    // Set interrupt offset master PIC starts at 32 (0x20) and slave PIC at 40 (0x28)
    outb(0x21, 0x20);
    outb(0xA1, 0x28);
    // Cascade identity, set irq 2 of master to slave
    outb(0x21, 0x04);
    outb(0xA1, 0x02);
    // ICW4 (8086 mode)
    outb(0x21, 0x01);
    outb(0xA1, 0x01);

    // Unmask all interrupts
    outb(0x21, 0);
    outb(0xA1, 0);
}
