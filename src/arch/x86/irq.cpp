//
// Created by gerben stavenga on 6/25/23.
//

#include "irq.h"

#include "kassert.h"
#include "x86_inst.h"

constexpr uint16_t kMasterPort = 0x20;
constexpr uint16_t kSlavePort = 0xA0;

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
    //kprint("IRQ: {} time counter {}\n", irq, counter);
}

void IrqHandler(Regs* regs) {
    int irq = regs->int_no - 32;
    uint16_t pic_port = (irq >= 8 ? kSlavePort : kMasterPort);
    uint8_t pic_mask = 1 << (irq & 7);

    bool spurious_irq = pic_mask == 0x80;  // irq == 7 || irq == 15
    if (spurious_irq) {
        // Note, we have set the PIC to ISR mode, so we can read the ISR from the PIC.
        auto isr_reg = inb(pic_port);
        if ((isr_reg & pic_mask) == 0) {
            return;
        }
    }

    // Block IRQ
    outb(pic_port + 1, inb(pic_port + 1) | pic_mask);
    // Acknowledge PIC
    outb(pic_port, 0x20);

    DoIrq(irq);

    // Unblock IRQ
    outb(pic_port + 1, inb(pic_port + 1) & ~pic_mask);
}

void IrqSlaveHandler(Regs* regs) {
    // A slave interrupt is always raised through IRQ 2 of the master, so we have to send an EOI to the master.
    outb(kMasterPort, 0x20);
    IrqHandler(regs);
}

void RemapInterrupts() {
    // Mask all interrupts
    outb(kMasterPort + 1, 0xFF);
    outb(kSlavePort + 1, 0xFF);

    // Remap PIC such that IRQ 0 .. 15 are directed to interrupts 32 .. 47
    // INIT | ICW4
    outb(kMasterPort, 0x11);
    outb(kSlavePort, 0x11);
    // Set interrupt offset master PIC starts at 32 (0x20) and slave PIC at 40 (0x28)
    outb(kMasterPort + 1, 0x20);
    outb(kSlavePort + 1, 0x28);
    // Cascade identity, set irq 2 of master to slave
    outb(kMasterPort + 1, 0x04);
    outb(kSlavePort + 1, 0x02);
    // ICW4 (8086 mode)
    outb(kMasterPort + 1, 0x01);
    outb(kSlavePort + 1, 0x01);

    // Set PIC to ISR mode, subsequent reads from PIC will read ISR
    outb(kMasterPort, 0xa);
    outb(kSlavePort, 0xa);

    // Unmask all interrupts
    outb(kMasterPort + 1, 0);
    outb(kSlavePort + 1, 0);
}
