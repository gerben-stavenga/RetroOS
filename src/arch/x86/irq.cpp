//
// Created by gerben stavenga on 6/25/23.
//

#include "irq.h"

#include "kassert.h"
#include "x86_inst.h"

constexpr uint16_t kMasterPort = 0x20;
constexpr uint16_t kSlavePort = 0xA0;
constexpr uint8_t kEOI = 0x20;

volatile int key_pressed = 0;

void WaitKeypress() {
    kprint("Press key");
    int key;
    do {
        key = key_pressed;
    } while (key == 0);
    key_pressed = 0;
    kprint(": pressed {}\n", key);
}

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
            if ((key & 0x80) == 0) {
                key_pressed = key;
            }
            //kprint("Key: {} {}\n", key & 0x7F, key & 0x80 ? "released" : "pressed");
            break;
        }
        default:
            break;
    }
    //kprint("IRQ: {} time counter {}\n", irq, counter);
}

void IrqHandler(Regs* regs) {
    int irq = regs->int_no - 32;
    if (irq >= 8) {
        // A slave interrupt is always raised through IRQ 2 of the master,
        // so we have to send an EOI to the master.
        outb(kMasterPort, kEOI);
    }
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
    // Interrupts are allowed to nest except for the same IRQ. At this point the PIC
    // is blocking all IRQs it handles. So we first block the IRQ we are handling.
    auto mask = inb(pic_port + 1);
    outb(pic_port + 1, mask | pic_mask);
    // Acknowledge interrupt by sending End Of Interrupt to PIC.
    outb(pic_port, kEOI);
    // At this point interrupts are resumed except for the IRQ we are handling.

    DoIrq(irq);

    // Unblock IRQ.
    outb(pic_port + 1, mask);
}

void InitializePic(uint16_t port, uint8_t irq_offset, uint8_t cascade) {
    // Sending Initialization Command Words (ICW) to PIC
    // ICW1 - INIT | ICW4
    outb(port, 0x11);
    // ICW2 - Set interrupt offset (must be multiple of 8), because the 3 LSBs are set to the IRQ number..
    outb(port + 1, irq_offset);
    // ICW3 Cascade identity, for master a bitmask of the slave's IRQ, for slave the identity
    outb(port + 1, cascade);
    // ICW4 (8086 mode)
    outb(port + 1, 0x01);

    // Set PIC to Interrupt Service Register mode, subsequent reads from PIC
    // will read ISR (needed for spurious IRQ detection)
    outb(port, 0xb);

    // Unmask all interrupts
    outb(port + 1, 0);
}

void RemapInterrupts() {
    constexpr int kCascadeIRQ = 2;  // Slave is connected to IRQ 2 of master
    // Set master PIC IRQs starting at 32 (0x20)
    InitializePic(kMasterPort, 0x20, 1 << kCascadeIRQ);
    // Set slave PIC IRQs starting at 40 (0x28)
    InitializePic(kSlavePort, 0x28, kCascadeIRQ);
}
