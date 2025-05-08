//
// Created by gerben stavenga on 6/25/23.
//

#include "irq.h"

#include "src/kernel/kassert.h"
#include "x86_inst.h"
#include "src/kernel/drv/basic.h"

constexpr uint16_t kMasterPort = 0x20;
constexpr uint16_t kSlavePort = 0xA0;
constexpr uint8_t kEOI = 0x20;

void (*irq_handlers[16])() = {nullptr};

inline uint16_t PicPort(int irq) {
    return irq >= 8 ? kSlavePort : kMasterPort;
}

bool RegisterIrqHandler(int irq, void (*handler)()) {
    uint16_t pic_port = PicPort(irq);
    auto mask = X86_inb(pic_port + 1);
    auto irq_bit = 1 << (irq & 7);
    if ((mask & irq_bit) == 0) {
        // IRQ is already enabled, so we can't register a handler.
        return false;
    }
    X86_outb(pic_port + 1, mask & ~irq_bit);
    irq_handlers[irq] = handler;
    return true;
}


void KeyboardHandler() {
    ProcessKey(X86_inb(0x60));
}

void IrqHandler(Regs* regs) {
    int irq = regs->int_no - 32;
    if (irq >= 8) {
        // A slave interrupt is always raised through IRQ 2 of the master,
        // so we have to send an EOI to the master.
        X86_outb(kMasterPort, kEOI);
    }
    uint16_t pic_port = PicPort(irq);
    uint8_t irq_bit = 1 << (irq & 7);

    bool spurious_irq = irq_bit == 0x80;  // irq == 7 || irq == 15
    if (spurious_irq) {
        // Note, we have set the PIC to ISR mode, so we can read the ISR from the PIC.
        auto isr_reg = X86_inb(pic_port);
        if ((isr_reg & irq_bit) == 0) return;
    }
    // Interrupts are allowed to nest except for the same IRQ. At this point the PIC
    // is blocking all IRQs it handles. So we first block the IRQ we are handling.
    auto mask = X86_inb(pic_port + 1);
    X86_outb(pic_port + 1, mask | irq_bit);
    // Acknowledge interrupt by sending End Of Interrupt to PIC.
    X86_outb(pic_port, kEOI);
    // At this point interrupts are resumed except for the IRQ we are handling.

    if (irq_handlers[irq] != nullptr) {
        irq_handlers[irq]();
    } else {
        kprint("Unhandled IRQ {}\n", irq);
    }

    // Unblock IRQ.
    X86_outb(pic_port + 1, mask);
}

void InitializePit(int channel, int frequency) {
    constexpr uint16_t kPitPort = 0x40;
    constexpr uint16_t kCommand = 3;
    // Set PIT to mode 3 (square wave generator)
    // channel(2 bits) = 0, rw mode (2 bits) = 3 (LSB then MSB), mode (3 bits) = 3 (square wave), bcd (1 bit) = 0
    constexpr uint8_t kMode3 = 0x36;
    X86_outb(kPitPort + kCommand, (channel << 6) | kMode3);
    // 2^32 ticks per hour equals 1193046.47111 Hz which is surprisingly close to 1193182 Hz.
    // The lowest frequency is chosen when the divisor = 65536 leading to the classical 18.2 Hz timer.
    // Calculate divisor for frequency
    constexpr int kPitFrequency = 1193182;
    auto divisor = kPitFrequency / frequency;
    if (divisor > 0xFFFF) {
        divisor = 0;  // 0 means 65536
    } else if (divisor < 1) {
        divisor = 1;
    }
    // Set frequency by sending the divisor LSB then MSB
    X86_outb(kPitPort + channel, divisor & 0xFF);
    X86_outb(kPitPort + channel, divisor >> 8);
}

void InitializePic(uint16_t port, uint8_t irq_offset, uint8_t cascade) {
    // Sending Initialization Command Words (ICW) to PIC
    // ICW1 - INIT | ICW4
    X86_outb(port, 0x11);
    // ICW2 - Set interrupt offset (must be multiple of 8), because the 3 LSBs are set to the IRQ number..
    X86_outb(port + 1, irq_offset);
    // ICW3 Cascade identity, for master a bitmask of the slave's IRQ, for slave the identity
    X86_outb(port + 1, cascade);
    // ICW4 (8086 mode)
    X86_outb(port + 1, 0x01);

    // Set PIC to Interrupt Service Register mode, subsequent reads from PIC
    // will read ISR (needed for spurious IRQ detection)
    X86_outb(port, 0xb);

    // Mask all interrupts, except for the cascade IRQ
    X86_outb(port + 1, port == kMasterPort ? ~cascade : 0xff);
}

void RemapInterrupts() {
    constexpr int kCascadeIRQ = 2;  // Slave is connected to IRQ 2 of master
    // Set master PIC IRQs starting at 32 (0x20)
    InitializePic(kMasterPort, 0x20, 1 << kCascadeIRQ);
    // Set slave PIC IRQs starting at 40 (0x28)
    InitializePic(kSlavePort, 0x28, kCascadeIRQ);

    InitializePit(0, 1000);
    RegisterIrqHandler(0, TimerHandler);
    RegisterIrqHandler(1, KeyboardHandler);
}
