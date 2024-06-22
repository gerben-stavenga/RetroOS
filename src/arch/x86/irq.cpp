//
// Created by gerben stavenga on 6/25/23.
//

#include "irq.h"

#include "kassert.h"
#include "x86_inst.h"
#include "pipe.h"

constexpr uint16_t kMasterPort = 0x20;
constexpr uint16_t kSlavePort = 0xA0;
constexpr uint8_t kEOI = 0x20;

volatile PipeN<1024> key_pipe;
static volatile int counter = 0;
volatile bool should_yield = false;

void WaitKeypress() {
    kprint("Press key");
    while (key_pipe.Empty()) {}
    int key = key_pipe.Pop();
    kprint(": pressed {}\n", key);
}

int GetTime() {
    return counter;
}

void (*irq_handlers[16])() = {nullptr};

bool RegisterIrqHandler(int irq, void (*handler)()) {
    uint16_t pic_port = (irq >= 8 ? kSlavePort : kMasterPort);
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

void TimerHandler() {
    counter++;
    should_yield = true;
}

enum Special {
    LSHIFT = 0x2A,
    RSHIFT = 0x36,
    CTRL = 0x1D,
    ALT = 0x38,
    CAPSLOCK = 0x3A,
    F1 = 0x3B,
    F2 = 0x3C,
    F3 = 0x3D,
    F4 = 0x3E,
    F5 = 0x3F,
    F6 = 0x40,
    F7 = 0x41,
    F8 = 0x42,
    F9 = 0x43,
    F10 = 0x44,
    F11 = 0x57,
    F12 = 0x58,
    NUMLOCK = 0x45,
    SCROLLLOCK = 0x46,
    HOME = 0x47,
    UP = 0x48,
    PGUP = 0x49,
    LEFT = 0x4B,
    RIGHT = 0x4D,
    END = 0x4F,
    DOWN = 0x50,
    PGDN = 0x51,
    INS = 0x52,
    DEL = 0x53,
};

char kbd_US[128] = {
    0,
    27,  // Escape
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b', '\t',
    'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n',
    -29, /* control key */
    'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`',
    -42, /* left shift */
    '\\',
    'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/',
    -54, /* right shift */
    '*',
    -56,  /* Alt */
    ' ',  /* Space bar */
    -58,  /* Caps lock */
    -59, -60, -61, -62, -63, -64, -65, -66, -67, -68,  /* F1 - F10 keys */
    -69,  /* 69 - Num lock*/
    -70,  /* Scroll Lock */
    -71,  /* Home key */
    -72,  /* Up Arrow */
    -73,  /* Page Up */
    '-',
    -75,  /* Left Arrow */
    0,
    -77,  /* Right Arrow */
    '+',
    -79,  /* 79 - End key*/
    -80,  /* Down Arrow */
    -81,  /* Page Down */
    -82,  /* Insert Key */
    -83,  /* Delete Key */
    0,   0,   0,
    -87,  /* F11 Key */
    -88,  /* F12 Key */
    0,  /* All other keys are undefined */
};
char kbd_US_shift[128] = {
    0,
    27,  // Escape
    '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '\b', '\t',
    'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n',
    -29, /* control key */
    'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '\"', '~',
    -42,  /* left shift */
    '|',
    'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?',
    -54,  /* right shift */
    '*',  /* keypad '*' */
    -56,  /* Alt */
    ' ',  /* Space bar */
    -58,  /* Caps lock */
    -59, -60, -61, -62, -63, -64, -65, -66, -67, -68,
    -69,  /* 69 - Num lock*/
    -70,  /* Scroll Lock */
    -71,  /* Home key */
    -72,  /* Up Arrow */
    -73,  /* Page Up */
    '-',
    -75,  /* Left Arrow */
    0,
    -77,  /* Right Arrow */
    '+',
    -79,  /* 79 - End key*/
    -80,  /* Down Arrow */
    -81,  /* Page Down */
    -82,  /* Insert Key */
    -83,  /* Delete Key */
    0,   0,   0,
    -87,  /* F11 Key */
    -88,  /* F12 Key */
    0,  /* All other keys are undefined */
};

void KeyboardHandler() {
    static uint8_t key_state[16];
    int key = X86_inb(0x60);
    if ((key & 0x80) == 0) {
        key_state[(key & 0x7f) >> 3] |= 1 << (key & 7);
        bool shift = (key_state[LSHIFT / 8] & (1 << (LSHIFT & 7))) || (key_state[RSHIFT / 8] & (1 << (RSHIFT & 7)));
        bool capslock = key_state[CAPSLOCK / 8] & (1 << (CAPSLOCK & 7));
        int8_t c = (shift != capslock) ? kbd_US_shift[key] : kbd_US[key];
        if (c <= 0) {
            return;
        } else {
            key_pipe.Push(c);
        }
    } else {
        key_state[(key & 0x7f) >> 3] &= ~(1 << (key & 7));
    }
}

void IrqHandler(Regs* regs) {
    int irq = regs->int_no - 32;
    if (irq >= 8) {
        // A slave interrupt is always raised through IRQ 2 of the master,
        // so we have to send an EOI to the master.
        X86_outb(kMasterPort, kEOI);
    }
    uint16_t pic_port = (irq >= 8 ? kSlavePort : kMasterPort);
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

    InitializePit(0, 100);
    RegisterIrqHandler(0, TimerHandler);
    RegisterIrqHandler(1, KeyboardHandler);
}
