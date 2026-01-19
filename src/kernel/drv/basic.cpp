#include "basic.h"

#include <cstdint>

#include "src/kernel/kassert.h"

PipeN<1024> key_pipe;
static volatile int counter = 0;

int GetTime() {
    return counter;
}

void TimerHandler() {
    counter++;
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

const char kbd_US[128] = {
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
const char kbd_US_shift[128] = {
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

void ProcessKey(int key) {
    static uint8_t key_state[16];
    if ((key & 0x80) == 0) {
        key_state[(key & 0x7f) >> 3] |= 1 << (key & 7);
        bool shift = (key_state[LSHIFT / 8] & (1 << (LSHIFT & 7))) || (key_state[RSHIFT / 8] & (1 << (RSHIFT & 7)));
        int8_t c = shift ? kbd_US_shift[key] : kbd_US[key];
        bool capslock = key_state[CAPSLOCK / 8] & (1 << (CAPSLOCK & 7));
        if (capslock && std::isalpha(c)) {
            c ^= 32;
        }
        if (c == -82) {
            // Insert key
            StackTrace();
        }
        if (c <= 0) {
            return;
        } else {
            key_pipe.Push(c);
        }
    } else {
        key_state[(key & 0x7f) >> 3] &= ~(1 << (key & 7));
    }
}
