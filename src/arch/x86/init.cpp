//
// Created by gerben stavenga on 6/27/23.
//

#include "src/libc/libc.h"

[[noreturn]] void Shell() {
    while (true) {
        uprint("I am the child!\n");
        while (true) {
            asm volatile("");
        }
        Yield();
    }
    Exit(0);
    uprint("This should not be printed!\n");
}

extern "C"
int main(int argc, char* argv[]) {
    (void)argc; (void)argv;
    uprint("Hello, world!\n");
    int pid = Fork();
    if (pid == 0) {
        Shell();
    }
    while (true) {
        asm volatile("");
    }
}
