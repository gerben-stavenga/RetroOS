//
// Created by gerben stavenga on 6/27/23.
//

#include "src/libc/libc.h"

[[noreturn]] void shell() {

    // create
    while (true) {
        uprint("shell> ");
        char buf[256];
        int n = uread(buf, 256);
        buf[n] = '\0';
        uprint("You typed: {}\n", buf);
    }
}

int main(int argc, char* argv[]) {
    (void)argc; (void)argv;
    uprint("Hello, world!\n");
    int pid = Fork();
    if (pid == 0) {
        uprint("I am the child!\n");
        Exit(0);
        uprint("This should not be printed!\n");
    }
    while (true) {
        asm volatile("");
    }
}
