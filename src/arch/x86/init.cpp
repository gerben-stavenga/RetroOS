//
// Created by gerben stavenga on 6/27/23.
//

#include "src/libc/libc.h"

int global = 1;
[[noreturn]] void Shell() {
    global = 2;
    for (int i = 0; i < 3; i++) {
        uprint("I am the child! {} {}\n", i, global);
        Yield();
    }
    Exit(0);
}

extern "C"
int main(int argc, char* argv[]) {
    (void)argc; (void)argv;
    while (true) {
        uprint("Logging in!\n");
        int pid = Fork();
        if (pid == 0) {
            Shell();
        }
        Yield();
    }
}
