//
// Created by gerben stavenga on 6/27/23.
//

#include "src/libc/libc.h"

int global = 1;
[[noreturn]] void Shell() {
    // global = 2;
    for (int i = 0; i < 3; i++) {
        kprint("I am the child! {} {}\n", i, global);
        Yield();
    }
    Exit(0);
}

extern "C"
int main(int argc, char* argv[]) {
    (void)argc; (void)argv;
    int i = 0;
    while (true) {
        kprint("Logging in {}!\n", ++i);
        if (1) {
            int r = Fork();
            if (r == 0) {
                Shell();
            }
            Yield();
        }
    }
}
