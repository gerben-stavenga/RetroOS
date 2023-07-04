//
// Created by gerben stavenga on 6/27/23.
//

#include "src/libc/libc.h"

int main(int argc, char* argv[]) {
    (void)argc; (void)argv;
    uprint("Hello, world!\n");
    while (true) asm volatile("");
}
