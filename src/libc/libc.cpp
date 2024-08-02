//
// Created by gerben stavenga on 6/27/23.
//

#include "libc.h"

uintptr_t SysCall(uintptr_t num, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4) {
    asm volatile("int $0x80"
                 : "+a"(num), "+d"(arg0)
                 : "c"(arg1), "b"(arg2), "S"(arg3), "D"(arg4)
                 : "memory");
    return num;
}

char** envp;

[[noreturn]] void StartProgram(int (*main)(int, char *[], char *[]), int argc, char *argv[]) {
    envp = argv + argc + 1;
    Exit(main(argc, argv, envp));
}
