#include "libc.h"

extern "C"
int main(int argc, char* argv[], char* envp[]);

[[noreturn]] void StartProgram(int (*main)(int, char *[], char *[]), int argc, char *argv[]);

extern "C"
__attribute__((fastcall))
[[noreturn]] void _start(int argc, char* argv[]) {
    InitializeAllocator((void*)0x10000, 0x100000);
    StartProgram(main, argc, argv);
}
