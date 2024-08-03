#include "libc.h"

extern "C"
int main(int argc, char* argv[], char* envp[]);

[[noreturn]] void StartProgram(int (*main)(int, char *[], char *[]), int argc, char *argv[]);

extern "C"
__attribute__((fastcall))
[[noreturn]] void _start(int argc, char* argv[]) {
    StartProgram(main, argc, argv);
}
