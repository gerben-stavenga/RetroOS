//
// Created by gerben stavenga on 6/27/23.
//

#include "src/libc/libc.h"

int global = 1;

[[noreturn]] void Shell() {
    while (true) {
        kprint("Shell: ");
        char buf[256];
        int pos = 0;
        char c;
        do {
            while (Read(0, &c, 1) == 0);
            buf[pos++] = c;
        } while (c != '\n');
        buf[pos - 1] = 0;
        auto str = std::string_view(buf, pos - 1);
        kprint("{}\n", str);
        if (str == "exit") {
            kprint("Exiting shell\n");
            break;
        } else if (str.substr(0, 4) == "cat ") {
            int fd = Open(buf + 4, 0, 0);
            if (fd < 0) {
                kprint("Failed to open file {}\n", buf + 4);
                continue;
            }
            void* p = malloc(fd);
            Read(fd, p, fd);
            free(p);
        } else {
            kprint("Executing command {}\n", str);
            Exec("src/apps/fib.elf", nullptr, nullptr);
        }
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
