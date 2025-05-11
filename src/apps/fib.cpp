#include "src/libc/libc.h"

extern "C"
int main(int argc, char* argv[]) {
    int a = 0;
    int b = 1;
    for (int i = 0; i < 10; i++) {
        kprint("{} {}\n", i, a);
        int c = a + b;
        a = b;
        b = c;
    }
    return 0;
}
