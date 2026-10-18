/* No libc: verify the Linux random ABI before and after interrupt seeding. */
typedef unsigned long word;
#if defined(__x86_64__)
#define SYS_RANDOM 318
#define SYS_WRITE 1
#define SYS_EXIT 60
static long call(word nr, word a, word b, word c) {
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(nr), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return result;
}
#else
#define SYS_RANDOM 355
#define SYS_WRITE 4
#define SYS_EXIT 1
static long call(word nr, word a, word b, word c) {
    long result;
    __asm__ volatile("int $0x80" : "=a"(result) : "a"(nr), "b"(a), "c"(b), "d"(c) : "memory");
    return result;
}
#endif
static void finish(int code) {
    call(SYS_EXIT, code, 0, 0);
    for (;;) {}
}
static void check(int ok, int code) { if (!ok) finish(code); }
static unsigned char bytes[131072];
static unsigned char previous[32];
void __attribute__((force_align_arg_pointer)) _start(void) {
    for (word i = 0; i < sizeof(bytes); ++i) bytes[i] = 0xaa;
    check(call(SYS_RANDOM, (word)bytes, 32, 8) == -22, 10);
    check(call(SYS_RANDOM, 0, 1, 1) == -14, 11);
    check(call(SYS_RANDOM, 0, 0, 0) == 0, 12);
    check(call(SYS_RANDOM, (word)bytes, 32, 1) == -11, 13);
    for (word i = 0; i < sizeof(bytes); ++i) check(bytes[i] == 0xaa, 14);
    static const char waiting[] = "GETRANDOM WAITING\n";
    call(SYS_WRITE, 2, (word)waiting, sizeof(waiting) - 1);
    /* Must stay blocked until the kernel entropy pool is actually seeded. */
    check(call(SYS_RANDOM, (word)bytes, 32, 0) == 32, 15);
    for (word i = 0; i < sizeof(previous); ++i) previous[i] = bytes[i];
    check(call(SYS_RANDOM, (word)bytes, 32, 3) == 32, 16);
    int different = 0;
    for (word i = 0; i < sizeof(previous); ++i) different |= previous[i] != bytes[i];
    check(different, 17);
    check(call(SYS_RANDOM, (word)bytes, sizeof(bytes), 0) == 65536, 18);
    for (word i = 65536; i < sizeof(bytes); ++i) check(bytes[i] == 0xaa, 19);
    static const char ready[] = "GETRANDOM PASS\n";
    call(SYS_WRITE, 2, (word)ready, sizeof(ready) - 1);
    finish(0);
}
