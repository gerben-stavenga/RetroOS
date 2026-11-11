/* Sparse multi-terabyte reservations, high buffers, protections and fork COW. */
#include <asm/unistd.h>
typedef unsigned long word;
static long call(word nr, word a, word b, word c, word d, word e, word f) {
    register word r10 __asm__("r10") = d;
    register word r8 __asm__("r8") = e;
    register word r9 __asm__("r9") = f;
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return result;
}
static void quit(int code) { call(__NR_exit, code, 0, 0, 0, 0, 0); for (;;) {} }
static void check(int ok, int code) { if (!ok) quit(code); }
static long map(word address, word size, word prot, word flags) {
    return call(__NR_mmap, address, size, prot, flags, -1UL, 0);
}
static long protect(word address, word size, word prot) { return call(__NR_mprotect, address, size, prot, 0, 0, 0); }
static long unmap(word address, word size) { return call(__NR_munmap, address, size, 0, 0, 0, 0); }
__attribute__((force_align_arg_pointer)) void _start(void) {
    const word size = 4UL << 40;
    long reservation = map(0, size, 0, 0x22);
    check(reservation >= (1L << 39), 10);
    word base = reservation;
    // An explicit hint below the automatic frontier must not collide with
    // the next downward allocation, even though the hint did not move it.
    word hint = base - (8UL << 30);
    check(map(hint, 4UL << 30, 0, 0x22) == (long)hint, 49);
    long automatic = map(0, 12UL << 30, 0, 0x22);
    check(automatic >= (1L << 39) && (word)automatic + (12UL << 30) <= hint, 50);
    check(unmap(automatic, 12UL << 30) == 0 && unmap(hint, 4UL << 30) == 0, 51);
    word at = base + (1UL << 40) + 0x23000;
    volatile unsigned char *p = (void *)at;
    check(map(at, 4096, 3, 0x100022) == -17, 11);
    check(protect(at, 12288, 3) == 0, 12);
    check(p[0] == 0 && p[8192] == 0, 13);
    p[0] = 41; p[4095] = 42; p[4096] = 43; p[8192] = 44;
#ifdef NO_EXECUTE
    ((void (*)(void))at)();
    quit(94);
#elif defined(READ_ONLY)
    check(protect(at, 4096, 1) == 0, 14);
    p[0] = 99;
    quit(90);
#elif defined(NO_ACCESS)
    check(protect(at, 4096, 0) == 0, 15);
    unsigned char value = p[0];
    quit(value == 99 ? 91 : 92);
#elif defined(UNMAPPED)
    check(unmap(at, 4096) == 0, 16);
    p[0] = 99;
    quit(93);
#else
    // Smaller reservations also fall back high once the low window is full.
    long low = map(0, 0x60000000UL, 0, 0x22);
    check(low > 0 && low < 0xc0000000L, 52);
    check(map(0, 0x80000000UL, 0, 0x62) == -12, 53); /* MAP_32BIT stays low. */
    long overflow = map(0, 0x80000000UL, 0, 0x22);
    check(overflow >= (1L << 39), 54);
    check(unmap(low, 0x60000000UL) == 0 && unmap(overflow, 0x80000000UL) == 0, 55);
    // Execute generated code above 4 GiB, then restore the data permissions.
    volatile unsigned char *code = p + 8192;
    code[0] = 0xb8; code[1] = 42; code[2] = 0; code[3] = 0; code[4] = 0; code[5] = 0xc3;
    check(protect(at + 8192, 4096, 5) == 0, 42);
    check(((int (*)(void))(at + 8192))() == 42, 43);
    check(protect(at + 8192, 4096, 3) == 0, 44);
    // Touch a separate PML4 slot and a separate PDPT/PD/PT boundary.
    word other = at + (1UL << 39) + (1UL << 30) + (1UL << 21);
    check(protect(other, 4096, 3) == 0, 17);
    *(volatile word *)other = 0x123456789abcdef0UL;
    check(*(volatile word *)other == 0x123456789abcdef0UL, 18);
    int descriptors[2];
    check(call(__NR_pipe, (word)descriptors, 0, 0, 0, 0, 0) == 0, 19);
    check(call(__NR_write, descriptors[1], at + 4095, 2, 0, 0, 0) == 2, 20);
    check(call(__NR_read, descriptors[0], at + 8191, 2, 0, 0, 0) == 2, 21);
    check(p[8191] == 42 && p[8192] == 43, 22);
    check(call(__NR_write, descriptors[1], base, 1, 0, 0, 0) == -14, 23);
    long child = call(__NR_fork, 0, 0, 0, 0, 0, 0);
    check(child >= 0, 24);
    if (child == 0) {
        check(p[0] == 41, 25);
        p[0] = 100;
        *(volatile word *)other = 7;
        check(protect(at + 4096, 4096, 0) == 0, 26);
        check(call(__NR_madvise, at + 8192, 4096, 4, 0, 0, 0) == 0, 27);
        check(p[8192] == 0, 28);
        p[8192] = 11;
        check(unmap(base, size) == 0, 29);
        quit(0);
    }
    int status = -1;
    check(call(__NR_wait4, child, (word)&status, 0, 0, 0, 0) == child && status == 0, 30);
    check(p[0] == 41 && p[4096] == 43 && p[8192] == 43, 31);
    check(*(volatile word *)other == 0x123456789abcdef0UL, 32);
    check(protect(at, 4096, 0) == 0 && protect(at, 4096, 3) == 0 && p[0] == 41, 33);
    check(call(__NR_madvise, at, 4096, 4, 0, 0, 0) == 0 && p[0] == 0, 34);
    check(protect(at, 4096, 0) == 0, 45);
    check(call(__NR_madvise, at, 4096, 4, 0, 0, 0) == 0, 46);
    check(call(__NR_write, descriptors[1], at, 1, 0, 0, 0) == -14, 47);
    check(protect(at, 4096, 3) == 0 && p[0] == 0, 48);
    check(unmap(at, 4096) == 0, 35);
    check(call(__NR_write, descriptors[1], at, 1, 0, 0, 0) == -14, 36);
    check(map(at, 4096, 3, 0x100022) == (long)at, 37);
    check(p[0] == 0, 38);
    check(unmap(base, size) == 0, 39);
    // A noncanonical address and the kernel's reserved PML4 slot must fail.
    check(map(1UL << 47, 4096, 3, 0x32) < 0, 40);
    check(map(1UL << 32, 4096, 3, 0x32) < 0, 41);
    quit(0);
#endif
}
