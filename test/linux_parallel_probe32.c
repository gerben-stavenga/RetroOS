/* i386 fork/COW and inherited segment TLS must survive worker CPU handoffs. */
typedef unsigned word;
static long call(word nr, word a, word b, word c) {
    long result;
    __asm__ volatile("int $0x80" : "=a"(result) : "a"(nr), "b"(a), "c"(b), "d"(c) : "memory", "cc");
    return result;
}
static void quit(word code) { call(1, code, 0, 0); for (;;) {} }
static void check(int ok) { if (!ok) quit(99); }
static volatile unsigned tls_value = 0x1234;
static unsigned tls_read(void) { unsigned value; __asm__ volatile("mov %%fs:0,%0" : "=r"(value)); return value; }
void _start(void) {
    struct { word entry, base, limit, flags; } descriptor = {-1U, (word)&tls_value, 4095, 0x41};
    check(call(243, (word)&descriptor, 0, 0) == 0);
    unsigned short selector = (descriptor.entry << 3) | 3;
    __asm__ volatile("mov %0,%%fs" :: "r"(selector));
    check(tls_read() == 0x1234);
    for (word child = 0; child < 16; ++child) {
        long pid = call(2, 0, 0, 0);
        check(pid >= 0);
        if (!pid) {
            check(tls_read() == 0x1234);
            tls_value = 100 + child;
            unsigned a, b, c, d;
            __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1));
            unsigned cpu = b >> 24, reported = 999;
            for (volatile unsigned n = 0; n < 100000; ++n) check(tls_read() == 100 + child);
            check(call(318, (word)&reported, 0, 0) == 0 && reported == cpu);
            quit(cpu + 1);
        }
    }
    unsigned mask = 0;
    for (unsigned child = 0; child < 16; ++child) {
        int status = -1;
        check(call(7, -1U, (word)&status, 0) > 0);
        check((status & 255) == 0 && (status >> 8) > 0 && (status >> 8) <= 32);
        mask |= 1U << ((status >> 8) - 1);
    }
    check(tls_value == 0x1234 && tls_read() == 0x1234);
    unsigned count = 0;
    while (mask) { count += mask & 1; mask >>= 1; }
    check(count >= EXPECTED);
    static const char message[] = "PARALLEL_PROCESS_PASS i386 tls=1 cow=1 children=16\n";
    call(4, 2, (word)message, sizeof(message)-1);
    quit(0);
}
