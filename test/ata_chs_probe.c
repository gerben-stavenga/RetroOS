/* Linux i386 program for the 86Box CHS disk integration test. */
static unsigned char buffer[8192];
static int call(int nr, int a, int b, int c) {
    int result;
    __asm__ volatile("int $0x80" : "=a"(result) : "0"(nr), "b"(a), "c"(b), "d"(c) : "memory");
    return result;
}
static void finish(int ok) {
    const char *text = ok ? "CHS-RW-OK\n" : "CHS-RW-FAILED\n";
    call(4, 1, (int)text, ok ? 10 : 14);
    call(1, !ok, 0, 0);
    for (;;) {}
}
void _start(void) {
    for (int pass = 0; pass < 2; ++pass) {
        int fd = call(5, (int)"/PROBE.DAT", 2, 0);
        if (fd < 0) finish(0);
        for (int offset = 0; offset < 256 * 1024; offset += sizeof(buffer)) {
            if (call(3, fd, (int)buffer, sizeof(buffer)) != sizeof(buffer)) finish(0);
            for (int i = 0; i < sizeof(buffer); ++i) {
                unsigned char expected = (unsigned char)((offset + i) * 37 + ((offset + i) >> 9));
                if (buffer[i] != (unsigned char)(expected ^ (pass ? 0xa5 : 0))) finish(0);
                buffer[i] ^= 0xa5;
            }
            if (!pass) {
                if (call(19, fd, offset, 0) != offset) finish(0);
                if (call(4, fd, (int)buffer, sizeof(buffer)) != sizeof(buffer)) finish(0);
            }
        }
        if (call(6, fd, 0, 0) != 0) finish(0);
    }
    finish(1);
}
