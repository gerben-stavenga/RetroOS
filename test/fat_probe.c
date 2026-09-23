/* Freestanding Linux i386 probe, run from a FAT root after GRUB handoff. */
static int call(int nr, int a, int b, int c) {
    int result;
    __asm__ volatile("int $0x80" : "=a"(result) : "0"(nr), "b"(a), "c"(b), "d"(c) : "memory");
    return result;
}
static void fail(char stage) {
    static const char text[] = "FAT-PROBE-FAILED\n";
    call(4, 1, (int)text, sizeof(text) - 1);
    call(4, 1, (int)&stage, 1);
    call(1, 1, 0, 0);
    for (;;) {}
}
void _start(void) {
    char data[8];
    /* Linux/VFS remains exact-case, even when the storage format is FAT. */
    if (call(5, (int)"/mIXED cASE fILENAME.txt", 0, 0) >= 0) fail('0');
    int fd = call(5, (int)"/Mixed case filename.txt", 0, 0);
    if (fd < 0 || call(3, fd, (int)data, 8) != 8) fail('1');
    call(6, fd, 0, 0);
    for (int i = 0; i < 8; ++i) if (data[i] != "FAT-DATA"[i]) fail('2');
    /* The existing Linux open shim does not implement O_CREAT yet. */
    fd = call(5, (int)"/WRITE.TXT", 2, 0);
    if (fd < 0 || call(4, fd, (int)data, 8) != 8) fail('3');
    call(6, fd, 0, 0);
    fd = call(5, (int)"/WRITE.TXT", 0, 0);
    if (fd < 0 || call(3, fd, (int)data, 8) != 8) fail('4');
    call(6, fd, 0, 0);
    for (int i = 0; i < 8; ++i) if (data[i] != "FAT-DATA"[i]) fail('5');
    /* Span multiple 64 KiB physical aperture windows, then reopen and verify. */
    static unsigned char block[4096];
    fd = call(5, (int)"/WRITE.TXT", 2, 0);
    if (fd < 0) fail('6');
    for (int chunk = 0; chunk < 32; ++chunk) {
        for (int i = 0; i < sizeof(block); ++i) block[i] = (unsigned char)(chunk + i);
        if (call(4, fd, (int)block, sizeof(block)) != sizeof(block)) fail('7');
    }
    call(6, fd, 0, 0);
    fd = call(5, (int)"/WRITE.TXT", 0, 0);
    if (fd < 0) fail('8');
    for (int chunk = 0; chunk < 32; ++chunk) {
        if (call(3, fd, (int)block, sizeof(block)) != sizeof(block)) fail('9');
        for (int i = 0; i < sizeof(block); ++i)
            if (block[i] != (unsigned char)(chunk + i)) fail('A');
    }
    call(6, fd, 0, 0);
    static const char text[] = "FAT-ROOT-RW-OK\n";
    call(4, 1, (int)text, sizeof(text) - 1);
    call(1, 0, 0, 0);
    for (;;) {}
}
