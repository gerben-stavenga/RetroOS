static void sys_write(int fd, const char *buf, int len) {
    __asm__ volatile("int $0x80" :: "a"(4), "b"(fd), "c"(buf), "d"(len) : "memory");
}
static void sys_exit(int code) {
    __asm__ volatile("int $0x80" :: "a"(1), "b"(code));
}
void _start(void) {
    const char msg[] = "Hello from an interpreted 32-bit Linux ELF!\n";
    sys_write(1, msg, sizeof(msg) - 1);
    sys_exit(0);
}
