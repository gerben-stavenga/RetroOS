/* A bare-ELF guest that is still running when the event loop's first OSD
 * composite comes due, which `hello.c` is not: it writes and exits inside a
 * single clock tick, so the composite path never runs and never reached
 * `sound_view` -> `platform::get` on the unprobed bare-ELF path. That panic
 * shipped and only appeared on CI, where the KVM engine's slower startup
 * pushed the same two syscalls across a tick boundary.
 *
 * The burn loop is sized to exceed a tick on the FAST engine (KVM, ~native)
 * while staying well inside the smoke timeout on the slow one (TCG is ~180x
 * slower here), so both engines exercise the composite.
 */
static void sys_write(int fd, const char *buf, int len) {
    __asm__ volatile("int $0x80" :: "a"(4), "b"(fd), "c"(buf), "d"(len) : "memory");
}
static void sys_exit(int code) {
    __asm__ volatile("int $0x80" :: "a"(1), "b"(code));
}
void _start(void) {
    const char msg[] = "Hello from an interpreted 32-bit Linux ELF!\n";
    volatile unsigned long i;
    for (i = 0; i < 8000000UL; i++) { }
    sys_write(1, msg, sizeof(msg) - 1);
    sys_exit(0);
}
