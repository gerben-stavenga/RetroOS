/* A DOS launcher remains ready while a Linux terminal yields and waits. */
#include <asm/unistd.h>
typedef unsigned long word;
static long call(word n, word a, word b, word c, word d) {
    register word r10 __asm__("r10") = d;
    long result;
    __asm__ volatile("syscall" : "=a"(result)
        : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10)
        : "rcx", "r11", "memory");
    return result;
}
static void finish(int code) {
    call(__NR_exit, code, 0, 0, 0);
    for (;;) {}
}
static void check(int ok) { if (!ok) finish(1); }
static void save(const char *path, const char *text, word length) {
    long fd = call(__NR_open, (word)path, 577, 0600, 0);
    check(fd >= 0);
    check(call(__NR_write, fd, (word)text, length, 0) == (long)length);
    check(call(__NR_close, fd, 0, 0, 0) == 0);
}
void _start(void) {
    static const char heading[] = "\033[2J\033[H\033[42mLinux terminal focus\r\n";
    static const char row[] = "                                                                \r\n";
    call(__NR_write, 1, (word)heading, sizeof heading - 1, 0);
    for (int i = 0; i < 15; i++) call(__NR_write, 1, (word)row, sizeof row - 1, 0);
    check(call(__NR_sched_yield, 0, 0, 0, 0) == 0);
    // Like a daemon/helper, fd 0 is an IPC pipe. Terminal input still belongs
    // to the controlling tty, retained here through another descriptor.
    check(call(__NR_dup2, 0, 31, 0, 0) == 31);
    int pipes[2];
    check(call(__NR_pipe, (word)pipes, 0, 0, 0) == 0);
    check(call(__NR_dup2, pipes[0], 0, 0, 0) == 0);
    long child = call(__NR_fork, 0, 0, 0, 0);
    check(child >= 0);
    if (!child) {
        save("/home/retroos/ready", "ready\n", 6);
        char input[8];
        long n = call(__NR_read, 31, (word)input, sizeof input, 0);
        finish(n == 2 && input[0] == 'k' && input[1] == '\n' ? 17 : 2);
    }
    int status = -1;
    check(call(__NR_wait4, child, (word)&status, 0, 0) == child);
    check(status == (17 << 8));
    save("/home/retroos/result", "FOCUS PASS\n", 11);
    finish(0);
}
