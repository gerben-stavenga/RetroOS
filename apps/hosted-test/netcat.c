// Minimal nostdlib TCP client for the hosted socket-syscall smoke test.
// socket()+connect() to 127.0.0.1:PORT, send a line, print the reply.
// Uses the i386 socketcall(2) multiplexer directly (no libc).
//
//   gcc -m32 -static -nostdlib -no-pie -fno-pic -O2 -e _start -DPORT=NNNN \
//       -o netcat.elf apps/hosted-test/netcat.c

static int socketcall(int call, unsigned long *args) {
    int ret;
    __asm__ volatile("int $0x80" : "=a"(ret) : "a"(102), "b"(call), "c"(args) : "memory");
    return ret;
}
static int sys_write(int fd, const char *buf, int len) {
    int ret;
    __asm__ volatile("int $0x80" : "=a"(ret) : "a"(4), "b"(fd), "c"(buf), "d"(len) : "memory");
    return ret;
}
static void sys_exit(int code) {
    __asm__ volatile("int $0x80" :: "a"(1), "b"(code));
    __builtin_unreachable();
}

#define SYS_SOCKET  1
#define SYS_CONNECT 3
#define SYS_SEND    9
#define SYS_RECV    10

void _start(void) {
    unsigned long a[6];

    // socket(AF_INET=2, SOCK_STREAM=1, 0)
    a[0] = 2; a[1] = 1; a[2] = 0;
    int fd = socketcall(SYS_SOCKET, a);
    if (fd < 0) { sys_write(1, "socket-fail\n", 12); sys_exit(1); }

    // sockaddr_in { AF_INET, htons(PORT), 127.0.0.1 }
    unsigned char sa[16] = {0};
    sa[0] = 2; sa[1] = 0;                  // sin_family = AF_INET (little-endian)
    sa[2] = (PORT >> 8) & 0xff; sa[3] = PORT & 0xff; // sin_port (big-endian)
    sa[4] = 127; sa[5] = 0; sa[6] = 0; sa[7] = 1;    // 127.0.0.1
    a[0] = (unsigned long)fd; a[1] = (unsigned long)sa; a[2] = 16;
    if (socketcall(SYS_CONNECT, a) < 0) { sys_write(1, "connect-fail\n", 13); sys_exit(1); }

    // send a request line
    static const char req[] = "PING";
    a[0] = (unsigned long)fd; a[1] = (unsigned long)req; a[2] = sizeof(req) - 1; a[3] = 0;
    socketcall(SYS_SEND, a);

    // recv the reply and echo it to stdout
    char buf[256];
    a[0] = (unsigned long)fd; a[1] = (unsigned long)buf; a[2] = sizeof(buf); a[3] = 0;
    int n = socketcall(SYS_RECV, a);
    if (n > 0) sys_write(1, buf, n);
    sys_exit(0);
}
