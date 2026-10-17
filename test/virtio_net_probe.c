/* Bare Linux socket syscalls: no libc or hosted network backend. */
typedef unsigned long u32;
#if defined(__x86_64__)
static int direct(int nr, u32 a, u32 b, u32 c, u32 d, u32 e, u32 f) {
    long result;
    register u32 r10 __asm__("r10") = d;
    register u32 r8 __asm__("r8") = e;
    register u32 r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "=a"(result) : "a"(nr), "D"(a), "S"(b), "d"(c),
                     "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return result;
}
static int call(int number, u32 a, u32 b, u32 c) {
    int nr;
    switch (number) {
        case 1: nr = 60; break;
        case 3: nr = 0; break;
        case 4: nr = 1; break;
        case 5: nr = 2; break;
        case 6: nr = 3; break;
        case 55: nr = 72; break;
        case 168: nr = 7; break;
        default: return -38;
    }
    return direct(nr, a, b, c, 0, 0, 0);
}
static int socketcall(int op, u32 a, u32 b, u32 c, u32 d, u32 e, u32 f) {
    int nr;
    switch (op) {
        case 1: nr = 41; break;
        case 2: nr = 49; break;
        case 3: nr = 42; break;
        case 4: nr = 50; break;
        case 5: nr = 43; break;
        case 7: nr = 52; break;
        case 9: case 11: nr = 44; break;
        case 10: case 12: nr = 45; break;
        case 15: nr = 55; break;
        default: return -38;
    }
    return direct(nr, a, b, c, d, e, f);
}
#else
static int call(int number, u32 a, u32 b, u32 c) {
    int result;
    __asm__ volatile("int $0x80" : "=a"(result) : "a"(number), "b"(a), "c"(b), "d"(c) : "memory");
    return result;
}
static int socketcall(int op, u32 a, u32 b, u32 c, u32 d, u32 e, u32 f) {
    u32 args[6] = {a, b, c, d, e, f};
    return call(102, op, (u32)args, 0);
}
#endif
static void finish(int code) { call(1, code, 0, 0); for (;;) {} }
static void check(int ok, int code) { if (!ok) finish(code); }
static void address(unsigned char *a, int port) {
    for (int i = 0; i < 16; ++i) a[i] = 0;
    a[0] = 2; a[2] = port >> 8; a[3] = port;
    a[4] = 10; a[5] = 0; a[6] = 2; a[7] = 2;
}
static unsigned char data[128 * 1024];
static unsigned char reply[128 * 1024];
/* ELF entry has no caller-pushed return address; align GCC's local frame. */
void __attribute__((force_align_arg_pointer)) _start(void) {
    int fd = socketcall(1, 2, 1, 0, 0, 0, 0);
#ifdef NO_NIC
    check(fd == -38, 2);
    finish(0);
#else
    check(fd >= 0, 3);
    int resolver = call(5, (u32)"/etc/resolv.conf", 0, 0);
    check(resolver >= 0, 44);
    int resolver_size = call(3, resolver, (u32)reply, 64);
    static const char dns[] = "nameserver 10.0.2.3\n";
    check(resolver_size == sizeof(dns) - 1, 45);
    for (int i = 0; i < resolver_size; ++i) check(reply[i] == dns[i], 46);
    call(6, resolver, 0, 0);
    unsigned char sa[16], peer[16];
    address(sa, TCP_PORT);
    check(socketcall(3, fd, (u32)sa, 16, 0, 0, 0) == 0, 4);
    u32 size = 16;
    check(socketcall(7, fd, (u32)peer, (u32)&size, 0, 0, 0) == 0, 5);
    check(size == 16 && peer[4] == 10 && peer[7] == 2 && peer[2] == sa[2] && peer[3] == sa[3], 6);
    for (u32 i = 0; i < sizeof(data); ++i) data[i] = (i * 37 + (i >> 8)) & 255;
    for (u32 sent = 0; sent < sizeof(data);) {
        int n = call(4, fd, (u32)(data + sent), sizeof(data) - sent);
        check(n > 0, 7); sent += n;
    }
    for (u32 received = 0; received < sizeof(reply);) {
        int n = call(3, fd, (u32)(reply + received), sizeof(reply) - received);
        check(n > 0, 8); received += n;
    }
    for (u32 i = 0; i < sizeof(data); ++i) check(reply[i] == (unsigned char)(data[i] ^ 0x5a), 9);
    check(call(3, fd, (u32)reply, 1) == 0, 10); /* peer EOF */
    check(call(6, fd, 0, 0) == 0, 11);

    fd = socketcall(1, 2, 2, 0, 0, 0, 0);
    check(fd >= 0, 12);
    address(sa, UDP_PORT);
    check(socketcall(11, fd, (u32)data, 257, 0, (u32)sa, 16) == 257, 13);
    size = 16;
    check(socketcall(12, fd, (u32)reply, 257, 2, (u32)peer, (u32)&size) == 257, 14); /* PEEK */
    check(size == 16 && peer[2] == sa[2] && peer[3] == sa[3], 15);
    check(socketcall(10, fd, (u32)reply, 257, 0, 0, 0) == 257, 16);
    for (int i = 0; i < 257; ++i) check(data[i] == reply[i], 17);
    check(socketcall(10, fd, (u32)reply, 257, 0x40, 0, 0) == -11, 18); /* DONTWAIT */
    check(call(55, fd, 4, 0x800) == 0, 19); /* F_SETFL O_NONBLOCK */
    check((call(55, fd, 3, 0) & 0x800) != 0, 20);
    check(call(3, fd, (u32)reply, 1) == -11, 21);
    check(socketcall(3, fd, (u32)sa, 16, 0, 0, 0) == 0, 22); /* connected UDP */
    check(socketcall(9, fd, (u32)data, 31, 0, 0, 0) == 31, 23);
    struct { int fd; short events, revents; } pollfd = {fd, 1, 0};
    check(call(168, (u32)&pollfd, 1, 10000) == 1 && pollfd.revents == 1, 24);
    check(socketcall(10, fd, (u32)reply, 31, 0, 0, 0) == 31, 25);
    pollfd.revents = -1;
    check(call(168, (u32)&pollfd, 1, 20) == 0 && pollfd.revents == 0, 31);
    check(call(6, fd, 0, 0) == 0, 26);

    /* Nonblocking TCP connect and readiness. */
    fd = socketcall(1, 2, 1 | 0x800, 0, 0, 0, 0);
    address(sa, TCP_PORT);
    check(fd >= 0, 27);
    check(socketcall(3, fd, (u32)sa, 16, 0, 0, 0) == -115, 28);
    pollfd.fd = fd; pollfd.events = 4; pollfd.revents = 0;
    check(call(168, (u32)&pollfd, 1, 10000) == 1 && pollfd.revents == 4, 29);
    int error = -1;
    size = 4;
    check(socketcall(15, fd, 1, 4, (u32)&error, (u32)&size, 0) == 0 && error == 0 && size == 4, 32);
    check(call(6, fd, 0, 0) == 0, 30);

    /* Host-forwarded incoming connections and listener replacement on accept. */
    int listener = socketcall(1, 2, 1, 0, 0, 0, 0);
    address(sa, 23456);
    sa[4] = sa[5] = sa[6] = sa[7] = 0;
    check(listener >= 0, 33);
    check(socketcall(2, listener, (u32)sa, 16, 0, 0, 0) == 0, 34);
    check(socketcall(4, listener, 4, 0, 0, 0, 0) == 0, 35);
    for (int connection = 0; connection < 2; ++connection) {
        size = 16;
        fd = socketcall(5, listener, (u32)peer, (u32)&size, 0, 0, 0);
        check(fd >= 0 && peer[0] == 2 && size == 16, 36);
        int duplicate = call(55, fd, 0, 0);
        check(duplicate >= 0 && duplicate != fd, 37);
        check(call(6, fd, 0, 0) == 0, 38);
        fd = duplicate;
        int total = 0;
        while (total < 4) {
            int n = call(3, fd, (u32)(reply + total), 4 - total);
            check(n > 0, 39); total += n;
        }
        check(reply[0] == 'P' && reply[1] == 'I' && reply[2] == 'N' && reply[3] == 'G', 40);
        check(call(4, fd, (u32)"PONG", 4) == 4, 41);
        check(call(6, fd, 0, 0) == 0, 42);
    }
    check(call(6, listener, 0, 0) == 0, 43);
    fd = socketcall(1, 2, 1 | 0x800, 0, 0, 0, 0);
    address(sa, REFUSED_PORT);
    check(fd >= 0 && socketcall(3, fd, (u32)sa, 16, 0, 0, 0) == -115, 47);
    pollfd.fd = fd; pollfd.events = 4; pollfd.revents = 0;
    check(call(168, (u32)&pollfd, 1, 10000) == 1 && (pollfd.revents & 8), 48);
    error = -1; size = 4;
    check(socketcall(15, fd, 1, 4, (u32)&error, (u32)&size, 0) == 0 && error == 111, 49);
    call(6, fd, 0, 0);
    finish(0);
#endif
}
