/* No libc: exercise both msghdr ABIs against a real UDP peer. */
typedef unsigned long word;
struct vector { void *base; word length; };
struct message {
    void *name; unsigned int namelen;
    struct vector *vectors; word count;
    void *control; word controllen; unsigned int flags;
};
#ifdef __x86_64__
#define READ 0
#define WRITE 1
#define EXIT 60
#define WRITEV 20
#define OPEN 2
#define CLOSE 3
#define FLOCK 73
#define FSYNC 74
#define FCHMOD 91
#define READLINK 89
#define UNLINKAT 263
static long call(word nr, word a, word b, word c) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return r;
}
static long socket_call(word op, word a, word b, word c) {
    return call(op == 1 ? 41 : op == 3 ? 42 : op == 16 ? 46 : 47, a, b, c);
}
#else
#define READ 3
#define WRITE 4
#define EXIT 1
#define WRITEV 146
#define OPEN 5
#define CLOSE 6
#define FLOCK 143
#define FSYNC 118
#define FCHMOD 94
#define READLINK 85
#define UNLINKAT 301
static long call(word nr, word a, word b, word c) {
    long r;
    __asm__ volatile("int $0x80" : "=a"(r) : "a"(nr), "b"(a), "c"(b), "d"(c) : "memory");
    return r;
}
static long socket_call(word op, word a, word b, word c) {
    static unsigned int receives;
    if (op == 17 && ++receives == 2) return call(372, a, b, c);
    word args[] = {a,b,c};
    return call(102, op, (word)args, 0);
}
#endif
static void check(int ok, int code) {
    if (!ok) { call(EXIT, code, 0, 0); for (;;) {} }
}
void __attribute__((force_align_arg_pointer)) _start(void) {
    char executable[16] = {0};
    check(call(READLINK, (word)"/proc/self/exe", (word)executable, sizeof(executable)) == 6, 30);
    check(executable[0]=='/' && executable[1]=='p' && executable[5]=='e', 31);
    long one = call(OPEN, (word)"/home/retroos/LOCK", 66, 0600);
    long two = call(OPEN, (word)"/home/retroos/LOCK", 2, 0);
    check(one >= 0 && two >= 0, 32);
    check(call(FCHMOD, one, 0600, 0) == 0, 33);
    check(call(FSYNC, one, 0, 0) == 0, 34);
    check(call(FLOCK, one, 2, 0) == 0, 35);
    check(call(FLOCK, two, 2|4, 0) == -11, 36);
    check(call(CLOSE, one, 0, 0) == 0, 37);
    check(call(FLOCK, two, 2|4, 0) == 0, 38);
    check(call(CLOSE, two, 0, 0) == 0, 39);
    check(call(UNLINKAT, (word)-100, (word)"/home/retroos/LOCK", 0) == 0, 40);
    unsigned char address[16] = {2,0,PORT >> 8,PORT & 255,10,0,2,2};
    long fd = socket_call(1, 2, 2, 0);
    check(fd >= 0, 10);
    check(socket_call(3, fd, (word)address, 16) == 0, 11);
    struct vector send[] = {{"he",2},{"llo",3}};
    check(call(WRITEV, fd, (word)send, 2) == 5, 12);
    unsigned char peer[16] = {0}, a[2] = {0}, b[4] = {0}, control[16] = {0};
    struct vector vectors[] = {{a,2},{b,2}};
    struct message m = {peer,16,vectors,2,control,16,0};
    check(socket_call(17, fd, (word)&m, 2 | 0x20) == 6, 13);
    check(m.flags == 0x20 && m.namelen == 16 && m.controllen == 0, 14);
    check(a[0]=='a' && a[1]=='b' && b[0]=='c' && b[1]=='d', 15);
    check(peer[0] == 2 && peer[2] == (PORT >> 8) && peer[3] == (PORT & 255), 16);
    check(socket_call(17, fd, (word)&m, 0) == 4 && m.flags == 0x20, 17);
    check(a[0]=='a' && a[1]=='b' && b[0]=='c' && b[1]=='d', 18);
    vectors[1].length = 4;
    check(socket_call(17, fd, (word)&m, 0) == 6 && m.flags == 0, 19);
    check(a[0]=='g' && a[1]=='h' && b[0]=='i' && b[3]=='l', 20);
    // Large stream writes may complete partially; scratch-buffer capacity is
    // not a message-size limit. Exercise one vector and two vectors spanning the limit.
    static char payload[160000];
    for (word i=0; i<sizeof payload; i++) payload[i] = 'a' + i % 26;
    struct vector large[] = {{payload, 65536}, {payload+65536, sizeof payload-65536}};
    struct message output = {0,0,large,2,0,0,0};
    check(call(WRITEV, fd, (word)large, 2) == -90, 41);
    check(socket_call(16, fd, (word)&output, 0) == -90, 42);
    call(CLOSE, fd, 0, 0);
    address[2] = TCP_PORT >> 8; address[3] = TCP_PORT & 255;
    fd = socket_call(1, 2, 1, 0); check(fd >= 0, 43);
    check(socket_call(3, fd, (word)address, 16) == 0, 44);
    for (int method=0; method<2; method++) {
        word done=0;
        while (done < sizeof payload) {
            word left = sizeof payload-done;
            word first = method ? left : (left > 40000 ? 40000 : left);
            large[0].base=payload+done; large[0].length=first;
            large[1].base=payload+done+first; large[1].length=left-first;
            long sent = method ? socket_call(16, fd, (word)&output, 0)
                               : call(WRITEV, fd, (word)large, 2);
            check(sent > 0 && (word)sent <= left, 45+method);
            done += sent;
        }
    }
    char ack = 0;
    check(call(READ, fd, (word)&ack, 1) == 1 && ack == 'Y', 47);
    call(CLOSE, fd, 0, 0);
    static const char pass[] = "RECVMSG PASS\n";
    call(WRITE, 2, (word)pass, sizeof(pass)-1);
    call(EXIT, 0, 0, 0);
    for (;;) {}
}
