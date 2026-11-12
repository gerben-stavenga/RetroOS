/* File cache frames must be independent of kernel virtual addresses. */
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static unsigned long long available(void) {
    struct sysinfo info; assert(sysinfo(&info) == 0);
    return (unsigned long long)info.freeram * info.mem_unit;
}
static unsigned long long milliseconds(void) {
    struct timespec ts; assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return (unsigned long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
int main(int argc, char **argv) {
    size_t size = argc > 1 ? strtoull(argv[1], 0, 0) : 16 * 1024 * 1024;
    int fd = open("/data", O_RDONLY); assert(fd >= 0);
    unsigned long long started = milliseconds();
    unsigned char *a = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);
    unsigned long long cold_ms = milliseconds() - started;
    assert(a != MAP_FAILED && a[0] == 'A' && a[size - 1] == 'Z');
    unsigned long long before = available();
    started = milliseconds();
    unsigned char *b = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);
    unsigned long long alias_ms = milliseconds() - started;
    assert(b != MAP_FAILED && b[0] == 'A' && b[size - 1] == 'Z');
    unsigned long long after = available();
    /* An alias may allocate page tables and bookkeeping, never another file. */
    assert(after + size / 16 > before);
    assert(mprotect(b, 4096, PROT_READ | PROT_WRITE) == 0);
    b[0] = 'B'; assert(a[0] == 'A' && b[0] == 'B');
    pid_t child = fork(); assert(child >= 0);
    if (!child) { b[0] = 'C'; _exit(b[0] != 'C' || a[0] != 'A'); }
    int status; assert(waitpid(child, &status, 0) == child && status == 0);
    assert(a[0] == 'A' && b[0] == 'B');
    unsigned char byte; assert(pread(fd, &byte, 1, 0) == 1 && byte == 'A');
    assert(munmap(a, size) == 0 && munmap(b, size) == 0);
    unsigned long long warm = available();
    a = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);
    assert(a != MAP_FAILED && a[0] == 'A' && a[size - 1] == 'Z');
    assert(available() + size / 16 > warm);
    assert(munmap(a, size) == 0 && close(fd) == 0);
    if (size <= 16 * 1024 * 1024) {
        /* Cold file frames must yield to anonymous process memory. */
        size_t pressure_size = 200 * 1024 * 1024;
        volatile unsigned char *pressure = mmap(0, pressure_size, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        assert(pressure != MAP_FAILED);
        for (size_t i = 0; i < pressure_size; i += 4096) pressure[i] = (unsigned char)(i / 4096);
        for (size_t i = 0; i < pressure_size; i += 4096) assert(pressure[i] == (unsigned char)(i / 4096));
        assert(munmap((void *)pressure, pressure_size) == 0);
    }
    fprintf(stderr, "FRAME_CACHE_PASS size=%zu alias_overhead=%lld cold_ms=%llu alias_ms=%llu\n", size, (long long)(before - after), cold_ms, alias_ms);
    return 0;
}
