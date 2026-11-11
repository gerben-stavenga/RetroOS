#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define CHECK(ok) do { if (!(ok)) { dprintf(2, "HIGH_TIME_FAIL line=%d errno=%d\n", __LINE__, errno); _exit(1); } } while (0)
int main(void) {
    unsigned char *low = mmap((void *)0x20000000UL, 4096, PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    unsigned char *high = mmap((void *)0x500020000000UL, 12288, PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    CHECK(low == (void *)0x20000000UL && high == (void *)0x500020000000UL);
    memset(low, 0xa5, 4096);
    struct timespec *ts = (void *)high;
    ts->tv_sec = INT64_MAX; ts->tv_nsec = INT64_MAX;
    CHECK(syscall(SYS_clock_gettime, CLOCK_MONOTONIC, ts) == 0);
    CHECK(ts->tv_sec >= 0 && ts->tv_sec < 9223372036853LL && ts->tv_nsec >= 0 && ts->tv_nsec < 1000000000);
    CHECK(low[0] == 0xa5 && low[15] == 0xa5);
    /* Both fields must copy correctly across a high page boundary. */
    ts = (void *)(high+4096-8);
    CHECK(syscall(SYS_clock_getres, CLOCK_MONOTONIC, ts) == 0);
    CHECK(ts->tv_sec == 0 && ts->tv_nsec > 0 && ts->tv_nsec <= 1000000);
    struct timeval *tv = (void *)high;
    CHECK(syscall(SYS_gettimeofday, tv, high+64) == 0);
    CHECK(tv->tv_sec > 1700000000 && tv->tv_usec >= 0 && tv->tv_usec < 1000000);
    long *seconds = (void *)(high+128);
    long now = syscall(SYS_time, seconds);
    CHECK(now == *seconds && *seconds >= tv->tv_sec);
    memset(high+256, 0x5a, 32);
    CHECK(syscall(SYS_getrandom, high+256, 32, 0) == 32);
    CHECK(memcmp(high+256, "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", 32) != 0);
    CHECK(low[256] == 0xa5 && low[287] == 0xa5);
    CHECK(mprotect(high+8192, 4096, PROT_NONE) == 0);
    errno=0; CHECK(syscall(SYS_clock_gettime, CLOCK_MONOTONIC, high+8192) == -1 && errno == EFAULT);
    errno=0; CHECK(syscall(SYS_clock_getres, CLOCK_MONOTONIC, high+8192) == -1 && errno == EFAULT);
    errno=0; CHECK(syscall(SYS_gettimeofday, high+8192, 0) == -1 && errno == EFAULT);
    errno=0; CHECK(syscall(SYS_time, high+8192) == -1 && errno == EFAULT);
    errno=0; CHECK(syscall(SYS_getrandom, high+8192, 16, 0) == -1 && errno == EFAULT);
    CHECK(syscall(SYS_clock_getres, CLOCK_MONOTONIC, 0) == 0);
    CHECK(munmap(high, 12288) == 0 && munmap(low, 4096) == 0);
    fprintf(stderr, "HIGH_TIME_PASS: 64-bit time/random output, alias guard, cross-page copy and protected buffers\n");
    return 0;
}
