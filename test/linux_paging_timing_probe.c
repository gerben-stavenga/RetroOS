/* Isolate page-table work from application startup and filesystem traffic. */
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

static uint64_t now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) _exit(90);
    return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

int main(void) {
    const size_t bytes = 64 * 1024 * 1024;
    uint64_t start = now();
    volatile unsigned char *p = mmap(0, bytes, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 1;
    uint64_t mapped = now();
    for (size_t i = 0; i < bytes; i += 4096) p[i] = (i / 4096) % 251 + 1;
    uint64_t touched = now();
    for (size_t i = 0; i < bytes; i += 4096)
        if (p[i] != (i / 4096) % 251 + 1) return 2;
    uint64_t checked = now();
    if (munmap((void *)p, bytes)) return 3;
    uint64_t unmapped = now();
    dprintf(2, "PAGING_NS map=%llu fault=%llu verify=%llu unmap=%llu pages=%zu\n",
            (unsigned long long)(mapped - start), (unsigned long long)(touched - mapped),
            (unsigned long long)(checked - touched), (unsigned long long)(unmapped - checked), bytes / 4096);
    dprintf(2, "PAGING_TIMING_PASS\n");
    return 0;
}
