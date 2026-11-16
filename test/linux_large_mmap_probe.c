/* Zero-filling a large fresh mmap must not exhaust arch's per-CPU fault
   reserve: every 2 MiB without a page table needs one new table page. */
#include <stdio.h>
#include <sys/mman.h>
int main(void) {
    static const unsigned long sizes[] = { 64ul << 20, 256ul << 20, 1024ul << 20 };
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        unsigned char *p = mmap(0, sizes[i], PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) { dprintf(2, "LARGE_MMAP_FAIL size=%lu\n", sizes[i]); return 1; }
        p[0] = 1; p[sizes[i] - 1] = 2;
        if (p[0] != 1 || p[sizes[i] - 1] != 2 || p[sizes[i] / 2] != 0) { dprintf(2, "LARGE_MMAP_BAD size=%lu\n", sizes[i]); return 1; }
        munmap(p, sizes[i]);
        dprintf(2, "LARGE_MMAP_OK size=%lu\n", sizes[i]);
    }
    dprintf(2, "LARGE_MMAP_PASS:\n");
    return 0;
}
