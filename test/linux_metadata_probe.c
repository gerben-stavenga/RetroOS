/* Metadata-heavy walks, with the log traffic of an interactive application. */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static unsigned long long now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) abort();
    return (unsigned long long)t.tv_sec * 1000000000 + t.tv_nsec;
}

int main(int argc, char **argv) {
    struct stat st;
    char path[160];
    const char *base = argc > 1 ? argv[1] : "/home/retroos";
    snprintf(path, sizeof(path), "%s/activity", base);
    int log = open(path, O_RDWR);
    if (log < 0) return 1;
    for (int phase = 0; phase < 3; phase++) {
        unsigned long long start = now();
        int count = phase == 2 ? 200 : 2000;
        for (int i = 0; i < count; i++) {
            if (phase == 0)
                snprintf(path, sizeof(path), "%s/flat/f%04d", base, i);
            else
                snprintf(path, sizeof(path), "%s/tree/d%02d/f%04d", base, i % 50, i);
            if (phase == 2 && pwrite(log, ".", 1, i) != 1) return 2;
            if (stat(path, &st) || st.st_size != 1 || st.st_uid != getuid()) return 3;
        }
        dprintf(2, "METADATA_NS %s %llu\n", phase == 0 ? "flat" : phase == 1 ? "tree" : "logged",
               now() - start);
    }
    if (fsync(log) || close(log)) return 4;
    snprintf(path, sizeof(path), "%s/growing", base);
    int growing = open(path, O_RDWR);
    if (growing < 0) return 5;
    static char buffer[65536];
    unsigned long long start = now();
    for (int i = 0; i < 32; i++)
        if (write(growing, buffer, sizeof(buffer)) != sizeof(buffer)) return 6;
    if (fsync(growing) || close(growing)) return 7;
    dprintf(2, "METADATA_NS allocate %llu\n", now() - start);
    dprintf(2, "METADATA_PASS\n");
    return 0;
}
