/* One file-content cache must agree with MAP_SHARED and external writers. */
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *file = "/home/retroos/cache-data";
    int fd = open(file, O_CREAT | O_TRUNC | O_RDWR, 0600);
    assert(fd >= 0);
    unsigned char bytes[8192];
    memset(bytes, 'A', sizeof bytes);
    assert(write(fd, bytes, sizeof bytes) == sizeof bytes);
    assert(pread(fd, bytes, sizeof bytes, 0) == sizeof bytes);
    int second = open(file, O_RDWR);
    assert(second >= 0);
    unsigned char *a = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    unsigned char *b = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, second, 0);
    assert(a != MAP_FAILED && b != MAP_FAILED);
    a[33] = 'B';
    assert(b[33] == 'B');
    assert(pread(second, bytes, 128, 0) == 128 && bytes[33] == 'B');
    assert(pwrite(second, "C", 1, 33) == 1 && a[33] == 'C' && b[33] == 'C');
    assert(msync(a, 8192, MS_SYNC) == 0);
    assert(munmap(a, 8192) == 0 && munmap(b, 8192) == 0);
    assert(close(fd) == 0 && close(second) == 0);
    fd = open(file, O_RDWR);
    assert(fd >= 0 && pread(fd, bytes, 128, 0) == 128 && bytes[33] == 'C');
    assert(ftruncate(fd, 17) == 0 && pread(fd, bytes, 128, 0) == 17);
    assert(ftruncate(fd, 8192) == 0 && pread(fd, bytes, sizeof bytes, 0) == sizeof bytes);
    for (int i = 17; i < sizeof bytes; ++i) assert(bytes[i] == 0);
    assert(close(fd) == 0);
    if (argc > 1) {
        fd = open("/home/retroos/cache-external", O_RDONLY);
        assert(fd >= 0 && pread(fd, bytes, 8, 0) == 8 && !memcmp(bytes, "original", 8));
        int ready = open("/home/retroos/cache-ready", O_CREAT | O_WRONLY, 0600);
        assert(ready >= 0 && close(ready) == 0);
        int changed = 0;
        for (int attempt = 0; attempt < 10000; ++attempt) {
            int n = pread(fd, bytes, 8, 0);
            if (n == 3 && !memcmp(bytes, "new", 3)) { changed = 1; break; }
            assert(n >= 0);
            usleep(1000);
        }
        assert(changed && close(fd) == 0);
    }
    puts("PASS: uniform file cache, shared mappings, truncate and freshness");
    return 0;
}
