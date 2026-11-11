/* One file-content cache must agree with MAP_SHARED and external writers. */
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <unistd.h>

static void append_probe(void) {
    const char *path = "/home/retroos/cache-append";
    int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    assert(fd >= 0 && write(fd, "abc", 3) == 3);
    int app = open(path, O_RDWR | O_APPEND);
    assert(app >= 0 && (fcntl(app, F_GETFL) & O_APPEND));
    // Another description grows the file after the append handle was opened.
    assert(write(fd, "++", 2) == 2);
    assert(lseek(app, 0, SEEK_SET) == 0 && write(app, "Z", 1) == 1);
    assert(lseek(app, 0, SEEK_CUR) == 6);
    int copy = dup(app);
    assert(copy >= 0 && fcntl(copy, F_SETFL, O_RDWR) == 0);
    assert(!(fcntl(app, F_GETFL) & O_APPEND));
    assert(lseek(app, 0, SEEK_SET) == 0 && write(app, "X", 1) == 1);
    assert(fcntl(copy, F_SETFL, O_RDWR | O_APPEND) == 0);
    assert(fcntl(app, F_GETFL) & O_APPEND);
    struct iovec parts[] = {{"A", 1}, {"B", 1}};
    assert(lseek(app, 0, SEEK_SET) == 0 && writev(app, parts, 2) == 2);
    pid_t child = fork();
    assert(child >= 0);
    if (!child) _exit(write(copy, "!", 1) == 1 ? 0 : 1);
    int status = -1;
    assert(waitpid(child, &status, 0) == child && status == 0);
    char bytes[16] = {0};
    assert(pread(fd, bytes, sizeof(bytes), 0) == 9 && !memcmp(bytes, "Xbc++ZAB!", 9));
    assert(close(copy) == 0 && close(app) == 0 && close(fd) == 0);
    assert(unlink(path) == 0);
}

int main(int argc, char **argv) {
    append_probe();
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
    /* Eager private mappings allocate fresh frames in bulk. Replacing a
       dirty mapping must reload file bytes and clear the partial EOF page. */
    fd = open("/home/retroos/cache-private", O_CREAT | O_TRUNC | O_RDWR, 0600);
    assert(fd >= 0);
    memset(bytes, 'D', sizeof bytes);
    assert(write(fd, bytes, 5003) == 5003);
    a = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    assert(a != MAP_FAILED);
    for (int i = 0; i < 8192; ++i) assert(a[i] == (i < 5003 ? 'D' : 0));
    memset(a, 'X', 8192);
    assert(mmap(a, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, 0) == a);
    for (int i = 0; i < 8192; ++i) assert(a[i] == (i < 5003 ? 'D' : 0));
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) { a[0] = 'Y'; _exit(a[0] != 'Y'); }
    int status = -1;
    assert(waitpid(child, &status, 0) == child && status == 0 && a[0] == 'D');
    assert(pread(fd, bytes, 1, 0) == 1 && bytes[0] == 'D');
    assert(munmap(a, 8192) == 0 && close(fd) == 0);
    /* A large streaming read must still see unflushed MAP_SHARED bytes. */
    const size_t stream_size = 256 * 1024;
    unsigned char *stream = malloc(stream_size);
    assert(stream);
    memset(stream, 'D', stream_size);
    fd = open("/home/retroos/cache-stream", O_CREAT | O_TRUNC | O_RDWR, 0600);
    assert(fd >= 0 && write(fd, stream, stream_size) == (ssize_t)stream_size && fsync(fd) == 0);
    a = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 128 * 1024);
    assert(a != MAP_FAILED);
    a[0] = 'Z';
    assert(pread(fd, stream, stream_size, 0) == (ssize_t)stream_size);
    for (size_t i = 0; i < stream_size; ++i) assert(stream[i] == (i == 128 * 1024 ? 'Z' : 'D'));
    /* Reused read scratch must handle growth, shrinkage, short reads, and
       pinned shared-page changes without leaking bytes from an earlier read. */
    assert(lseek(fd, 0, SEEK_SET) == 0);
    const size_t requests[] = {17, 65536, 8192, 200000};
    size_t consumed = 0, iteration = 0;
    while (consumed < stream_size) {
        size_t requested = requests[iteration++ % 4];
        ssize_t n = read(fd, stream, requested);
        assert(n > 0 && (size_t)n <= requested && (size_t)n <= stream_size - consumed);
        for (ssize_t i = 0; i < n; ++i)
            assert(stream[i] == (consumed + i == 128 * 1024 ? 'Z' : 'D'));
        consumed += n;
    }
    stream[0] = 'Q';
    assert(read(fd, stream, 200000) == 0 && stream[0] == 'Q');
    assert(munmap(a, 4096) == 0 && close(fd) == 0);
    free(stream);
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
