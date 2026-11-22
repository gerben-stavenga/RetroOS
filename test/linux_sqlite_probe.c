/* Use the host's SQLite runtime without requiring its development package. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
typedef struct sqlite3 sqlite3;
extern int sqlite3_open(const char *, sqlite3 **);
extern int sqlite3_close(sqlite3 *);
extern int sqlite3_exec(sqlite3 *, const char *, int (*)(void *, int, char **, char **), void *, char **);
extern const char *sqlite3_errmsg(sqlite3 *);

static void sql(sqlite3 *db, const char *query) {
    if (sqlite3_exec(db, query, 0, 0, 0)) {
        fprintf(stderr, "SQLite: %s\n", sqlite3_errmsg(db));
        exit(1);
    }
}
static int row(void *output, int n, char **values, char **names) {
    (void)names;
    if (n == 1 && values[0]) *(int *)output = atoi(values[0]);
    return 0;
}
static void count(sqlite3 *db, int expected) {
    int actual = -1;
    if (sqlite3_exec(db, "SELECT count(*) FROM entries", row, &actual, 0) || actual != expected) {
        fprintf(stderr, "SQLite count: wanted %d, got %d: %s\n", expected, actual, sqlite3_errmsg(db));
        exit(2);
    }
}

/* Recent SQLite tries O_TMPFILE for its subjournal. A successful open must
 * return a writable file. EOPNOTSUPP lets SQLite use a named temporary file. */
static void check_tempfile(void) {
    int fd = open("/home/retroos", O_TMPFILE | O_RDWR | O_EXCL, 0600);
    if (fd < 0) {
        if (errno == EOPNOTSUPP) return;
        perror("open O_TMPFILE");
    } else {
        struct stat st;
        if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && write(fd, "x", 1) == 1
                && close(fd) == 0) return;
        fputs("O_TMPFILE did not return a writable regular file\n", stderr);
    }
    exit(7);
}

static void check_unlinked_journal(void) {
    static unsigned char input[61504], output[sizeof(input)];
    char path[] = "/tmp/retroos-sqlite-XXXXXX";
    int writer = mkstemp(path);
    int reader = writer < 0 ? -1 : open(path, O_RDWR);
    for (size_t i = 0; i < sizeof(input); ++i) input[i] = i % 251;
    if (reader < 0 || unlink(path) < 0 ||
            pwrite(writer, input, sizeof(input), 0) != sizeof(input)) {
        perror("write to unlinked SQLite journal");
        exit(8);
    }
    int replacement = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (replacement < 0 || write(replacement, "new", 3) != 3 ||
            close(writer) < 0 || pread(reader, output, sizeof(output), 0) != sizeof(output) ||
            memcmp(input, output, sizeof(input)) != 0 ||
            close(reader) < 0 || close(replacement) < 0) {
        fputs("Unlinked journal and recreated name did not retain separate contents\n", stderr);
        exit(9);
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0 || read(fd, output, sizeof(output)) != 3 || memcmp(output, "new", 3) != 0 ||
            close(fd) < 0 || unlink(path) < 0) {
        fputs("Journal close damaged the file at its old path\n", stderr);
        exit(10);
    }
}

int main(void) {
    check_tempfile();
    check_unlinked_journal();
    sqlite3 *reader = 0, *writer = 0;
    const char *path = "/home/retroos/wal.sqlite";
    if (sqlite3_open(path, &reader) || sqlite3_open(path, &writer)) return 3;
    sql(reader, "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE entries(value INTEGER)");
    sql(writer, "PRAGMA synchronous=FULL; INSERT INTO entries VALUES(1)");
    sql(reader, "BEGIN");
    count(reader, 1);
    sql(writer, "INSERT INTO entries VALUES(2)");
    count(reader, 1); /* A WAL reader keeps its snapshot while a writer commits. */
    sql(reader, "COMMIT");
    count(reader, 2);
    if (sqlite3_close(writer) || sqlite3_close(reader)) return 4;
    if (sqlite3_open(path, &reader)) return 5;
    count(reader, 2);
    sql(reader, "PRAGMA wal_checkpoint(TRUNCATE)");
    if (sqlite3_close(reader)) return 6;
    puts("SQLITE WAL PASS");
    return 0;
}
