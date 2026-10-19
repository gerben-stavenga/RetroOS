/* Use the host's SQLite runtime without requiring its development package. */
#include <stdio.h>
#include <stdlib.h>
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
int main(void) {
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
