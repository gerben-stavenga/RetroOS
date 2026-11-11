#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *self;
static void check(int ok, int line) {
    if (!ok) { dprintf(2, "EXEC ARGUMENTS FAIL line=%d errno=%d\n", line, errno); _exit(1); }
}
#define CHECK(ok) check((ok), __LINE__)
static char *payload(size_t length) {
    char *p = malloc(length + 1); CHECK(p != NULL);
    for (size_t i=0; i<length; i++) p[i] = 'a' + i % 26;
    p[length] = 0;
    return p;
}
static void run(size_t length, int environment, int too_big) {
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        char number[32]; snprintf(number, sizeof number, "%zu", length);
        char *value = payload(length);
        char *args[] = {(char *)self, "child", number, environment ? "env" : value, NULL};
        char *env[] = {environment ? value : NULL, NULL};
        execve(self, args, env);
        CHECK(too_big && errno == E2BIG);
        _exit(0);
    }
    int status; CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
int main(int argc, char **argv, char **envp) {
    self = argv[0];
    if (argc == 4 && !strcmp(argv[1], "child")) {
        size_t length = strtoul(argv[2], NULL, 10);
        const char *value = !strcmp(argv[3], "env") ? envp[0] : argv[3];
        CHECK(value != NULL && strlen(value) == length);
        for (size_t i=0; i<length; i++) CHECK(value[i] == 'a' + i % 26);
        return 0;
    }
    for (int env=0; env<2; env++) {
        size_t lengths[] = {4095, 4096, 4097, 65536, 131071};
        for (size_t i=0; i<sizeof lengths/sizeof *lengths; i++) run(lengths[i], env, 0);
        run(131072, env, 1);
    }
    // Pointer and string storage must both be bounded; a rejected exec must
    // leave the caller alive and usable.
    char *value = payload(65536);
    char *args[40]; args[0]=(char *)self;
    for (int i=1; i<39; i++) args[i]=value;
    args[39]=NULL;
    char *empty[] = {NULL};
    CHECK(execve(self, args, empty) == -1 && errno == E2BIG);
    free(value);
    fprintf(stderr, "EXEC_ARGUMENTS_PASS: long argv/env, exact string limit, aggregate E2BIG\n");
    return 0;
}
