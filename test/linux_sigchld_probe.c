#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static int reports[2];
static void check(int ok, int line) {
    if (!ok) { dprintf(2, "SIGCHLD FAIL line=%d errno=%d\n", line, errno); _exit(1); }
}
#define CHECK(ok) check((ok), __LINE__)
static void handler(int signal, siginfo_t *info, void *context) {
    (void)context;
    int saved = errno;
    int report[] = {signal, info->si_pid, info->si_code, info->si_status};
    if (write(reports[1], report, sizeof report) != sizeof report) _exit(2);
    errno = saved;
}

int main(void) {
    CHECK(pipe(reports) == 0);
    struct sigaction action = {.sa_sigaction=handler, .sa_flags=SA_SIGINFO};
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGCHLD, &action, NULL) == 0);
    for (int masked=0; masked<2; masked++) {
        for (int repeat=0; repeat<4; repeat++) {
            int gate[2]; CHECK(pipe(gate) == 0);
            sigset_t mask; sigemptyset(&mask); sigaddset(&mask, SIGCHLD);
            if (masked) CHECK(sigprocmask(SIG_BLOCK, &mask, NULL) == 0);
            pid_t child = fork(); CHECK(child >= 0);
            if (!child) {
                close(gate[1]); char byte;
                CHECK(read(gate[0], &byte, 1) == 1);
                _exit(37);
            }
            close(gate[0]);
            int status = 0x12345678;
            CHECK(waitpid(child, &status, WNOHANG) == 0 && status == 0x12345678);
            CHECK(write(gate[1], "x", 1) == 1); close(gate[1]);
            struct pollfd watched = {.fd=reports[0], .events=POLLIN};
            if (masked) {
                CHECK(poll(&watched, 1, 30) == 0);
                CHECK(sigprocmask(SIG_UNBLOCK, &mask, NULL) == 0);
            }
            int ready;
            do { ready = poll(&watched, 1, 1000); } while (ready < 0 && errno == EINTR);
            CHECK(ready == 1);
            int report[4]; CHECK(read(reports[0], report, sizeof report) == sizeof report);
            CHECK(report[0] == SIGCHLD && report[1] == child && report[2] == CLD_EXITED && report[3] == 37);
            CHECK(waitpid(child, &status, WNOHANG) == child && WIFEXITED(status) && WEXITSTATUS(status) == 37);
        }
    }
    fprintf(stderr, "SIGCHLD_PASS: async wait, parked poll, masked delivery, child identity and status\n");
    return 0;
}
