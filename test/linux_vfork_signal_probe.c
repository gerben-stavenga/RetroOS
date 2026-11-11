#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int release_pipe[2];
static volatile sig_atomic_t shared_child_done;
static volatile sig_atomic_t early_signal;
static volatile sig_atomic_t signals_seen;
static unsigned char child_stack[65536] __attribute__((aligned(16)));

static void child_exit_signal(int signal) {
    (void)signal;
    if (!shared_child_done) early_signal = 1;
    signals_seen++;
}

static int shared_child(void *unused) {
    int mode = *(int *)unused;
    if (mode == 2) {
        execl("/does-not-exist-vfork-probe", "missing", (char *)NULL);
        if (errno != ENOENT) _exit(92);
    }
    /* Let an older sibling exit while this child still borrows the image. */
    if (write(release_pipe[1], "x", 1) != 1) _exit(90);
    struct timespec delay = {0, 100000000};
    nanosleep(&delay, NULL);
    shared_child_done = 1;
    if (mode == 1) {
        execl("/proc/self/exe", "probe", "exec-child", (char *)NULL);
        _exit(93);
    }
    _exit(9);
}

static int reap(pid_t child, int code) {
    int status;
    pid_t result;
    do { result = waitpid(child, &status, 0); } while (result < 0 && errno == EINTR);
    return result == child && WIFEXITED(status) && WEXITSTATUS(status) == code;
}

static int run_case(int mode) {
    shared_child_done = early_signal = signals_seen = 0;
    if (pipe(release_pipe)) return 1;
    pid_t sibling = fork();
    if (sibling < 0) return 2;
    if (!sibling) {
        char byte;
        _exit(read(release_pipe[0], &byte, 1) == 1 ? 7 : 91);
    }
    pid_t child = clone(shared_child, child_stack + sizeof child_stack,
                        CLONE_VM | CLONE_VFORK | SIGCHLD, &mode);
    if (child < 0 || !shared_child_done || early_signal) return 3;
    if (!reap(sibling, 7)) return 4;
    if (!reap(child, 9)) return 5;
    if (!signals_seen) return 6;
    close(release_pipe[0]);
    close(release_pipe[1]);
    return 0;
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc > 1) return 9;
    struct sigaction action = {.sa_handler = child_exit_signal};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGCHLD, &action, NULL)) return 1;
    for (int repeat = 0; repeat < 8; repeat++) {
        for (int mode = 0; mode < 3; mode++) {
            int result = run_case(mode);
            if (result) {
                fprintf(stderr, "VFORK SIGNAL FAIL: repeat=%d mode=%d code=%d\n", repeat, mode, result);
                return result;
            }
        }
    }
    fprintf(stderr, "VFORK SIGNAL PASS: 24 sibling exits across vfork exit, exec, failed exec\n");
    return 0;
}
