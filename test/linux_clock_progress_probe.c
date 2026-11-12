#define _GNU_SOURCE
#include <stdatomic.h>
#include <signal.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t alarms;
static _Atomic int progress, started;
static volatile sig_atomic_t child_exited;
static int channel[2];
static void tick(int signal) {
    if (signal == SIGCHLD) child_exited = 1;
    else ++alarms;
}
static long long now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) abort();
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}
static void *worker(void *arg) {
    (void)arg;
    while (!atomic_load(&started)) sched_yield();
    struct timespec delay = {0, 20000000};
    while (nanosleep(&delay, &delay)) {}
    atomic_store(&progress, 1);
    if (write(channel[1], "x", 1) != 1) abort();
    return NULL;
}
int main(void) {
    struct sigaction action = {.sa_handler = tick};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGCHLD, &action, NULL) || pipe(channel)) return 1;
    pid_t child = fork();
    if (child < 0) return 2;
    if (!child) {
        char c;
        close(channel[1]);
        if (read(channel[0], &c, 1) != 1) _exit(3);
        _exit(0);
    }
    pthread_t thread;
    if (sigaction(SIGALRM, &action, NULL) || pthread_create(&thread, NULL, worker, NULL)) return 4;
    struct itimerval timer = {{0, 10000}, {0, 10000}};
    if (setitimer(ITIMER_REAL, &timer, NULL)) return 5;
    long long end = now() + 300000000;
    atomic_store(&started, 1);
    unsigned long reads = 0;
    while (now() < end) ++reads;
    // Observe progress before join/wait can give the other tasks CPU time.
    int woke = atomic_load(&progress), ran = child_exited;
    int ticks = alarms;
    timer = (struct itimerval){{0, 0}, {0, 0}};
    if (setitimer(ITIMER_REAL, &timer, NULL)) return 6;
    int status;
    if (pthread_join(thread, NULL) || waitpid(child, &status, 0) != child || status) return 7;
    fprintf(stderr, "clock progress: reads=%lu alarms=%d worker=%d child=%d\n", reads, ticks, woke, ran);
    if (!reads || ticks < 3 || !woke || !ran) return 8;
    close(channel[0]); close(channel[1]);
    fprintf(stderr, "CLOCK_PROGRESS_PASS:\n");
    return 0;
}
