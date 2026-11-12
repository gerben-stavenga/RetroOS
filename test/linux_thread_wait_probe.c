#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { dprintf(2, "THREAD_WAIT_FAIL %d errno=%d\n", __LINE__, errno); exit(1); } } while (0)
struct waiter { pid_t child, result; int status, error; atomic_int started; };
static atomic_int signals;
static void handler(int sig) { (void)sig; atomic_fetch_add(&signals, 1); }
static void *wait_child(void *arg) {
    struct waiter *wait = arg;
    atomic_store(&wait->started, 1);
    wait->result = waitpid(wait->child, &wait->status, 0);
    wait->error = errno;
    return NULL;
}
static pid_t spawn(int descriptors[2], int code) {
    CHECK(pipe(descriptors) == 0);
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        close(descriptors[1]); ualarm(5000000, 0);
        char token; if (read(descriptors[0], &token, 1) != 1) _exit(90);
        _exit(code);
    }
    close(descriptors[0]); return child;
}
static void release(int fd) { CHECK(write(fd, "x", 1) == 1); CHECK(close(fd) == 0); }
static void started(struct waiter *wait) {
    while (!atomic_load(&wait->started)) usleep(1000);
    usleep(20000);
}
int main(void) {
    CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
    int first[2], second[2], status = 0x1234;
    struct waiter a = {.child = spawn(first, 37)};
    CHECK(waitpid(a.child, &status, WNOHANG) == 0 && status == 0x1234);
    pthread_t ta, tb;
    CHECK(pthread_create(&ta, NULL, wait_child, &a) == 0); started(&a);
    /* Only the sibling can unblock the child. Parking the whole process
       deadlocks until the child's watchdog fires, yielding a wrong status. */
    release(first[1]); CHECK(pthread_join(ta, NULL) == 0);
    CHECK(a.result == a.child && WIFEXITED(a.status) && WEXITSTATUS(a.status) == 37);

    a = (struct waiter){.child = spawn(first, 41)};
    struct waiter b = {.child = spawn(second, 42)};
    CHECK(waitpid(1000000, &status, WNOHANG) == -1 && errno == ECHILD);
    CHECK(pthread_create(&ta, NULL, wait_child, &a) == 0);
    CHECK(pthread_create(&tb, NULL, wait_child, &b) == 0);
    started(&a); started(&b);
    release(second[1]); release(first[1]);
    CHECK(pthread_join(ta, NULL) == 0 && pthread_join(tb, NULL) == 0);
    CHECK(a.result == a.child && WIFEXITED(a.status) && WEXITSTATUS(a.status) == 41);
    CHECK(b.result == b.child && WIFEXITED(b.status) && WEXITSTATUS(b.status) == 42);

    struct sigaction action = {.sa_handler = handler}; sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    a = (struct waiter){.child = spawn(first, 43)};
    CHECK(pthread_create(&ta, NULL, wait_child, &a) == 0); started(&a);
    CHECK(pthread_kill(ta, SIGUSR1) == 0); CHECK(pthread_join(ta, NULL) == 0);
    CHECK(a.result == -1 && a.error == EINTR && atomic_load(&signals) == 1);
    CHECK(waitpid(a.child, &status, WNOHANG) == 0);
    release(first[1]); CHECK(waitpid(a.child, &status, 0) == a.child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 43);
    CHECK(waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD);
    fprintf(stderr, "THREAD_WAIT_PASS: sibling progress, concurrent waits, status, WNOHANG, ECHILD, EINTR\n");
    return 0;
}
