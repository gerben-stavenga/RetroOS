#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { dprintf(2,"KILL_FAIL line=%d errno=%d\n",__LINE__,errno); return 1; } } while (0)
static volatile sig_atomic_t seen;
static void received(int sig) { seen = sig; }
int main(void) {
    CHECK(kill(999999, 0) == -1 && errno == ESRCH);
    CHECK(kill(getpid(), 65) == -1 && errno == EINVAL);
    CHECK(kill(getpid(), -1) == -1 && errno == EINVAL);
    CHECK(kill(getpid(), 0) == 0);
    CHECK(kill(0, 0) == 0);
#ifdef __x86_64__
    struct sigaction action = {.sa_handler = received};
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, &action, 0) == 0);
    CHECK(kill(getpid(), SIGUSR1) == 0 && seen == SIGUSR1);
    seen = 0;
    sigset_t mask;
    sigemptyset(&mask); sigaddset(&mask,SIGUSR1);
    CHECK(sigprocmask(SIG_BLOCK,&mask,0)==0);
    CHECK(kill(getpid(),SIGUSR1)==0 && seen==0);
    CHECK(sigprocmask(SIG_UNBLOCK,&mask,0)==0 && seen==SIGUSR1);
#endif
    int fds[2], status;
    CHECK(pipe(fds) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        close(fds[1]);
        char byte;
        _exit(read(fds[0], &byte, 1) == 1 ? 99 : 98);
    }
    CHECK(kill(child,0)==0);
    CHECK(kill(child,SIGKILL)==0);
    CHECK(waitpid(child,&status,0)==child);
    CHECK(WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL);
    CHECK(kill(child,0)==-1 && errno==ESRCH);
    close(fds[0]); close(fds[1]);
    dprintf(2,"KILL_PASS\n");
    return 0;
}
