#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
static volatile sig_atomic_t seen;
static void child_signal(int signal) { assert(signal==SIGCHLD); ++seen; }
static void restored(void) {
    sigset_t mask; assert(!sigprocmask(SIG_SETMASK,0,&mask));
    assert(sigismember(&mask,SIGCHLD)==1);
}
int main(void) {
    struct sigaction action={.sa_handler=child_signal}; sigemptyset(&action.sa_mask);
    assert(!sigaction(SIGCHLD,&action,0));
    sigset_t block,empty; sigemptyset(&block);sigaddset(&block,SIGCHLD);sigemptyset(&empty);
    assert(!sigprocmask(SIG_BLOCK,&block,0));
    struct timespec zero={0},timeout={0,2000000};
    assert(!pselect(0,0,0,0,&zero,&empty));restored();
    assert(!pselect(0,0,0,0,&timeout,&empty));restored();
    int pipefd[2];assert(!pipe(pipefd));assert(write(pipefd[1],"x",1)==1);
    fd_set ready;FD_ZERO(&ready);FD_SET(pipefd[0],&ready);
    assert(pselect(pipefd[0]+1,&ready,0,0,&zero,&empty)==1);restored();
    close(pipefd[0]);close(pipefd[1]);
    for(int i=0;i<16;++i) {
        pid_t child=fork(); assert(child>=0);
        if(!child) {usleep(10000);_exit(0);}
        timeout=(struct timespec){2,0};
        int before=seen;
        assert(pselect(0,0,0,0,&timeout,&empty)==-1 && errno==EINTR);
        assert(seen==before+1);restored();
        int status;assert(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
    }
    assert(!kill(getpid(),SIGCHLD));
    timeout=(struct timespec){2,0};
    assert(pselect(0,0,0,0,&timeout,&empty)==-1 && errno==EINTR);restored();
    unsigned long long mask=0;struct {void *pointer;unsigned long length;} descriptor={&mask,7};
    assert(syscall(SYS_pselect6,0,0,0,0,&zero,&descriptor)==-1 && errno==EINVAL);restored();
    fprintf(stderr,"PSELECT_SIGNAL_PASS: temporary masks, pending SIGCHLD, timeout and restoration\n");
}
