#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
    int report[2], hold[2]; assert(pipe(report)==0 && pipe(hold)==0);
    pid_t session=getsid(0), own_group=getpgrp();
    pid_t leader=fork(); assert(leader>0 || leader==0);
    if(!leader) {
        pid_t inherited = getpgrp();
        assert(write(report[1], &inherited, sizeof(inherited)) == sizeof(inherited));
        assert(getpgrp()==own_group && getsid(0)==session);
        assert(setpgid(0,0)==0 && getpgrp()==getpid());
        pid_t group=getpid();
        pid_t member=fork(); assert(member>=0);
        if(!member) {
            pid_t self=getpid();
            assert(getpgrp()==group && getsid(0)==session);
            assert(write(report[1],&self,sizeof(self))==sizeof(self));
            char byte; int ignored = read(hold[0],&byte,1); _exit(ignored == 42 ? 94 : 92);
        }
        _exit(0);
    }
    pid_t inherited;
    assert(read(report[0], &inherited, sizeof(inherited)) == sizeof(inherited) && inherited == own_group);
    pid_t member; assert(read(report[0],&member,sizeof(member))==sizeof(member));
    int status; assert(waitpid(leader,&status,0)==leader && status==0);
    assert(getpgid(member)==leader && getsid(member)==session);
    pid_t unrelated=fork(); assert(unrelated>=0 && unrelated!=leader);
    if(!unrelated) { char byte; int ignored = read(hold[0],&byte,1); _exit(ignored == 42 ? 94 : 93); }
    assert(getpgid(unrelated)==own_group);
    assert(setpgid(unrelated,unrelated)==0 && getpgid(unrelated)==unrelated);
    assert(kill(-leader,0)==0 && kill(-leader,SIGKILL)==0);
    assert(waitpid(member,&status,0)==member && WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL);
    assert(kill(unrelated,0)==0);
    assert(kill(unrelated,SIGTERM)==0);
    assert(waitpid(unrelated,&status,0)==unrelated && WIFSIGNALED(status) && WTERMSIG(status)==SIGTERM);
    assert(kill(-leader,0)==-1 && errno==ESRCH);
    assert(getpgid(member)==-1 && errno==ESRCH);
    pid_t child=fork(); assert(child>=0);
    if(!child) {
        assert(setsid()==getpid() && getsid(0)==getpid() && getpgrp()==getpid());
        assert(setpgid(0,0)==-1 && errno==EPERM);
        _exit(0);
    }
    assert(waitpid(child,&status,0)==child && status==0);
    fprintf(stderr,"PROCESS_GROUP_PASS: inheritance, orphan group, PID reservation, cleanup isolation, sessions\n");
    return 0;
}
