#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { dprintf(2,"THREAD_SIGNAL_FAIL %d errno=%d\n",__LINE__,errno); exit(1); } } while(0)
static atomic_int count, seen_tid, target_tid, ready, release_worker;
static void handler(int sig,siginfo_t *info,void *context) {
 (void)context;
 if(sig!=SIGUSR1 || info->si_code!=SI_TKILL || info->si_pid!=getpid() || info->si_uid!=getuid())_exit(91);
 atomic_store(&seen_tid,syscall(SYS_gettid)); atomic_fetch_add(&count,1);
}
static void *worker(void *arg) {
 (void)arg; sigset_t set;sigemptyset(&set);sigaddset(&set,SIGUSR1);
 CHECK(pthread_sigmask(SIG_BLOCK,&set,NULL)==0);
 atomic_store(&target_tid,syscall(SYS_gettid));atomic_store(&ready,1);
 while(!atomic_load(&release_worker))usleep(1000);
 CHECK(pthread_sigmask(SIG_UNBLOCK,&set,NULL)==0);
 while(atomic_load(&count)!=2)usleep(1000);
 return (void *)77;
}
int main(void) {
 struct sigaction sa={.sa_sigaction=handler,.sa_flags=SA_SIGINFO};sigemptyset(&sa.sa_mask);
 CHECK(sigaction(SIGUSR1,&sa,NULL)==0);
 int pid=getpid(), main_tid=syscall(SYS_gettid);
 CHECK(syscall(SYS_tkill,main_tid,0)==0);
 CHECK(raise(SIGUSR1)==0);CHECK(atomic_load(&count)==1 && atomic_load(&seen_tid)==main_tid);
 pthread_t thread;CHECK(pthread_create(&thread,NULL,worker,NULL)==0);
 while(!atomic_load(&ready))usleep(1000);
 int target=atomic_load(&target_tid);
 CHECK(syscall(SYS_tgkill,pid,target,0)==0);
 CHECK(syscall(SYS_tgkill,pid+1000,target,0)==-1 && errno==ESRCH);
 CHECK(syscall(SYS_tgkill,pid,0,0)==-1 && errno==EINVAL);
 CHECK(syscall(SYS_tgkill,pid,target,65)==-1 && errno==EINVAL);
 CHECK(syscall(SYS_tgkill,pid,target,SIGUSR1)==0);
 CHECK(syscall(SYS_tkill,target,SIGUSR1)==0);
 usleep(20000);CHECK(atomic_load(&count)==1);
 atomic_store(&release_worker,1);
 void *result;CHECK(pthread_join(thread,&result)==0 && result==(void *)77);
 CHECK(atomic_load(&count)==2 && atomic_load(&seen_tid)==target);
 /* Joining observes clear_child_tid before Linux finishes task teardown. */
 int alive=0;
 for(int i=0;i<100;i++) { alive=syscall(SYS_tgkill,pid,target,0); if(alive==-1)break; usleep(1000); }
 CHECK(alive==-1 && errno==ESRCH);
 CHECK(syscall(SYS_tkill,target,0)==-1 && errno==ESRCH);
 pid_t child=fork();CHECK(child>=0);
 if(!child) { syscall(SYS_tgkill,getpid(),syscall(SYS_gettid),SIGTERM);_exit(92); }
 int status;CHECK(waitpid(child,&status,0)==child && WIFSIGNALED(status) && WTERMSIG(status)==SIGTERM);
 fprintf(stderr,"THREAD_SIGNAL_PASS: self/worker, masks, coalescing, identity, ESRCH, fatal signal\n");
 return 0;
}
