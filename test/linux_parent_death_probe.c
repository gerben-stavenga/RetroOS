#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>

static int report_fd;
static void check(int ok, int code) { if (!ok) { dprintf(2,"PDEATH FAIL %d errno=%d\n",code,errno); _exit(code); } }
static int setting(void) { int value=-1; check(prctl(PR_GET_PDEATHSIG,&value,0UL,0UL,0UL)==0,10); return value; }
static void arm(int signal) { check(prctl(PR_SET_PDEATHSIG,(unsigned long)signal,0UL,0UL,0UL)==0,11); }
static void reap_exit(pid_t child,int code) { int status; check(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==code,12); }
static void handler(int signal,siginfo_t *info,void *context) {
 (void)context;
 int values[2]={signal,info->si_pid};
 if(write(report_fd,values,sizeof values)!=(ssize_t)sizeof values)_exit(90);
 _exit(37);
}
static void install_handler(int fd) {
 report_fd=fd;
 struct sigaction action={0};action.sa_sigaction=handler;action.sa_flags=SA_SIGINFO;
 sigemptyset(&action.sa_mask);check(sigaction(SIGTERM,&action,0)==0,13);
}
static void death_case(int mode) {
 int report[2],hold[2];check(pipe(report)==0 && pipe(hold)==0,20);
 pid_t middle=fork();check(middle>=0,21);
 if(!middle){
  close(report[0]);close(hold[1]);
  int ready[2];check(pipe(ready)==0,22);
  pid_t expected_parent=getpid();
  pid_t leaf=fork();check(leaf>=0,23);
  if(!leaf){
   close(ready[0]);
   check(getppid()==expected_parent,24);
   check(write(report[1],&(pid_t){getpid()},sizeof(pid_t))==sizeof(pid_t),25);
   if(mode==1 || mode==2)install_handler(report[1]);
   if(mode==2){sigset_t mask;sigemptyset(&mask);sigaddset(&mask,SIGTERM);check(sigprocmask(SIG_BLOCK,&mask,0)==0,26);}
   if(mode==4)check(signal(SIGTERM,SIG_IGN)!=SIG_ERR,27);
   arm(mode==5 ? SIGKILL : SIGTERM);
   if(mode==3)arm(0);
   check(write(ready[1],"R",1)==1,28);close(ready[1]);
   if(mode==2){
    struct timespec delay={0,50000000};nanosleep(&delay,0);
    check(getppid()==1,29);
    sigset_t mask;sigemptyset(&mask);sigaddset(&mask,SIGTERM);
    check(sigprocmask(SIG_UNBLOCK,&mask,0)==0,30);
    _exit(91);
   }
   char byte;check(read(hold[0],&byte,1)==0,31);
   check(mode==3 || mode==4,32);
   _exit(37);
  }
  close(ready[1]);char byte;check(read(ready[0],&byte,1)==1,33);
  _exit(0);
 }
 close(report[1]);close(hold[0]);pid_t leaf;
 check(read(report[0],&leaf,sizeof leaf)==sizeof leaf,34);
 reap_exit(middle,0);
 if(mode==3 || mode==4)close(hold[1]);
 if(mode==1 || mode==2){
  int values[2];check(read(report[0],values,sizeof values)==sizeof values,35);
  check(values[0]==SIGTERM && values[1]==middle,36);
 }
 int status;check(waitpid(leaf,&status,0)==leaf,37);
 if(mode==0 || mode==5)check(WIFSIGNALED(status) && WTERMSIG(status)==(mode==5 ? SIGKILL : SIGTERM),38);
 else check(WIFEXITED(status) && WEXITSTATUS(status)==37,39);
 if(mode!=3 && mode!=4)close(hold[1]);close(report[0]);
 fprintf(stderr,"PDEATH CASE %d PASS\n",mode);
}
static int thread_report[2],thread_hold[2];
static pid_t thread_child;
static void *creator(void *unused) {
 (void)unused;check(setting()==0,50);
 int ready[2];check(pipe(ready)==0,51);
 thread_child=fork();check(thread_child>=0,52);
 if(!thread_child){
  close(ready[0]);install_handler(thread_report[1]);arm(SIGTERM);
  check(write(ready[1],"R",1)==1,53);close(ready[1]);
  char byte;ssize_t count=read(thread_hold[0],&byte,1);_exit(count==0 ? 92 : 94);
 }
 close(ready[1]);char byte;check(read(ready[0],&byte,1)==1,54);close(ready[0]);
 return 0;
}
int main(int argc,char **argv) {
 if(argc>1){
  check(setting()==SIGTERM,60);check(getppid()==atoi(argv[1]),61);
  pid_t child=fork();check(child>=0,62);
  if(!child){check(setting()==0,63);_exit(0);}
  reap_exit(child,0);return 37;
 }
 check(setting()==0,1);arm(SIGTERM);check(setting()==SIGTERM,2);
 errno=0;check(prctl(PR_SET_PDEATHSIG,65UL,0UL,0UL,0UL)==-1 && errno==EINVAL && setting()==SIGTERM,3);
 errno=0;check(prctl(PR_GET_PDEATHSIG,0UL,0UL,0UL,0UL)==-1 && errno==EFAULT,4);
 pid_t parent=getpid(),child=fork();check(child>=0,5);
 if(!child){check(setting()==0,6);check(getppid()==parent,7);check(setsid()>0,8);arm(SIGTERM);
  char value[32];snprintf(value,sizeof value,"%d",parent);
  execl("/proc/self/exe","probe",value,(char *)0);_exit(93);
 }
 reap_exit(child,37);check(setting()==SIGTERM,9);arm(0);
 for(int mode=0;mode<6;mode++)death_case(mode);
 check(pipe(thread_report)==0 && pipe(thread_hold)==0,55);
 arm(SIGTERM);pthread_t thread;check(pthread_create(&thread,0,creator,0)==0,56);
 check(pthread_join(thread,0)==0,57);
 int values[2];check(read(thread_report[0],values,sizeof values)==sizeof values && values[0]==SIGTERM && values[1]==getpid(),58);
 reap_exit(thread_child,37);arm(0);
 close(thread_report[0]);close(thread_report[1]);close(thread_hold[0]);close(thread_hold[1]);
 /* User exit(-1) remains a normal status of 255, distinct from fatal signals. */
 child=fork();check(child>=0,64);if(!child)_exit(-1);reap_exit(child,255);
 fprintf(stderr,"PARENT DEATH PASS: identity, fork, exec, defaults, handlers, mask, clear, ignore, creator thread\n");
 return 0;
}
