#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <spawn.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
static atomic_int ready,done;
static volatile sig_atomic_t alarms;
static void alarm_handler(int signal) { if(signal==SIGALRM)alarms++; }
static void check_timer(void) {
 struct sigaction action={0};action.sa_handler=alarm_handler;sigemptyset(&action.sa_mask);
 if(sigaction(SIGALRM,&action,0))_exit(31);
 struct itimerval timer={0},old={0};timer.it_value.tv_usec=20000;
 if(setitimer(ITIMER_REAL,&timer,&old) || old.it_value.tv_sec || old.it_value.tv_usec)_exit(32);
 struct timespec pause={1,0};errno=0;
 if(nanosleep(&pause,0)!=-1 || errno!=EINTR || alarms!=1)_exit(33);
 if(getitimer(ITIMER_REAL,&old) || old.it_value.tv_sec || old.it_value.tv_usec)_exit(34);
 sigset_t mask;sigemptyset(&mask);sigaddset(&mask,SIGALRM);
 if(sigprocmask(SIG_BLOCK,&mask,0) || setitimer(ITIMER_REAL,&timer,0))_exit(35);
 pause.tv_sec=0;pause.tv_nsec=50000000;
 if(nanosleep(&pause,0) || alarms!=1)_exit(36);
 if(sigprocmask(SIG_UNBLOCK,&mask,0) || alarms!=2)_exit(38);
 timer.it_interval.tv_usec=20000;
 if(setitimer(ITIMER_REAL,&timer,0))_exit(39);
 for(int i=0;i<2;i++){pause.tv_sec=1;pause.tv_nsec=0;
  if(nanosleep(&pause,0)!=-1 || errno!=EINTR)_exit(40);
 }
 if(alarms!=4)_exit(41);
 timer=(struct itimerval){0};if(setitimer(ITIMER_REAL,&timer,&old) || !old.it_interval.tv_usec)_exit(42);
 timer.it_value.tv_usec=1000000;errno=0;
 if(setitimer(ITIMER_REAL,&timer,0)!=-1 || errno!=EINVAL)_exit(43);
 timer.it_value.tv_usec=0;timer.it_value.tv_sec=100;
 if(setitimer(ITIMER_REAL,&timer,0))_exit(44);
 pid_t child=fork();if(child<0)_exit(45);
 if(!child){if(getitimer(ITIMER_REAL,&old) || old.it_value.tv_sec || old.it_value.tv_usec)_exit(46);_exit(37);}
 int status;if(waitpid(child,&status,0)!=child || !WIFEXITED(status) || WEXITSTATUS(status)!=37)_exit(47);
 fprintf(stderr,"GLIBC TIMER PASS\n");
}
static unsigned char *regions[3];
static volatile int shared_spawn_value;
static int shared_child(void *argument) {
 (void)argument;
 shared_spawn_value=73;
 return 19;
}
static void check_spawn(void) {
 if(setpgid(0,0)!=0 || getpgrp()!=getpid())_exit(49);
 void *stack=malloc(65536);if(!stack)_exit(20);
 pid_t child=clone(shared_child,(char *)stack+65536,CLONE_VM|CLONE_VFORK|SIGCHLD,0);
 if(child<0 || shared_spawn_value!=73)_exit(21);
 int status;if(waitpid(child,&status,0)!=child || !WIFEXITED(status) || WEXITSTATUS(status)!=19)_exit(22);
 free(stack);
 char *args[]={"probe","spawn-child",0};char *env[]={"SPAWN_CHECK=yes",0};
 for(int i=0;i<3;i++){
  posix_spawnattr_t attributes;
  if(posix_spawnattr_init(&attributes) || posix_spawnattr_setpgroup(&attributes,0) ||
     posix_spawnattr_setflags(&attributes,POSIX_SPAWN_SETPGROUP))_exit(50);
  int error=posix_spawn(&child,"/missing-spawn-program",0,&attributes,args,env);
  if(error!=ENOENT)_exit(23);
  int pipefd[2];if(pipe(pipefd))_exit(24);
  posix_spawn_file_actions_t actions;
  if(posix_spawn_file_actions_init(&actions) || posix_spawn_file_actions_adddup2(&actions,pipefd[1],1) ||
     posix_spawn_file_actions_addclose(&actions,pipefd[0]))_exit(25);
  error=posix_spawn(&child,"/proc/self/exe",&actions,&attributes,args,env);
  posix_spawnattr_destroy(&attributes);
  posix_spawn_file_actions_destroy(&actions);close(pipefd[1]);
  if(error)_exit(26);
  char reply[2];if(read(pipefd[0],reply,2)!=2 || memcmp(reply,"OK",2))_exit(27);
  close(pipefd[0]);
  if(waitpid(child,&status,0)!=child || !WIFEXITED(status) || WEXITSTATUS(status)!=37)_exit(28);
 }
 fprintf(stderr,"GLIBC SPAWN PASS\n");
}
static void *worker(void *argument) {
 int which=(int)(long)argument;
 const int count=32*1024*1024;
 unsigned char *bytes=malloc(count);
 if(!bytes)_exit(1);
 memset(bytes,which+17,count);
 atomic_fetch_add(&ready,1);
 while(atomic_load(&ready)!=2)sched_yield();
 if(which==0){
  check_spawn();
  fprintf(stderr,"GLIBC FORK BEGIN\n");
  pid_t child=fork();
  if(child<0)_exit(2);
  if(child==0){
   fprintf(stderr,"GLIBC FORK CHILD\n");
   for(int area=0;area<3;area++)for(int i=0;i<4*1024*1024;i+=4096){
    if(regions[area][i]!=area+41)_exit(9);
    regions[area][i]=99;
   }
   void *tmp=calloc(1,66001);if(!tmp)_exit(3);
   for(int i=0;i<66001;i++)if(((unsigned char *)tmp)[i])_exit(4);
   free(tmp);
   char *args[]={"probe","child",0};char *env[]={"MALLOC_ARENA_MAX=2",0};
   execve("/proc/self/exe",args,env);perror("execve");_exit(5);
  }
  int status=0;if(waitpid(child,&status,0)!=child || !WIFEXITED(status) || WEXITSTATUS(status)!=37)_exit(6);
  fprintf(stderr,"GLIBC FORK PARENT\n");atomic_store(&done,1);
 }else while(!atomic_load(&done))sched_yield();
 for(int i=0;i<count;i++)if(bytes[i]!=(unsigned char)(which+17))_exit(7);
 free(bytes);return 0;
}
int main(int argc,char **argv){
 if(argc>1 && !strcmp(argv[1],"timer-exec")){
  struct itimerval timer;if(getitimer(ITIMER_REAL,&timer) || timer.it_value.tv_sec<90)return 48;
  fprintf(stderr,"GLIBC TIMER EXEC PASS\n");return 0;
 }
 if(argc>1 && !strcmp(argv[1],"child"))return 37;
 if(argc>1 && !strcmp(argv[1],"spawn-child")){
  if(getpgrp()!=getpid())return 51;
  if(!getenv("SPAWN_CHECK") || strcmp(getenv("SPAWN_CHECK"),"yes"))return 29;
  if(write(1,"OK",2)!=2)return 30;
  return 37;
 }
 for(int area=0;area<3;area++){
  regions[area]=mmap((void *)(0x20000000UL+area*0x40000000UL),4*1024*1024,3,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
  if(regions[area]==MAP_FAILED)return 10;
  for(int i=0;i<4*1024*1024;i+=4096)regions[area][i]=area+41;
 }
 pthread_t a,b;
 if(pthread_create(&a,0,worker,(void *)0) || pthread_create(&b,0,worker,(void *)1))return 8;
 pthread_join(a,0);pthread_join(b,0);
 for(int area=0;area<3;area++)for(int i=0;i<4*1024*1024;i+=4096)if(regions[area][i]!=area+41)return 11;
 fprintf(stderr,"GLIBC FORK PASS\n");
 check_timer();
 char *args[]={"probe","timer-exec",0};char *env[]={"MALLOC_ARENA_MAX=2",0};
 execve("/proc/self/exe",args,env);return 49;
}
