#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static long long now(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))_exit(90);return (long long)t.tv_sec*1000000000+t.tv_nsec;}
static pid_t helper(int pipe_fd,long long end){
 pid_t pid=fork();if(pid<0)_exit(91);
 if(!pid){if(write(pipe_fd,"R",1)!=1)_exit(92);volatile unsigned n=1;while(now()<end){for(int i=0;i<1000;i++)n=n*1664525+1013904223;}_exit(0);}
 return pid;
}
int main(void){
 int channel[2];if(pipe(channel))return 1;long long start=now();
 pid_t a=helper(channel[1],start+2000000000);char c;if(read(channel[0],&c,1)!=1)return 2;
 long long first=now()-start;
 pid_t b=helper(channel[1],now()+2000000000);if(read(channel[0],&c,1)!=1)return 3;
 long long second=now()-start;
 long long before=now();struct timespec delay={0,100000000};if(nanosleep(&delay,0))return 4;
 long long timer=now()-before;
 int status;if(waitpid(a,&status,0)!=a||!WIFEXITED(status)||WEXITSTATUS(status))return 5;
 if(waitpid(b,&status,0)!=b||!WIFEXITED(status)||WEXITSTATUS(status))return 6;
 dprintf(2,"RESPONSE_MS ready=%lld second=%lld timer=%lld\n",first/1000000,second/1000000,timer/1000000);
 if(first>700000000||second>1400000000||timer>600000000)return 7;
 dprintf(2,"RESPONSIVENESS_PASS: runnable parent and blocked timer progress during CPU-bound children\n");return 0;
}
