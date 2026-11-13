#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
static unsigned long long now(void) { struct timespec t; assert(!clock_gettime(CLOCK_MONOTONIC,&t)); return t.tv_sec*1000000000ULL+t.tv_nsec; }
#ifdef COMPILER_WRAPPER
static int instance;
static void record(const char *kind, int pid, unsigned cpu, unsigned apic, int status) {
    int fd=open("/project/compilers.log",O_WRONLY|O_CREAT|O_APPEND,0666); assert(fd>=0);
    char text[192]; int n=snprintf(text,sizeof(text),"%s %d %u %u %llu %d %d\n",kind,pid,cpu,apic,now(),status,instance);
    assert(write(fd,text,n)==n); close(fd);
}
int main(int argc,char **argv) {
    assert(argc>1);
    const char *name=strrchr(argv[1],'/'); name=name?name+1:argv[1];
    if(strcmp(name,"cc1")) { execvp(argv[1],argv+1); return 127; }
    // The wrapper remains alive until END is written. Its PID identifies this
    // invocation even if the reaped compiler PID is reused before that write.
    instance=getpid();
    pid_t child=fork(); assert(child>=0);
    if(!child) {
        unsigned cpu=999,a,b,c,d; assert(!syscall(SYS_getcpu,&cpu,0,0));
        __asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(1));
        record("START",getpid(),cpu,b>>24,0);
        execvp(argv[1],argv+1); _exit(127);
    }
    int status; pid_t waited;
    do { waited=waitpid(child,&status,0); } while(waited<0 && errno==EINTR);
    assert(waited==child);
    record("END",child,0,0,status);
    return WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status);
}
#else
static int builder_pid, last_wait, last_errno;
static void state(unsigned keys,int done) {
    int fd=open("/project/state",O_WRONLY|O_CREAT|O_TRUNC,0666); assert(fd>=0);
    char text[192]; int n=snprintf(text,sizeof(text),"keys=%u build_done=%d builder=%d wait=%d errno=%d\n",keys,done,builder_pid,last_wait,last_errno);
    assert(write(fd,text,n)==n); close(fd);
}
int main(void) {
    assert(!chdir("/project"));
    struct termios saved,raw; assert(!tcgetattr(0,&saved)); raw=saved;
    raw.c_lflag&=~(ICANON|ECHO); raw.c_cc[VMIN]=0; raw.c_cc[VTIME]=0; assert(!tcsetattr(0,TCSANOW,&raw));
    assert(fcntl(0,F_SETFL,fcntl(0,F_GETFL)|O_NONBLOCK)>=0);
    pid_t builder=fork(); assert(builder>=0);
    builder_pid=builder;
    if(!builder) {
        int out=open("/project/build.log",O_WRONLY|O_CREAT|O_TRUNC,0666); assert(out>=0);
        assert(dup2(out,1)==1 && dup2(out,2)==2); close(out);
        execl("/usr/bin/make","make","-j8","all",(char*)0); _exit(127);
    }
    printf("USB input and eight real GCC compile jobs\r\n"); fflush(stdout);
    unsigned keys=0; int done=0,status=0,dumped=0; unsigned long long start=now(); state(keys,done);
    while(keys<1000 || !done) {
        char bytes[64]; int n=read(0,bytes,sizeof(bytes));
        if(n>0) { keys+=n; assert(write(1,bytes,n)==n); state(keys,done); }
        if(!done) { last_wait=waitpid(builder,&status,WNOHANG); last_errno=errno; }
        if(!done && last_wait==builder) {
            assert(WIFEXITED(status) && WEXITSTATUS(status)==0); done=1; state(keys,done);
        }
        if(!dumped && now()-start>10000000000ULL) {
            int control=open("/dev/retroos-control",O_RDWR|O_NONBLOCK); assert(control>=0);
            assert(write(control,"debug dump\n",11)==11); close(control); dumped=1;
        }
        assert(now()-start<180000000000ULL);
        usleep(1000);
    }
    assert(!tcsetattr(0,TCSANOW,&saved));
    fprintf(stderr,"PARALLEL_BUILD_INPUT_PASS keys=%u\n",keys);
    return 0;
}
#endif
