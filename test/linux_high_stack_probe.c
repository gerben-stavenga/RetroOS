#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define CHECK(ok) do { if (!(ok)) { dprintf(2, "HIGH_STACK_FAIL line=%d errno=%d\n", __LINE__, errno); _exit(1); } } while (0)
static int input[2], ready[2], pair[2], event;
static void *worker(void *unused) {
    (void)unused;
    volatile int word = 7;
    CHECK((unsigned long)&word >= (1UL<<39));
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0 && now.tv_sec < 9223372036853LL);
    unsigned char bytes[16]; CHECK(syscall(SYS_getrandom, bytes, sizeof bytes, 0) == sizeof bytes);
    sigset_t mask; CHECK(pthread_sigmask(SIG_SETMASK, NULL, &mask) == 0);
    stack_t old; CHECK(sigaltstack(NULL, &old) == 0);
    struct timespec delay = {0, 1000000};
    errno=0; CHECK(syscall(SYS_futex, &word, 128, 7, &delay, NULL, 0) == -1 && errno == ETIMEDOUT);
    CHECK(nanosleep(&delay, NULL) == 0);
    CHECK(write(ready[1], "r", 1) == 1);
    char byte; CHECK(read(input[0], &byte, 1) == 1 && byte == 'x');
    eventfd_t count=5; CHECK(eventfd_write(event, count) == 0);
    byte='s';CHECK(write(pair[1],&byte,1)==1);
    CHECK(read(pair[1],&byte,1)==1 && byte=='t');
    return (void *)37;
}
int main(void) {
    CHECK(pipe(input) == 0 && pipe(ready) == 0);
    CHECK(socketpair(AF_UNIX,SOCK_STREAM,0,pair)==0);
    event=eventfd(0, 0);CHECK(event>=0);
    size_t size=2*1024*1024;
    void *stack=mmap((void *)0x510020000000UL, size, PROT_READ|PROT_WRITE,
                    MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    CHECK(stack == (void *)0x510020000000UL);
    pthread_attr_t attrs;CHECK(pthread_attr_init(&attrs)==0 && pthread_attr_setstack(&attrs,stack,size)==0);
    pthread_t thread;CHECK(pthread_create(&thread,&attrs,worker,NULL)==0);
    char byte;CHECK(read(ready[0],&byte,1)==1 && byte=='r');
    CHECK(write(input[1],"x",1)==1);
    CHECK(read(pair[0],&byte,1)==1 && byte=='s');
    CHECK(write(pair[0],"t",1)==1);
    void *result=NULL;CHECK(pthread_join(thread,&result)==0 && result==(void *)37);
    eventfd_t count;CHECK(eventfd_read(event,&count)==0 && count==5);
    CHECK(munmap(stack,size)==0);
    fprintf(stderr,"HIGH_STACK_PASS: pthread TLS/TID, time, random, signal mask, futex, sleep, pipe, eventfd and socketpair\n");
    return 0;
}
