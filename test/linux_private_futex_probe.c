#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#define CHECK(x) do { if (!(x)) { dprintf(2,"FUTEX FAIL %d errno=%d\n",__LINE__,errno); exit(1); } } while(0)
static atomic_int gate, ready;
static void *worker(void *arg) {
    (void)arg;
    atomic_fetch_add(&ready,1);
    while (!atomic_load(&gate)) {
        int r=syscall(SYS_futex,&gate,FUTEX_WAIT_PRIVATE,0,NULL);
        CHECK(r==0 || errno==EAGAIN || errno==EINTR);
    }
    return (void *)73;
}
int main(void) {
    pthread_t threads[64];
    for (int i=0;i<64;i++) CHECK(pthread_create(&threads[i],NULL,worker,NULL)==0);
    while (atomic_load(&ready)!=64) usleep(1000);
    usleep(20000);
    struct timespec start, end;
    CHECK(clock_gettime(CLOCK_MONOTONIC,&start)==0);
    for (int i=0;i<10000;i++) CHECK(syscall(SYS_getpid)>0);
    CHECK(clock_gettime(CLOCK_MONOTONIC,&end)==0);
    long long ns=(end.tv_sec-start.tv_sec)*1000000000LL+end.tv_nsec-start.tv_nsec;
    fprintf(stderr,"PRIVATE_FUTEX_PROFILE: 10000 getpid with 64 waiters: %lld ns\n",ns);
    atomic_store(&gate,1);
    CHECK(syscall(SYS_futex,&gate,FUTEX_WAKE_PRIVATE,64,NULL)>=0);
    for(int i=0;i<64;i++) { void *r; CHECK(pthread_join(threads[i],&r)==0 && r==(void *)73); }
    struct timespec timeout={.tv_nsec=10000000};
    errno=0;
    CHECK(syscall(SYS_futex,&gate,FUTEX_WAIT_PRIVATE,1,&timeout)==-1 && errno==ETIMEDOUT);
    CHECK(syscall(SYS_futex,&gate,FUTEX_WAIT_PRIVATE,0,NULL)==-1 && errno==EAGAIN);
    fprintf(stderr,"PRIVATE_FUTEX_PASS: 64 thread wake/join, timeout, mismatched value\n");
    return 0;
}
