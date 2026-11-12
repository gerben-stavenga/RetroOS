#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
int main(void) {
    struct timespec start,end;
    if (clock_gettime(CLOCK_MONOTONIC,&start)) return 4;
    unsigned char bytes[70003];
    for (unsigned i=0;i<sizeof bytes;i++) bytes[i]=(unsigned char)(i*37+11);
    int fd=open("/home/retroos/shutdown-data",O_CREAT|O_TRUNC|O_WRONLY,0600);
    if (fd<0) return 1;
    unsigned done=0;
    while (done<sizeof bytes) {
        ssize_t n=write(fd,bytes+done,sizeof bytes-done);
        if (n<=0) return 2;
        done+=(unsigned)n;
    }
    if (close(fd)) return 3;
    if (clock_gettime(CLOCK_MONOTONIC,&end)) return 4;
    long long elapsed=(end.tv_sec-start.tv_sec)*1000000000LL+end.tv_nsec-start.tv_nsec;
    if (elapsed>=4000000000LL) return 5;
    fprintf(stderr,"WRITEBACK_SHUTDOWN_PASS: closed without fsync in %lld ms\n",elapsed/1000000);
    return 0;
}
