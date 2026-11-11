#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { dprintf(2,"CACHE_BUDGET_FAIL %d\n",__LINE__); exit(1); } } while(0)
int main(void) {
 int pins=open("/pins",O_RDONLY), fd=open("/data",O_RDONLY); CHECK(pins>=0 && fd>=0);
 void *mapping=mmap(NULL,3*1024*1024,PROT_READ,MAP_SHARED,pins,0); CHECK(mapping!=MAP_FAILED);
 struct timespec a,b; CHECK(clock_gettime(CLOCK_MONOTONIC,&a)==0);
 char bytes[8192]; uint64_t sum=0,total=0; ssize_t n;
 while((n=read(fd,bytes,sizeof bytes))>0) { for(ssize_t i=0;i<n;i++)sum+=(unsigned char)bytes[i]; total+=n; }
 CHECK(n==0 && total==16*1024*1024 && sum==total*97);
 CHECK(clock_gettime(CLOCK_MONOTONIC,&b)==0);
 long long ns=(b.tv_sec-a.tv_sec)*1000000000LL+b.tv_nsec-a.tv_nsec;
 fprintf(stderr,"CACHE_BUDGET_PASS bytes=%llu ns=%lld\n",(unsigned long long)total,ns);
 CHECK(munmap(mapping,3*1024*1024)==0); close(pins);close(fd);return 0;
}
