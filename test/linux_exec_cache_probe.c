#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { dprintf(2,"EXEC_CACHE_FAIL line=%d\n",__LINE__); return 1; } } while (0)
static int run(const char *path, int expected) {
    int status; pid_t pid=fork();
    if (pid==0) { execl(path,path,(char *)0); _exit(127); }
    return pid>0 && waitpid(pid,&status,0)==pid && WIFEXITED(status) && WEXITSTATUS(status)==expected;
}
int main(int argc,char **argv) {
    CHECK(argc==2); off_t offset=strtoll(argv[1],0,10);
    const char *path="/home/retroos/child";
    CHECK(run(path,11)); CHECK(run(path,11));
    int fd=open(path,O_RDWR); CHECK(fd>=0);
    unsigned char value=12; CHECK(pwrite(fd,&value,1,offset)==1);
    CHECK(run(path,12)); CHECK(run(path,12));
    off_t page=offset & ~(off_t)4095;
    unsigned char *map=mmap(0,4096,PROT_READ|PROT_WRITE,MAP_SHARED,fd,page);
    CHECK(map!=MAP_FAILED); map[offset-page]=13;
    CHECK(run(path,13));
    CHECK(munmap(map,4096)==0); CHECK(close(fd)==0);
    CHECK(rename(path,"/home/retroos/moved")==0);
    CHECK(run("/home/retroos/moved",13));
    int input=open("/home/retroos/moved",O_RDONLY); CHECK(input>=0);
    int output=open(path,O_CREAT|O_TRUNC|O_WRONLY,0700); CHECK(output>=0);
    char bytes[8192]; ssize_t n;
    while ((n=read(input,bytes,sizeof(bytes)))>0) CHECK(write(output,bytes,n)==n);
    CHECK(n==0); CHECK(close(input)==0); CHECK(close(output)==0);
    CHECK(run(path,13));
    CHECK(unlink(path)==0); CHECK(rename("/home/retroos/moved",path)==0);
    CHECK(run(path,13));
    dprintf(2,"EXEC_CACHE_PASS\n"); return 0;
}
