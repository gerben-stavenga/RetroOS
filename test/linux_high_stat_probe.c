#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/stat.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
    char *region=mmap((void*)0x100ffffd000ULL,12288,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    assert(region==(void*)0x100ffffd000ULL);
    struct stat *st=(void*)(region+4096-64);
    assert(syscall(SYS_stat,"/probe",st)==0);assert(S_ISREG(st->st_mode) && st->st_size>0);
    strcpy(region,"/probe");
    assert(syscall(SYS_lstat,region,st)==0);
    int fd=open("/probe",O_RDONLY);assert(fd>=0);
    assert(syscall(SYS_fstat,fd,st)==0);
    assert(syscall(SYS_newfstatat,AT_FDCWD,region,st,0)==0);
    assert(syscall(SYS_newfstatat,fd,"",st,AT_EMPTY_PATH)==0);
    struct statx *sx=(void*)(region+8192-128);
    assert(syscall(SYS_statx,AT_FDCWD,region,0,STATX_BASIC_STATS,sx)==0);
    assert(S_ISREG(sx->stx_mode) && sx->stx_size==(unsigned long long)st->st_size);
    assert(syscall(SYS_statx,fd,"",AT_EMPTY_PATH,STATX_BASIC_STATS,sx)==0);
    assert(syscall(SYS_stat,"/probe",(void*)0xffffd000UL)==-1 && errno==EFAULT);
    assert(syscall(SYS_stat,(void*)0xffffd000UL,st)==-1 && errno==EFAULT);
    assert(syscall(SYS_fstat,fd,(void*)0xffffd000UL)==-1 && errno==EFAULT);
    assert(syscall(SYS_newfstatat,AT_FDCWD,region,(void*)0xffffd000UL,0)==-1 && errno==EFAULT);
    assert(syscall(SYS_statx,fd,"",AT_EMPTY_PATH,STATX_BASIC_STATS,(void*)0xffffd000UL)==-1 && errno==EFAULT);
    memset(st,0x5a,sizeof(*st));
    pid_t child=fork();assert(child>=0);
    if(!child) {assert(syscall(SYS_stat,region,st)==0);assert(S_ISREG(st->st_mode));_exit(0);}
    int status;assert(waitpid(child,&status,0)==child && status==0);
    for(unsigned i=0;i<sizeof(*st);++i)assert(((unsigned char*)st)[i]==0x5a);
    // Paths and output buffers in a high mapping must never alias their low bits.
    strcpy(region,"/probe");
    int highfd=open(region,O_RDONLY);assert(highfd>=0);
    char magic[4];assert(read(highfd,magic,4)==4 && !memcmp(magic,"\177ELF",4));close(highfd);
    assert(access(region,F_OK)==0);
    assert(open("",O_RDONLY)==-1 && errno==ENOENT);
    assert(open((void*)0xffffd000UL,O_RDONLY)==-1 && errno==EFAULT);
    strcpy(region,"/home/retroos/high-path");
    highfd=open(region,O_CREAT|O_EXCL|O_RDWR,0600);assert(highfd>=0);
    assert(write(highfd,"ok",2)==2);
    strcpy(region+1024,"config");
    assert(pwrite(highfd,region+1024,6,1)==6);
    assert(lseek(highfd,0,SEEK_CUR)==2);
    memset(region+4094,0,8);
    assert(pread(highfd,region+4094,8,0)==7);
    assert(!memcmp(region+4094,"oconfig",7));
    assert(lseek(highfd,0,SEEK_CUR)==2);
    assert(pread(highfd,(void*)0xffffd000UL,7,0)==-1 && errno==EFAULT);
    assert(pwrite(highfd,(void*)0xffffd000UL,7,0)==-1 && errno==EFAULT);
    assert(pread(highfd,region+4094,8,7)==0);
    struct iovec *vec=(void*)(region+2048);
    vec[0]=(struct iovec){region+1024,3};
    vec[1]=(struct iovec){region+1027,3};
    assert(writev(highfd,vec,2)==6);
    assert(pread(highfd,region+4094,8,0)==8);
    assert(!memcmp(region+4094,"occonfig",8));
    assert(lseek(highfd,0,SEEK_SET)==0);
    assert(readv(highfd,vec,2)==6);
    assert(!memcmp(region+1024,"occonf",6));
    close(highfd);
    strcpy(region+256,"/home/retroos/high-renamed");
    assert(rename(region,region+256)==0);
    assert(chmod(region+256,0644)==0);
    strcpy(region+512,"/home/retroos/high-link");
    assert(symlink(region+256,region+512)==0);
    int n=readlink(region+512,region+1024,128);
    assert(n==(int)strlen(region+256) && !memcmp(region+1024,region+256,n));
    assert(readlink(region+512,(void*)0xffffd000UL,128)==-1 && errno==EFAULT);
    assert(unlink(region+512)==0 && unlink(region+256)==0);
    strcpy(region,"/home/retroos");assert(chdir(region)==0);
    assert(syscall(SYS_getcwd,region+1024,128)==sizeof("/home/retroos"));
    assert(!strcmp(region+1024,"/home/retroos"));
    assert(syscall(SYS_getcwd,region+1024,1)==-1 && errno==ERANGE);
    assert(syscall(SYS_getcwd,(void*)0xffffd000UL,128)==-1 && errno==EFAULT);
    highfd=open(region,O_RDONLY|O_DIRECTORY);assert(highfd>=0);
    assert(read(highfd,magic,4)==-1 && errno==EISDIR);close(highfd);
    assert(syscall(SYS_sched_getaffinity,0,32,region+1024)==8);
    assert(*(unsigned long long*)(region+1024)!=0);
    assert(syscall(SYS_sched_getaffinity,0,32,(void*)0xffffd000UL)==-1 && errno==EFAULT);
    struct utsname *uts=(void*)(region+1024);
    memset(uts,0x5a,sizeof(*uts));
    child=fork();assert(child>=0);
    if(!child) {assert(uname(uts)==0 && !strcmp(uts->sysname,"Linux"));_exit(0);}
    assert(waitpid(child,&status,0)==child && status==0);
    for(unsigned i=0;i<sizeof(*uts);++i)assert(((unsigned char*)uts)[i]==0x5a);
    assert(uname(uts)==0 && !strcmp(uts->sysname,"Linux"));
    struct pollfd *pollfd=(void*)(region+1024);
    *pollfd=(struct pollfd){fd,POLLIN,0};
    assert(poll(pollfd,1,0)==1 && (pollfd->revents & POLLIN));
    int ep=epoll_create1(0), ev=eventfd(1,0);assert(ep>=0 && ev>=0);
    struct epoll_event *event=(void*)(region+1024);
    event->events=EPOLLIN;event->data.u64=0x123456789abcdef0ULL;
    assert(epoll_ctl(ep,EPOLL_CTL_ADD,ev,event)==0);
    assert(epoll_wait(ep,event+1,1,0)==1);
    assert(event[1].events==EPOLLIN && event[1].data.u64==event->data.u64);
    assert(epoll_wait(ep,(void*)0xffffd000UL,1,0)==-1 && errno==EFAULT);
    assert(epoll_ctl(ep,EPOLL_CTL_MOD,ev,(void*)0xffffd000UL)==-1 && errno==EFAULT);
    unsigned long long counter;
    assert(read(ev,&counter,sizeof(counter))==sizeof(counter));
    child=fork();assert(child>=0);
    if(!child) {usleep(20000);counter=1;assert(write(ev,&counter,sizeof(counter))==sizeof(counter));_exit(0);}
    assert(epoll_wait(ep,event+1,1,1000)==1);
    assert(event[1].events==EPOLLIN && event[1].data.u64==event->data.u64);
    assert(waitpid(child,&status,0)==child && status==0);
    close(ev);close(ep);
    close(fd);assert(!munmap(region,12288));
    fprintf(stderr,"HIGH_STAT_PASS: 64-bit paths, cross-page outputs, COW and EFAULT\n");
}
