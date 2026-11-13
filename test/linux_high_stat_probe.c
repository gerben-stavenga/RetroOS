#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/stat.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
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
    close(fd);assert(!munmap(region,12288));
    fprintf(stderr,"HIGH_STAT_PASS: 64-bit paths, cross-page outputs, COW and EFAULT\n");
}
