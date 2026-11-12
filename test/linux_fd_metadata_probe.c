#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/stat.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { dprintf(2,"FD_METADATA_FAIL line=%d errno=%d\n",__LINE__,errno); exit(1); } } while (0)
static void check(int fd, ino_t ino, off_t size, mode_t mode, time_t modified) {
    struct stat s;
    CHECK(!fstat(fd,&s));
    CHECK(s.st_ino==ino && s.st_size==size && (s.st_mode&07777)==mode);
    CHECK(s.st_uid==geteuid() && s.st_gid==getegid() && s.st_mtime==modified);
    struct statx x;
    CHECK(!syscall(SYS_statx,fd,"",AT_EMPTY_PATH,STATX_BASIC_STATS,&x));
    CHECK(x.stx_ino==ino && x.stx_size==size && (x.stx_mode&07777)==mode);
    CHECK(x.stx_uid==s.st_uid && x.stx_gid==s.st_gid && x.stx_mtime.tv_sec==modified);
}
struct dirent64 { uint64_t ino; int64_t off; unsigned short len; unsigned char type; char name[]; };
static void listing(const char *root) {
    char dir[1024],path[1100];
    CHECK(snprintf(dir,sizeof dir,"%s/fd-listing",root)<sizeof dir);
    CHECK(!mkdir(dir,0700));
    const char *names[]={"one","two","third"};
    for (int i=0;i<3;i++) {
        CHECK(snprintf(path,sizeof path,"%s/%s",dir,names[i])<sizeof path);
        int fd=open(path,O_CREAT|O_WRONLY,0600); CHECK(fd>=0 && !close(fd));
    }
    int fd=open(dir,O_RDONLY|O_DIRECTORY); CHECK(fd>=0);
    unsigned char *high=mmap((void *)0x500030000000UL,8192,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    CHECK(high==(void *)0x500030000000UL);
    // One record per call and output split over two initially untouched pages.
    unsigned char *buffer=high+4096-8;
    for (int pass=0;pass<2;pass++) {
        unsigned found=0;
        for (;;) {
            long n=syscall(SYS_getdents64,fd,buffer,32); CHECK(n>=0 && n<=32);
            if (!n) break;
            struct dirent64 *entry=(void *)buffer;
            CHECK(entry->len==n && entry->len>=24 && memchr(entry->name,0,n-19));
            if (!strcmp(entry->name,".") || !strcmp(entry->name,"..")) continue;
            for (int i=0;i<3;i++) if (!strcmp(entry->name,names[i])) {
                CHECK(!(found&(1u<<i)) && entry->type==8); found|=1u<<i;
            }
        }
        CHECK(found==7);
        CHECK(lseek(fd,0,SEEK_SET)==0);
    }
    CHECK(!munmap(high,8192) && !close(fd));
    for (int i=0;i<3;i++) {
        CHECK(snprintf(path,sizeof path,"%s/%s",dir,names[i])<sizeof path);
        CHECK(!unlink(path));
    }
    CHECK(!rmdir(dir));
}
int main(void) {
    const char *root=getenv("FD_METADATA_ROOT");
    if (!root) root="/home/retroos";
    listing(root);
    char path[1024],renamed[1024];
    CHECK(snprintf(path,sizeof path,"%s/fd-metadata",root)<sizeof path);
    CHECK(snprintf(renamed,sizeof renamed,"%s/fd-metadata-renamed",root)<sizeof renamed);
    int a=open(path,O_CREAT|O_TRUNC|O_RDWR,0600); CHECK(a>=0);
    int b=open(path,O_RDONLY); CHECK(b>=0);
    CHECK(write(a,"abcde",5)==5);
    CHECK(!chmod(path,0640));
    struct timespec times[2]={{1700000000,0},{1700000123,0}};
    CHECK(!utimensat(AT_FDCWD,path,times,0));
    struct stat initial; CHECK(!fstat(a,&initial));
    check(a,initial.st_ino,5,0640,1700000123);
    check(b,initial.st_ino,5,0640,1700000123);
    CHECK(!ftruncate(a,8193));
    // Reset mtime after truncation so both descriptors must see the explicit value.
    CHECK(!utimensat(AT_FDCWD,path,times,0));
    check(b,initial.st_ino,8193,0640,1700000123);
    CHECK(!rename(path,renamed));
    int replacement=open(path,O_CREAT|O_TRUNC|O_RDWR,0600); CHECK(replacement>=0);
    CHECK(write(replacement,"replacement",11)==11 && !close(replacement));
    check(a,initial.st_ino,8193,0640,1700000123);
    CHECK(!unlink(renamed));
    check(a,initial.st_ino,8193,0640,1700000123);
    check(b,initial.st_ino,8193,0640,1700000123);
    CHECK(!close(a) && !close(b) && !unlink(path));
    fprintf(stderr,"FD_METADATA_PASS: live size/mode/time/ownership, statx, rename, unlink\n");
    return 0;
}
