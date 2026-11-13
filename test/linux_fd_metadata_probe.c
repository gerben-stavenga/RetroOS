#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/stat.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
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
static volatile sig_atomic_t dos_child_signals;
static void dos_child_signal(int signal) { (void)signal; dos_child_signals++; }
static void dos_child_wait(const char *root) {
    if (access("/dev/retroos-control",F_OK)) return; // Linux cannot execute DOS COM images.
    char path[1024]; CHECK(snprintf(path,sizeof path,"%s/exit.COM",root)<sizeof path);
    const unsigned char program[]={0xb9,0xff,0xff,0xe2,0xfe,0xb8,37,0x4c,0xcd,0x21};
    int fd=open(path,O_CREAT|O_TRUNC|O_WRONLY,0700); CHECK(fd>=0);
    CHECK(write(fd,program,sizeof program)==sizeof program && !close(fd));
    struct sigaction action={.sa_handler=dos_child_signal},previous;
    sigemptyset(&action.sa_mask); CHECK(!sigaction(SIGCHLD,&action,&previous));
    pid_t child=fork(); CHECK(child>=0);
    if (!child) { char *args[]={path,NULL}; execv(path,args); _exit(127); }
    int status; pid_t waited;
    do { waited=waitpid(child,&status,0); } while (waited<0 && errno==EINTR);
    CHECK(waited==child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status)==37 && dos_child_signals==1);
    CHECK(!sigaction(SIGCHLD,&previous,NULL) && !unlink(path));
}
static void descriptor_paths(void) {
    const char *prefixes[]={"/dev/fd/", "/proc/self/fd/", "/proc/thread-self/fd/"};
    for (unsigned i=0;i<sizeof prefixes/sizeof *prefixes;i++) {
        int pipefd[2]; CHECK(!pipe(pipefd));
        errno=0; CHECK(!isatty(pipefd[0]) && errno==ENOTTY);
        errno=0; CHECK(!isatty(pipefd[1]) && errno==ENOTTY);
        char path[128],byte;
        CHECK(snprintf(path,sizeof path,"%s%d",prefixes[i],pipefd[0])<sizeof path);
        errno=0; CHECK(open(path,O_RDONLY|O_NOFOLLOW)==-1 && errno==ELOOP);
        int input=open(path,O_RDONLY|O_CLOEXEC); CHECK(input>=0 && fcntl(input,F_GETFD)==FD_CLOEXEC);
        CHECK(snprintf(path,sizeof path,"%s%d",prefixes[i],pipefd[1])<sizeof path);
        int output=open(path,O_WRONLY); CHECK(output>=0);
        CHECK(!close(pipefd[0]) && !close(pipefd[1]));
        CHECK(write(output,"x",1)==1 && !close(output));
        CHECK(read(input,&byte,1)==1 && byte=='x' && read(input,&byte,1)==0);
        CHECK(!close(input));
        errno=0; CHECK(open(path,O_WRONLY)==-1 && errno==ENOENT);
    }
    CHECK(system("/bin/bash -c 'read -r a b < <(printf \"123 456\\n\"); [[ $a == 123 && $b == 456 ]]'")==0);
    CHECK(system("/bin/bash -c 'read -r value < /dev/stdin <<<works; [[ $value == works ]]'")==0);
}
static void symlink_modes(const char *root) {
    char linkpath[1024],target[1024];
    CHECK(snprintf(linkpath,sizeof linkpath,"%s/before",root)<sizeof linkpath);
    CHECK(snprintf(target,sizeof target,"%s/after",root)<sizeof target);
    CHECK(!symlink("after",linkpath));
    errno=0; CHECK(syscall(452,AT_FDCWD,linkpath,0755,AT_SYMLINK_NOFOLLOW)==-1 && errno==EOPNOTSUPP);
    int fd=open(target,O_CREAT|O_TRUNC|O_RDWR,0600); CHECK(fd>=0);
    CHECK(!syscall(452,fd,"",0644,AT_EMPTY_PATH));
    struct stat s; CHECK(!fstat(fd,&s) && (s.st_mode&0777)==0644);
    errno=0; CHECK(syscall(452,AT_FDCWD,linkpath,0755,AT_SYMLINK_NOFOLLOW)==-1 && errno==EOPNOTSUPP);
    CHECK(!fstat(fd,&s) && (s.st_mode&0777)==0644);
    CHECK(!syscall(452,AT_FDCWD,linkpath,0700,0));
    CHECK(!fstat(fd,&s) && (s.st_mode&0777)==0700);
    char archive[1024],destination[1024],copy[1024];
    CHECK(snprintf(archive,sizeof archive,"%s/links.tar",root)<sizeof archive);
    CHECK(snprintf(destination,sizeof destination,"%s/extracted",root)<sizeof destination);
    CHECK(!mkdir(destination,0700));
    for (int extract=0;extract<2;extract++) {
        pid_t child=fork(); CHECK(child>=0);
        if (!child) {
            if (extract) execl("/bin/tar","tar","xf",archive,"-C",destination,NULL);
            else execl("/bin/tar","tar","cf",archive,"-C",root,"before","after",NULL);
            _exit(127);
        }
        int status; CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
    }
    CHECK(snprintf(copy,sizeof copy,"%s/before",destination)<sizeof copy);
    CHECK(!lstat(copy,&s) && S_ISLNK(s.st_mode) && !unlink(copy));
    CHECK(snprintf(copy,sizeof copy,"%s/after",destination)<sizeof copy);
    CHECK(!stat(copy,&s) && (s.st_mode&0777)==0700 && !unlink(copy));
    CHECK(!close(fd) && !unlink(linkpath) && !unlink(target) && !unlink(archive) && !rmdir(destination));
}
static void duplicates(const char *root) {
    char path[1024];
    CHECK(snprintf(path,sizeof path,"%s/fd-duplicate",root)<sizeof path);
    FILE *stream=fopen(path,"w"); CHECK(stream);
    // glibc freopen uses dup3 to replace the stream's existing descriptor.
    CHECK(freopen(path,"w",stream)==stream);
    CHECK(fputs("reopened",stream)>=0 && !fclose(stream));
    int fd=open(path,O_RDWR); CHECK(fd>=0);
    CHECK(dup3(fd,60,O_CLOEXEC)==60 && fcntl(60,F_GETFD)==FD_CLOEXEC);
    char bytes[8]; CHECK(read(60,bytes,8)==8 && !memcmp(bytes,"reopened",8));
    CHECK(lseek(fd,0,SEEK_CUR)==8);
    errno=0; CHECK(dup3(fd,fd,0)==-1 && errno==EINVAL);
    errno=0; CHECK(dup3(fd,60,1)==-1 && errno==EINVAL);
    errno=0; CHECK(dup3(-1,60,0)==-1 && errno==EBADF);
    CHECK(fcntl(60,F_GETFD)==FD_CLOEXEC);
    CHECK(dup3(fd,60,0)==60 && fcntl(60,F_GETFD)==0);
    CHECK(!close(fd) && lseek(60,0,SEEK_SET)==0);
    CHECK(read(60,bytes,8)==8 && !memcmp(bytes,"reopened",8));
    // Sparse disk images cross the signed 32-bit offset boundary.
    CHECK(lseek(60,0x82000000LL,SEEK_SET)==0x82000000LL);
    CHECK(lseek(60,0,SEEK_CUR)==0x82000000LL);
    CHECK(write(60,"X",1)==1);
    CHECK(lseek(60,-1,SEEK_END)==0x82000000LL);
    CHECK(read(60,bytes,1)==1 && bytes[0]=='X');
    CHECK(!ftruncate(60,8));
    CHECK(!close(60) && !unlink(path));
}
static void large_transfers(const char *root) {
    enum { COUNT=262144+17 };
    char path[1024]; static unsigned char low[COUNT+64];
    CHECK(snprintf(path,sizeof path,"%s/fd-large-transfer",root)<sizeof path);
    unsigned char *high=mmap((void *)0x500050000000UL,COUNT+4096,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    CHECK(high==(void *)0x500050000000UL);
    for (size_t i=0;i<COUNT;i++) high[i]=(i*37+11)&255;
    int fd=open(path,O_CREAT|O_TRUNC|O_RDWR,0600); CHECK(fd>=0);
    CHECK(write(fd,high,COUNT)==COUNT);
    CHECK(lseek(fd,0,SEEK_SET)==0);
    memset(high,0,COUNT); memset(high+COUNT,0x6d,64);
    CHECK(read(fd,high,COUNT+64)==COUNT);
    for (size_t i=0;i<COUNT;i++) CHECK(high[i]==((i*37+11)&255));
    for (size_t i=COUNT;i<COUNT+64;i++) CHECK(high[i]==0x6d);
    CHECK(lseek(fd,0,SEEK_SET)==0 && read(fd,low,COUNT)==COUNT);
    CHECK(!memcmp(low,high,COUNT));
    CHECK(!close(fd) && !unlink(path) && !munmap(high,COUNT+4096));
}
static void hard_links(const char *root) {
    char source[1024],twin[1024],symbol[1024],symbol2[1024],followed[1024];
    CHECK(snprintf(source,sizeof source,"%s/hard-source",root)<sizeof source);
    CHECK(snprintf(twin,sizeof twin,"%s/hard-twin",root)<sizeof twin);
    CHECK(snprintf(symbol,sizeof symbol,"%s/hard-symbol",root)<sizeof symbol);
    CHECK(snprintf(symbol2,sizeof symbol2,"%s/hard-symbol2",root)<sizeof symbol2);
    CHECK(snprintf(followed,sizeof followed,"%s/hard-followed",root)<sizeof followed);
    int fd=open(source,O_CREAT|O_TRUNC|O_RDWR,0600); CHECK(fd>=0 && write(fd,"abc",3)==3);
    CHECK(!chmod(source,0444));
    int dir=open(root,O_RDONLY|O_DIRECTORY); CHECK(dir>=0);
    CHECK(!linkat(dir,"hard-source",dir,"hard-twin",0));
    struct stat a,b; CHECK(!stat(source,&a) && !stat(twin,&b));
    CHECK(a.st_ino==b.st_ino && a.st_nlink==2 && b.st_nlink==2);
    CHECK(!fstat(fd,&b) && a.st_ino==b.st_ino && b.st_nlink==2);
    struct statx x; CHECK(!statx(dir,"hard-twin",0,STATX_BASIC_STATS,&x) && x.stx_nlink==2);
    errno=0; CHECK(link(source,twin)==-1 && errno==EEXIST);
    CHECK(!unlink(source) && !fstat(fd,&b) && b.st_nlink==1);
    CHECK(!chmod(twin,0644));
    int other=open(twin,O_RDWR); CHECK(other>=0 && write(other,"xyz",3)==3);
    char bytes[8]; CHECK(lseek(fd,0,SEEK_SET)==0 && read(fd,bytes,3)==3 && !memcmp(bytes,"xyz",3));
    CHECK(!symlink("hard-twin",symbol) && !link(symbol,symbol2));
    CHECK(!lstat(symbol,&a) && !lstat(symbol2,&b) && S_ISLNK(a.st_mode));
    CHECK(a.st_ino==b.st_ino && a.st_nlink==2 && b.st_nlink==2);
    CHECK(!linkat(dir,"hard-symbol",dir,"hard-followed",AT_SYMLINK_FOLLOW));
    CHECK(!stat(twin,&a) && !stat(followed,&b) && a.st_ino==b.st_ino && a.st_nlink==2);
    CHECK(!unlink(symbol) && !unlink(symbol2) && !unlink(followed) && !unlink(twin));
    CHECK(!fstat(fd,&a) && a.st_nlink==0);
    CHECK(!close(other) && !close(fd) && !close(dir));
}
static void parallel_append(const char *root) {
    enum { COUNT=262144+17, CHILDREN=3 };
    char path[1024]; CHECK(snprintf(path,sizeof path,"%s/parallel-append",root)<sizeof path);
    int fd=open(path,O_CREAT|O_TRUNC|O_RDWR,0600); CHECK(fd>=0);
    pid_t children[CHILDREN];
    for (int i=0;i<CHILDREN;i++) {
        children[i]=fork(); CHECK(children[i]>=0);
        if (!children[i]) {
            unsigned char *data=malloc(COUNT); CHECK(data); memset(data,'A'+i,COUNT);
            int out=open(path,O_WRONLY|O_APPEND); CHECK(out>=0);
            CHECK(write(out,data,COUNT)==COUNT && !close(out));
            _exit(0);
        }
    }
    for (int i=0;i<CHILDREN;i++) { int status; CHECK(waitpid(children[i],&status,0)==children[i] && WIFEXITED(status) && !WEXITSTATUS(status)); }
    unsigned char *data=malloc(COUNT); CHECK(data); unsigned seen=0;
    for (int i=0;i<CHILDREN;i++) {
        CHECK(read(fd,data,COUNT)==COUNT && data[0]>='A' && data[0]<'A'+CHILDREN);
        unsigned bit=1u<<(data[0]-'A'); CHECK(!(seen&bit)); seen|=bit;
        for (int j=1;j<COUNT;j++) CHECK(data[j]==data[0]);
    }
    CHECK(seen==(1u<<CHILDREN)-1 && read(fd,data,1)==0);
    free(data); CHECK(!close(fd) && !unlink(path));
}
static void copy_tree(const char *root) {
    char source[1024],nested[1100],destination[1024],path[1200],source_dot[1100];
    CHECK(snprintf(source,sizeof source,"%s/copy-source",root)<sizeof source);
    CHECK(snprintf(nested,sizeof nested,"%s/glib",source)<sizeof nested);
    CHECK(snprintf(destination,sizeof destination,"%s/copy-destination",root)<sizeof destination);
    CHECK(snprintf(source_dot,sizeof source_dot,"%s/.",source)<sizeof source_dot);
    CHECK(!mkdir(source,0700) && !mkdir(nested,0700));
    for (int i=0;i<80;i++) {
        CHECK(snprintf(path,sizeof path,"%s/file-%d",i&1?source:nested,i)<sizeof path);
        int fd=open(path,O_CREAT|O_WRONLY,0600); CHECK(fd>=0);
        char data[32]; int n=snprintf(data,sizeof data,"copied-file-%d",i);
        CHECK(write(fd,data,n)==n && !close(fd));
    }
    CHECK(snprintf(path,sizeof path,"%s/configure",source)<sizeof path);
    int fd=open(path,O_CREAT|O_WRONLY,0700); CHECK(fd>=0 && write(fd,"#!/bin/sh\n",10)==10 && !close(fd));
    pid_t child=fork(); CHECK(child>=0);
    if (!child) { execl("/usr/bin/cp","cp","-L","-R",source_dot,destination,(char *)0); _exit(127); }
    int status; CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    CHECK(snprintf(path,sizeof path,"%s/configure",destination)<sizeof path);
    fd=open(path,O_RDONLY); char bytes[32]; CHECK(fd>=0 && read(fd,bytes,10)==10 && !memcmp(bytes,"#!/bin/sh\n",10) && !close(fd));
    for (int i=0;i<80;i++) {
        CHECK(snprintf(path,sizeof path,"%s/%sfile-%d",destination,i&1?"":"glib/",i)<sizeof path);
        fd=open(path,O_RDONLY); CHECK(fd>=0);
        char expected[32]; int n=snprintf(expected,sizeof expected,"copied-file-%d",i);
        CHECK(read(fd,bytes,sizeof bytes)==n && !memcmp(bytes,expected,n) && !close(fd));
    }
}
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
            struct stat metadata; CHECK(!fstatat(fd,entry->name,&metadata,AT_SYMLINK_NOFOLLOW));
            CHECK(metadata.st_ino==entry->ino);
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
    dos_child_wait(root);
    descriptor_paths();
    symlink_modes(root);
    duplicates(root);
    large_transfers(root);
    hard_links(root);
    parallel_append(root);
    copy_tree(root);
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
