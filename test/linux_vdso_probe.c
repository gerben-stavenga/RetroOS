#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { dprintf(2,"VDSO_FAIL line=%d errno=%d\n",__LINE__,errno); exit(1); } } while (0)
typedef int (*clock_fn)(clockid_t, struct timespec *);
static long long ns(struct timespec t) { return t.tv_sec*1000000000LL+t.tv_nsec; }
static clock_fn lookup(uintptr_t base) {
    Elf64_Ehdr *elf=(void *)base;
    CHECK(!memcmp(elf->e_ident, ELFMAG, SELFMAG) && elf->e_ident[EI_CLASS]==ELFCLASS64);
    Elf64_Phdr *ph=(void *)(base+elf->e_phoff);
    Elf64_Dyn *dyn=NULL;
    for (int i=0;i<elf->e_phnum;i++) if (ph[i].p_type==PT_DYNAMIC) dyn=(void *)(base+ph[i].p_vaddr);
    CHECK(dyn);
    const char *strings=NULL; Elf64_Sym *symbols=NULL; uint32_t *hash=NULL;
    for (;dyn->d_tag;dyn++) {
        if (dyn->d_tag==DT_STRTAB) strings=(void *)(base+dyn->d_un.d_ptr);
        if (dyn->d_tag==DT_SYMTAB) symbols=(void *)(base+dyn->d_un.d_ptr);
        if (dyn->d_tag==DT_HASH) hash=(void *)(base+dyn->d_un.d_ptr);
    }
    CHECK(strings && symbols && hash);
    for (unsigned i=1;i<hash[1];i++)
        if (!strcmp(strings+symbols[i].st_name,"__vdso_clock_gettime")) return (clock_fn)(base+symbols[i].st_value);
    CHECK(0); return NULL;
}
int main(int argc, char **argv) {
    // Give the controller time to enable the syscall counters before probing.
    if (argc==1 || (argc>1 && !strcmp(argv[1],"--fallback"))) usleep(500000);
    uintptr_t base=getauxval(AT_SYSINFO_EHDR);
    if (argc>1 && !strcmp(argv[1],"--fallback")) {
        CHECK(!base);
        struct timespec a,b;
        CHECK(!clock_gettime(CLOCK_MONOTONIC,&a)); usleep(20000);
        CHECK(!clock_gettime(CLOCK_MONOTONIC,&b) && ns(b)>ns(a));
        fprintf(stderr,"VDSO_FALLBACK_PASS:\n"); usleep(1000000); return 0;
    }
    CHECK(base);
    clock_fn direct=lookup(base);
    if (argc>1 && !strcmp(argv[1],"--exec")) {
        struct timespec t;
        for (int i=0;i<10000;i++) CHECK(!direct(CLOCK_MONOTONIC,&t) && !clock_gettime(CLOCK_MONOTONIC,&t));
        return 0;
    }
    int ids[]={CLOCK_MONOTONIC,CLOCK_MONOTONIC_RAW,CLOCK_MONOTONIC_COARSE,CLOCK_BOOTTIME};
    for (unsigned i=0;i<sizeof ids/sizeof *ids;i++) {
        struct timespec a,b,c,d;
        CHECK(!syscall(SYS_clock_gettime,ids[i],&a));
        CHECK(!direct(ids[i],&b) && !clock_gettime(ids[i],&c));
        CHECK(!syscall(SYS_clock_gettime,ids[i],&d));
        CHECK(ns(a)<=ns(b) && ns(b)<=ns(c) && ns(c)<=ns(d));
    }
    struct timespec previous={0},t;
    for (int i=0;i<100000;i++) {
        CHECK(!direct(CLOCK_MONOTONIC,&t) && ns(t)>=ns(previous)); previous=t;
        CHECK(!clock_gettime(CLOCK_MONOTONIC,&t) && ns(t)>=ns(previous)); previous=t;
    }
    // Normal anonymous mappings must not replace the vDSO page.
    void *space=mmap(NULL,16*1024*1024,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    CHECK(space!=MAP_FAILED && !((uintptr_t)space<=base && base<(uintptr_t)space+16*1024*1024));
    CHECK(!direct(CLOCK_MONOTONIC,&t)); CHECK(!munmap(space,16*1024*1024));
    // Direct stores must retain full-width pointers, including a page split.
    unsigned char *high=mmap((void *)0x500020000000UL,8192,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    CHECK(high==(void *)0x500020000000UL);
    struct timespec *split=(void *)(high+4096-8);
    CHECK(!direct(CLOCK_MONOTONIC,split) && ns(*split)>=ns(previous));
    CHECK(!clock_gettime(CLOCK_MONOTONIC,split) && ns(*split)>=ns(previous));
    CHECK(!munmap(high,8192));
    // Unsupported fast-path clocks must retain syscall results and errno.
    CHECK(!direct(CLOCK_REALTIME,&t) && !clock_gettime(CLOCK_REALTIME,&t));
    CHECK(!direct(CLOCK_REALTIME_COARSE,&t) && !clock_gettime(CLOCK_REALTIME_COARSE,&t));
    CHECK(direct(-123,&t)==-EINVAL);
    errno=0; CHECK(clock_gettime(-123,&t)==-1 && errno==EINVAL);
    pid_t child=fork(); CHECK(child>=0);
    if (!child) {
        CHECK(!direct(CLOCK_MONOTONIC,&t));
        *(volatile unsigned char *)base=0; // must fault: vDSO is read-only
        _exit(2);
    }
    int status; CHECK(waitpid(child,&status,0)==child && WIFSIGNALED(status) && WTERMSIG(status)==SIGSEGV);
    child=fork(); CHECK(child>=0);
    if (!child) { execl("/probe","/probe","--exec",NULL); _exit(3); }
    CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    fprintf(stderr,"VDSO_PASS: libc/direct clocks, fallback, fork/exec, read-only mapping\n");
    usleep(1000000);
    return 0;
}
