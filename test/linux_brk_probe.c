#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#define CHECK(ok) do { if (!(ok)) { dprintf(2,"BRK_FAIL line=%d errno=%d\n",__LINE__,errno);_exit(1); } } while (0)
static unsigned long brk_at(unsigned long address) { return syscall(SYS_brk,address); }
int main(void) {
    unsigned long old=brk_at(0), base=(old+4095)&~4095UL;
    CHECK(brk_at(base+3*4096)==base+3*4096);
    volatile uint64_t *live=(void *)(base+4096);
    *live=0x123456789abcdef0UL;
    CHECK(mmap((void *)base,4096,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)==(void *)base);
    CHECK(brk_at(base+4*4096)==base+4*4096);
    CHECK(*live==0x123456789abcdef0UL);
    CHECK(mmap((void *)(base+6*4096),4096,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)==(void *)(base+6*4096));
    CHECK(brk_at(base+8*4096)==base+4*4096);
    CHECK(brk_at(0)==base+4*4096 && *live==0x123456789abcdef0UL);
    CHECK(brk_at(0x500020000000UL)==base+4*4096);
    CHECK(brk_at(1)==base+4*4096);
    volatile unsigned char *released=(void *)(base+3*4096);
    for (unsigned i=0;i<4096;i++) released[i]=0xa5;
    CHECK(brk_at(base+2*4096)==base+2*4096);
    CHECK(brk_at(0)==base+2*4096 && *live==0x123456789abcdef0UL);
    CHECK(brk_at(base+4*4096)==base+4*4096);
    for (unsigned i=0;i<4096;i++) CHECK(released[i]==0);
    static const char pass[]="BRK_PASS: internal guard, growth, collision preserves heap, full-width rejection and shrink\n";
    CHECK(write(2,pass,sizeof pass-1)==sizeof pass-1);
    _exit(0);
}
