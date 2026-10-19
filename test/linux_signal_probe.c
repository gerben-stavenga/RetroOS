#define _GNU_SOURCE
#include <signal.h>
#include <sys/ucontext.h>
#include <asm/unistd.h>
typedef unsigned long word;
static long call(word n,word a,word b,word c,word d) {
 long result;register word fourth __asm__("r10")=d;
 __asm__ volatile("syscall":"=a"(result):"a"(n),"D"(a),"S"(b),"d"(c),"r"(fourth):"rcx","r11","memory");return result;
}
static void check(int ok,int code){if(!ok){call(__NR_exit_group,code,0,0,0);for(;;){}}}
static unsigned char alt[16384] __attribute__((aligned(16)));
static volatile int called;
extern void fault_site(void), resume_site(void), restorer(void);
__asm__(".text\n.global restorer\nrestorer: mov $15,%eax\nsyscall\nud2\n"
 ".global fault_site,resume_site\n");
static void handler(int sig,siginfo_t *info,void *context) {
 ucontext_t *uc=context;word mask=0;
 check(sig==SIGSEGV && info->si_signo==SIGSEGV && info->si_addr==0,11);
 check((word)&uc>=(word)alt && (word)&uc<(word)alt+sizeof alt,12);
 check(uc->uc_mcontext.gregs[REG_RIP]==(word)fault_site,13);
 check(uc->uc_mcontext.gregs[REG_RAX]==0x12345678,14);
 check(uc->uc_mcontext.fpregs && ((word)uc->uc_mcontext.fpregs&15)==0,15);
 check(call(__NR_rt_sigprocmask,0,0,(word)&mask,8)==0,16);
 check((mask&((1UL<<(SIGSEGV-1))|(1UL<<(SIGUSR1-1))))==((1UL<<(SIGSEGV-1))|(1UL<<(SIGUSR1-1))),17);
 stack_t current;
 check(call(__NR_sigaltstack,0,(word)&current,0,0)==0 && current.ss_flags==SS_ONSTACK,18);
 uc->uc_mcontext.gregs[REG_RIP]=(word)resume_site;
 uc->uc_mcontext.gregs[REG_RAX]=0x87654321;
#ifdef BAD_MXCSR
 uc->uc_mcontext.fpregs->mxcsr=0xffffffff;
#endif
#ifdef BAD_PC
 uc->uc_mcontext.gregs[REG_RIP]=0xc0000000UL;
#endif
 __asm__ volatile("pxor %%xmm15,%%xmm15":::"xmm15");
 called++;
}
struct action {word handler,flags,restorer,mask;};
__attribute__((force_align_arg_pointer)) void _start(void) {
 struct action act={(word)handler,SA_SIGINFO|SA_ONSTACK|0x04000000,(word)restorer,0},old={0};
 stack_t stack={.ss_sp=alt,.ss_size=sizeof alt};
 word mask=1UL<<(SIGUSR1-1),result,simd,redzone;
 check(call(__NR_rt_sigaction,SIGSEGV,(word)&act,(word)&old,8)==0,1);
 check(old.handler==0,2);
 check(call(__NR_rt_sigaction,SIGKILL,(word)&act,0,8)==-22,3);
 check(call(__NR_rt_sigaction,65,0,0,8)==-22,4);
 check(call(__NR_rt_sigaction,SIGSEGV,0,0xbfffffffUL,8)==-14,5);
 check(call(__NR_sigaltstack,(word)&stack,0,0,0)==0,6);
 check(call(__NR_rt_sigprocmask,2,(word)&mask,0,8)==0,7);
 __asm__ volatile("mov $0x12345678,%%eax\nmovq %%rax,%%xmm15\nmov %%rax,-8(%%rsp)\nxor %%edx,%%edx\n"
 "fault_site: mov (%%rdx),%%rdx\nresume_site: movq %%xmm15,%1\nmov -8(%%rsp),%2"
 :"=a"(result),"=r"(simd),"=r"(redzone)::"rdx","xmm15","memory");
 check(called==1 && result==0x87654321 && simd==0x12345678 && redzone==0x12345678,8);
 check(call(__NR_rt_sigprocmask,0,0,(word)&mask,8)==0 && mask==(1UL<<(SIGUSR1-1)),9);
 call(__NR_exit_group,0,0,0,0);for(;;){}
}
