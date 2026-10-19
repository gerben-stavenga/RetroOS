/* Direct Linux syscalls and genuine CALLs to each fixed x86-64 entry. */
#include <asm/unistd.h>
#include <linux/sysinfo.h>
typedef unsigned long word;
static long invoke(word nr,word a,word b,word c) {
 long result;
#ifdef __x86_64__
 __asm__ volatile("syscall":"=a"(result):"a"(nr),"D"(a),"S"(b),"d"(c):"rcx","r11","memory");
#else
 __asm__ volatile("int $0x80":"=a"(result):"a"(nr),"b"(a),"c"(b),"d"(c):"memory");
#endif
 return result;
}
static long invoke4(word nr,word a,word b,word c,word d) {
 long result;
#ifdef __x86_64__
 register word fourth __asm__("r10")=d;
 __asm__ volatile("syscall":"=a"(result):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(fourth):"rcx","r11","memory");
#else
 __asm__ volatile("int $0x80":"=a"(result):"a"(nr),"b"(a),"c"(b),"d"(c),"S"(d):"memory");
#endif
 return result;
}
static void check(int ok,int code) {
 if(!ok){invoke(__NR_exit,code,0,0);for(;;){}}
}
#ifdef __x86_64__
typedef long (*gate)(void *,void *,void *);
static long fixed_map(word base,word length) {
 long result;
 register word flags __asm__("r10")=0x32;
 register word fd __asm__("r8")=(word)-1;
 register word offset __asm__("r9")=0;
 __asm__ volatile("syscall":"=a"(result):"a"(__NR_mmap),"D"(base),"S"(length),"d"(3UL),"r"(flags),"r"(fd),"r"(offset):"rcx","r11","memory");
 return result;
}
#define GETCPU ((gate)0xffffffffff600800UL)
#define TIME ((gate)0xffffffffff600400UL)
#define GETTIMEOFDAY ((gate)0xffffffffff600000UL)
#endif
__attribute__((force_align_arg_pointer)) void _start(void) {
#ifdef BAD_ENTRY
 ((gate)0xffffffffff600801UL)(0,0,0);
 check(0,70);
#elif defined(BAD_OUTPUT)
 GETCPU((void *)0xc0000000UL,0,0);
 check(0,71);
#elif defined(READ_GATE)
 volatile word value=*(volatile word *)0xffffffffff600800UL;
 check(value==123,72);
#else
 unsigned long long limits[2]={0,0};
 check(invoke4(__NR_prlimit64,0,9,0,(word)limits)==0,40);
 check(limits[0]==~0ULL && limits[1]==~0ULL,41);
 check(invoke4(__NR_prlimit64,0,3,0,(word)limits)==0 && limits[0]>0,42);
 check(invoke4(__NR_prlimit64,0,9,(word)limits,0)==0,43);
 limits[0]=1;limits[1]=2;
 check(invoke4(__NR_prlimit64,0,9,(word)limits,0)==-95,44);
 check(invoke4(__NR_prlimit64,0,16,0,(word)limits)==-22,45);
 check(invoke4(__NR_prlimit64,0,9,0,0xbfffffffUL)==-14,46);
 struct sysinfo info;
 check(invoke(__NR_sysinfo,(word)&info,0,0)==0,30);
 unsigned long long total=(unsigned long long)info.totalram*info.mem_unit;
 unsigned long long free=(unsigned long long)info.freeram*info.mem_unit;
 check(total>=128UL*1024*1024 && total<=256UL*1024*1024,31);
 check(free>0 && free<=total && info.procs>=1 && info.uptime>=0,32);
 check(invoke(__NR_sysinfo,0,0,0)==-14,33);
 check(invoke(__NR_sysinfo,0xbfffffffUL,0,0)==-14,34);
 unsigned cpu=99,node=99;
 check(invoke(__NR_getcpu,(word)&cpu,(word)&node,(word)-1)==0,10);
 check(cpu==0 && node==0,11);
 check(invoke(__NR_getcpu,0,0,0)==0,12);
 cpu=99;
 check(invoke(__NR_getcpu,(word)&cpu,0xc0000000UL,0)==-14,13);
 check(cpu==99,14);
 check(invoke(__NR_getcpu,0xbfffffffUL,0,0)==-14,15);
#ifdef __x86_64__
 /* Register a Linux thread context, then map the former idle-stub address.
    Blocking must not require a hidden executable page in user memory. */
 check(invoke(__NR_prctl,15,(word)"mapping-probe",0)==0,49);
 check(fixed_map(0x7ff60000UL,4096)==0x7ff60000UL,50);
 *(volatile word *)0x7ff60000UL=0xdeadbeef;
 check(fixed_map(0x7ff60000UL,4096)==0x7ff60000UL,51);
 check(*(volatile word *)0x7ff60000UL==0,54);
 check(fixed_map(0x100000000UL,4096)==-12,52);
 check(fixed_map(0x40000000UL,(word)-1)==-12,53);
 /* Reserving a gigabyte in this 256 MiB guest must stay demand-zero. */
 check(invoke(__NR_sysinfo,(word)&info,0,0)==0,55);
 word free_before=info.freeram;
 check(fixed_map(0x50000000UL,0x40000000UL)==0x50000000UL,56);
 check(invoke(__NR_sysinfo,(word)&info,0,0)==0,57);
 check(info.freeram+1024>=free_before,58);
 check(*(volatile word *)0x50000000UL==0,59);
 check(*(volatile word *)0x8ffffff8UL==0,60);
 *(volatile word *)0x50000000UL=123;
 check(*(volatile word *)0x50000000UL==123,61);
 check(invoke(__NR_munmap,0x50000000UL,0x40000000UL,0)==0,62);
 cpu=99;node=99;
 check(GETCPU(&cpu,&node,(void *)-1)==0,20);
 check(cpu==0 && node==0,21);
 check(GETCPU(0,0,0)==0,22);
 long seconds=0;
 long now=TIME(&seconds,0,0);
 check(now>1700000000 && seconds==now,23);
 check(TIME(0,0,0)>=now,24);
 struct { long seconds,micros; } tv={0,99};
 int timezone[2]={99,99};
 check(GETTIMEOFDAY(&tv,timezone,0)==0,25);
 check(tv.seconds>=now && tv.seconds-now<3 && tv.micros==0,26);
 check(timezone[0]==0 && timezone[1]==0,27);
 check(GETTIMEOFDAY(0,0,0)==0,28);
#endif
 invoke(__NR_write,1,(word)"VSYSCALL PASS\n",14);
 invoke(__NR_exit,0,0,0);for(;;){}
#endif
}
