/* Ordinary descriptor capacity, high-bit flags/select, and spawn cleanup. */
#include <asm/unistd.h>
typedef unsigned long word;
static long call(word n,word a,word b,word c,word d,word e) {
 long r;
#ifdef __x86_64__
 register word fourth __asm__("r10")=d,fifth __asm__("r8")=e;
 __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c),"r"(fourth),"r"(fifth):"rcx","r11","memory");
#else
 __asm__ volatile("int $0x80":"=a"(r):"a"(n),"b"(a),"c"(b),"d"(c),"S"(d),"D"(e):"memory");
#endif
 return r;
}
#define C(n,a,b,c,d) call(n,(word)(a),(word)(b),(word)(c),(word)(d),0)
static void check(int ok,int code){if(!ok){C(__NR_exit,code,0,0,0);for(;;){}}}
static unsigned char readset[128],writeset[128];
static long timeout[2];
static unsigned long long limits[2];
__attribute__((force_align_arg_pointer)) void _start(void) {
#ifdef CODE_HOST_PATH
 for(int i=0;i<96;i++)check(C(__NR_open,"/dev/null",0,0,0)>=0,42);
 char *args[]={CODE_HOST_PATH,0};
 char *env[]={"HOME=/home/retroos","TMPDIR=/home/retroos/TEMP",0};
 C(__NR_execve,CODE_HOST_PATH,args,env,0);check(0,43);
#endif
 if(C(__NR_fcntl,963,1,0,0)==0) {
  check(C(__NR_fcntl,80,1,0,0)==0 && C(__NR_fcntl,900,1,0,0)==0,70);
  for(int i=100;i<195;i++)check(C(__NR_fcntl,i,1,0,0)==-9,71);
  check(C(__NR_fcntl,512,1,0,0)==-9 && C(__NR_fcntl,700,1,0,0)==-9,72);
#ifdef __x86_64__
  check(C(__NR_fcntl,1024,1,0,0)==-9,73);
#endif
  check(C(__NR_close_range,3,0xffffffffUL,2,0)==0,74);
  check(C(__NR_open,"/dev/null",0,0,0)==3,75);
  C(__NR_exit,0,0,0,0);for(;;){}
 }
 check(C(__NR_prlimit64,0,7,0,limits)==0 && limits[0]>=1024,1);
 for(int i=3;i<195;i++)check(C(__NR_open,"/dev/null",0,0,0)==i,2);
 check(C(__NR_dup2,3,512,0,0)==512 && C(__NR_fcntl,512,2,1,0)==0,3);
 check(C(__NR_fcntl,3,1030,700,0)==700,4);
 check(C(__NR_dup2,3,900,0,0)==900 && C(__NR_dup2,3,963,0,0)==963,5);
 check(C(__NR_fcntl,0,1,0,0)==0 && C(__NR_fcntl,64,1,0,0)==0,6);
 int pipe[2];check(C(__NR_pipe,pipe,0,0,0)==0,7);
 check(C(__NR_dup2,pipe[0],128,0,0)==128 && C(__NR_dup2,pipe[1],255,0,0)==255,8);
 C(__NR_close,pipe[0],0,0,0);C(__NR_close,pipe[1],0,0,0);
 check(C(__NR_write,255,"x",1,0)==1,9);
 readset[128/8]=1;writeset[255/8]=128;
 check(call(__NR_pselect6,256,(word)readset,(word)writeset,0,(word)timeout)==2,10);
 check(readset[128/8]==1 && writeset[255/8]==128,11);
 /* Enter and resume the parked pselect path with the full descriptor table. */
 timeout[1]=5000000;
 check(call(__NR_pselect6,0,0,0,0,(word)timeout)==0,22);
 timeout[1]=0;
 check(C(__NR_close_range,100,199,4,0)==0 && C(__NR_fcntl,150,1,0,0)==1,12);
#ifdef __x86_64__
 check(C(__NR_eventfd2,0,0,0,0)==1024,13);
 check(C(__NR_close_range,1024,0xffffffffUL,4,0)==0,14);
#endif
 for(int repeat=0;repeat<24;repeat++) {
  long child=C(__NR_fork,0,0,0,0);check(child>=0,15);
  if(!child){char *args[]={"child",0},*env[]={0};C(__NR_execve,"/proc/self/exe",args,env,0);check(0,16);}
  int status=-1;check(C(__NR_wait4,child,&status,0,0)==child && status==0,17);
  check(C(__NR_fcntl,150,1,0,0)==1 && C(__NR_fcntl,900,1,0,0)==0,18);
 }
 check(C(__NR_close_range,10,9,0,0)==-22 && C(__NR_close_range,0,0xffffffffUL,8,0)==-22,19);
 check(C(__NR_close_range,3,0xffffffffUL,0,0)==0 && C(__NR_open,"/dev/null",0,0,0)==3,20);
#ifdef __x86_64__
 check(C(__NR_eventfd2,0,0,0,0)==1024,21);
#endif
 C(__NR_exit,0,0,0,0);for(;;){}
}
