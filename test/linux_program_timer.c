/* Monotonic child-process timing, independent of gettimeofday resolution. */
#include <asm/unistd.h>
typedef unsigned long word;
static long call(word n,word a,word b,word c,word d) {
 register word fourth __asm__("r10")=d;long r;
 __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c),"r"(fourth):"rcx","r11","memory");return r;
}
static unsigned long long now(void) {
 long t[2];if(call(__NR_clock_gettime,1,(word)t,0,0))return 0;
 return (unsigned long long)t[0]*1000000000+t[1];
}
static void gate(const char *tag,const char *label) {
 char text[128];word n=0;
 for(const char *s=tag;*s;s++)text[n++]=*s;
 for(const char *s=label;*s&&n<120;s++)text[n++]=*s;
 text[n++]='\n';call(__NR_write,2,(word)text,n,0);
 char byte;call(__NR_read,0,(word)&byte,1,0);
}
int probe_main(long argc,char **argv,char **envp) {
 int profile=argc>3&&argv[1][0]=='-'&&argv[1][1]=='-';
 if(profile){argc--;argv++;}
 if(argc<3)return 125;
 if(profile)gate("PROFILE_READY ",argv[1]);
 unsigned long long start=now();long child=call(__NR_fork,0,0,0,0);
 if(child<0)return 125;
 if(!child){call(__NR_execve,(word)argv[2],(word)(argv+2),(word)envp,0);return 127;}
 int status=0;if(call(__NR_wait4,child,(word)&status,0,0)!=child)return 125;
 unsigned long long ms=now()-start;
 if(!profile)ms/=1000000;
 char line[128],digits[24];word n=0,count=0;
 if(profile)for(char *s="PROFILE_DONE ";*s;s++)line[n++]=*s;
 for(char *s=argv[1];*s && n<80;s++)line[n++]=*s;
 line[n++]=' ';
 do{digits[count++]='0'+ms%10;ms/=10;}while(ms);
 while(count)line[n++]=digits[--count];line[n++]=profile?'n':'m';line[n++]='s';line[n++]='\n';
 if(profile){
  call(__NR_write,2,(word)line,n,0);gate("PROFILE_HOLD ",argv[1]);
  return status&127 ? 128+(status&127) : (status>>8)&255;
 }
 long fd=call(__NR_open,(word)"/home/retroos/timings",65,0600,0);
 if(fd<0)return 125;
 if(call(__NR_lseek,fd,0,2,0)<0 || call(__NR_write,fd,(word)line,n,0)!=(long)n)return 125;
 call(__NR_close,fd,0,0,0);
 return status&127 ? 128+(status&127) : (status>>8)&255;
}
__asm__(".global _start\n_start:\n"
 "xor %ebp,%ebp\nmov (%rsp),%rdi\nlea 8(%rsp),%rsi\nlea 16(%rsp,%rdi,8),%rdx\n"
 "call probe_main\nmov %eax,%edi\nmov $60,%eax\nsyscall\nud2\n");
