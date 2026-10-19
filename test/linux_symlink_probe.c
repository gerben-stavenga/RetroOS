/* Native filesystem/descriptor ABIs and canonical executable paths. */
#include <asm/unistd.h>
typedef unsigned long word;
#ifdef __x86_64__
#define OPEN 2
#define READ 0
#define WRITE 1
#define CLOSE 3
#define LINK 88
#define LINKAT __NR_symlinkat
#define READLINK 89
#define EXIT 60
#define EXEC 59
#define DUP2 33
#define DUP 32
#define FCNTL 72
#define RENAMEAT 264
static long call(word nr, word a, word b, word c) {
 long r; __asm__ volatile("syscall":"=a"(r):"a"(nr),"D"(a),"S"(b),"d"(c):"rcx","r11","memory");return r;
}
#else
#define OPEN 5
#define READ 3
#define WRITE 4
#define CLOSE 6
#define LINK 83
#define LINKAT __NR_symlinkat
#define READLINK 85
#define EXIT 1
#define DUP 41
#define FCNTL 55
#define RENAMEAT 302
static long call(word nr, word a, word b, word c) {
 long r; __asm__ volatile("int $0x80":"=a"(r):"a"(nr),"b"(a),"c"(b),"d"(c):"memory");return r;
}
#endif
static long call4(word nr,word a,word b,word c,word d) {
 long r;
#ifdef __x86_64__
 register word fourth __asm__("r10")=d;
 __asm__ volatile("syscall":"=a"(r):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(fourth):"rcx","r11","memory");
#else
 __asm__ volatile("int $0x80":"=a"(r):"a"(nr),"b"(a),"c"(b),"d"(c),"S"(d):"memory");
#endif
 return r;
}
static void check(int ok,int code) { if (!ok) {call(EXIT,code,0,0);for(;;){}} }
#ifdef CODEX
void _start(void) {
 long fd=call(OPEN,(word)"/home/retroos/codex.out",577,0600);
 check(fd>=0,50);
check(call(DUP2,fd,1,0)==1,51);
 check(call(DUP2,fd,2,0)==2,52);
 call(CLOSE,fd,0,0);
 static char *args[]={"codex","--version",0};
 static char *env[]={"HOME=/home/retroos","PATH=/home/retroos/bin:/bin","TERM=linux",0};
 call(EXEC,(word)"/home/retroos/bin/codex",(word)args,(word)env);
 check(0,53);
}
#else
#define HOME "/home/retroos/"
#define LONG_TARGET "directory-with-a-name-long-enough-to-require-a-block-backed-symbolic-link/target"
static void contents(const char *path) {
 char bytes[6];long fd=call(OPEN,(word)path,0,0);check(fd>=0,30);
 check(call(READ,fd,(word)bytes,6)==6,31);call(CLOSE,fd,0,0);
 check(bytes[0]=='L' && bytes[5]=='K',32);
}
void _start(void) {
#ifdef VERIFY_SMB
 contents(HOME "relative");
 contents(HOME "absolute");
 contents(HOME "long");
 char target[16];
 check(call(READLINK,(word)HOME "relative",(word)target,sizeof(target))==6,90);
 check(target[0]=='t' && target[5]=='t',91);
 check(call(OPEN,(word)HOME "dangling",0,0)==-2,92);
 call(WRITE,2,(word)"SMB REBOOT PASS\n",16);call(EXIT,0,0,0);for(;;){}
#endif
 char executable[128];
#ifdef SMB
 check(call(READLINK,(word)"/proc/self/exe",(word)executable,sizeof(executable))==19,84);
 check(executable[0]=='/' && executable[6]=='r' && executable[18]=='e',85);
#else
 check(call(READLINK,(word)"/proc/self/exe",(word)executable,sizeof(executable))==6,84);
 check(executable[0]=='/' && executable[1]=='p' && executable[5]=='e',85);
#endif
 check(call(LINK,(word)"target",(word)HOME "relative",0)==0,10);
 contents(HOME "relative");
 check(call(LINK,(word)HOME "target",(word)HOME "absolute",0)==0,11);
 contents(HOME "absolute");
 check(call(LINK,(word)LONG_TARGET,(word)HOME "long",0)==0,12);
 contents(HOME "long");
 check(call(LINK,(word)"missing",(word)HOME "dangling",0)==0,13);
 check(call(LINK,(word)"target",(word)HOME "dangling",0)==-17,14);
 check(call(OPEN,(word)HOME "dangling",0,0)==-2,15);
 char text[16];for(int i=0;i<16;i++)text[i]=85;
 check(call(READLINK,(word)HOME "relative",(word)text,3)==3,16);
 check(text[0]=='t' && text[2]=='r' && text[3]==85,17);
 long dir=call(OPEN,(word)"/home/retroos",65536,0);check(dir>=0,18);
 check(call(LINKAT,(word)"target",dir,(word)"at")==0,19);
 contents(HOME "at");call(CLOSE,dir,0,0);
 check(call(LINKAT,(word)"target",(word)-9,(word)"bad")==-9,20);
 check(call(LINKAT,(word)"target",(word)-9,(word)HOME "at-absolute")==0,21);
 check(call(LINK,(word)"",(word)HOME "empty",0)==-2,22);
 char boundary[61];for(int i=0;i<60;i++)boundary[i]='x';boundary[60]=0;
 check(call(LINK,(word)boundary,(word)HOME "boundary60",0)==0,23);
 boundary[59]=0;check(call(LINK,(word)boundary,(word)HOME "boundary59",0)==0,24);

 /* dup retains the same offset and survives closing the original. */
 long original=call(OPEN,(word)HOME "target",0,0);check(original>=0,60);
 check(call(FCNTL,original,2,1)==0,61);
 long copy=call(DUP,original,0,0);check(copy>=0 && copy!=original,62);
 check(call(FCNTL,copy,1,0)==0,63);
 char byte;check(call(READ,original,(word)&byte,1)==1 && byte=='L',64);
 check(call(READ,copy,(word)&byte,1)==1 && byte=='I',65);
 call(CLOSE,original,0,0);
 check(call(READ,copy,(word)&byte,1)==1 && byte=='N',66);
 call(CLOSE,copy,0,0);check(call(DUP,999,0,0)==-9,67);
 /* renameat uses separate source/destination directory bases. */
 original=call(OPEN,(word)HOME,65536,0);check(original>=0,70);
 dir=call(DUP,original,0,0);check(dir>=0 && dir!=original,86);
 call(CLOSE,original,0,0);
 long subdir=call(OPEN,(word)HOME "directory-with-a-name-long-enough-to-require-a-block-backed-symbolic-link",65536,0);check(subdir>=0,71);
 check(call4(RENAMEAT,dir,(word)"target",subdir,(word)"moved")==0,72);
 contents(HOME "directory-with-a-name-long-enough-to-require-a-block-backed-symbolic-link/moved");
 check(call4(RENAMEAT,(word)-9,(word)"bad",dir,(word)"bad")==-9,73);
 check(call4(RENAMEAT,dir,(word)"",dir,(word)"bad")==-2,74);
 check(call4(RENAMEAT,(word)-9,(word)HOME "directory-with-a-name-long-enough-to-require-a-block-backed-symbolic-link/moved",(word)-9,(word)HOME "target")==0,75);
 contents(HOME "target");call(CLOSE,dir,0,0);call(CLOSE,subdir,0,0);
#ifdef __x86_64__
 /* Virtual eventfds must duplicate their shared counter as well. */
 long event=call(290,3,0x80000,0);check(event>=0,80);
 copy=call(DUP,event,0,0);check(copy>=0 && copy!=event,81);
 check(call(FCNTL,copy,1,0)==0,82);call(CLOSE,event,0,0);
 unsigned long long count=0;
 check(call(READ,copy,(word)&count,8)==8 && count==3,83);
 call(CLOSE,copy,0,0);
#endif

 call(WRITE,2,(word)"SYMLINK PASS\n",13);call(EXIT,0,0,0);for(;;){}
}
#endif
