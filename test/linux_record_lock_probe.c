/* POSIX byte-range locks across processes: both Linux ABI layouts and waits. */
typedef unsigned long word;
#ifdef __x86_64__
#define OPEN 2
#define READ 0
#define WRITE 1
#define CLOSE 3
#define FCNTL 72
#define PWRITE 18
#define FSYNC 74
#define PIPE 22
#define FORK 57
#define WAIT 61
#define EXIT 60
#define GETLK 5
#define SETLK 6
#define SETLKW 7
struct lock { short type,whence; long long start,len; int pid; };
#else
#define OPEN 5
#define READ 3
#define WRITE 4
#define CLOSE 6
#define FCNTL 221
#define PWRITE 181
#define FSYNC 118
#define PIPE 42
#define FORK 2
#define WAIT 114
#define EXIT 1
#define GETLK 12
#define SETLK 13
#define SETLKW 14
struct lock { short type,whence; long long start,len; int pid; } __attribute__((packed));
#endif
static long call(word nr,word a,word b,word c) {
 long result;
#ifdef __x86_64__
 __asm__ volatile("syscall":"=a"(result):"a"(nr),"D"(a),"S"(b),"d"(c):"rcx","r11","memory");
#else
 __asm__ volatile("int $0x80":"=a"(result):"a"(nr),"b"(a),"c"(b),"d"(c):"memory");
#endif
 return result;
}
static long positioned(word nr,word a,word b,word c,word d) {
 long result;
#ifdef __x86_64__
 register word fourth __asm__("r10")=d;
 __asm__ volatile("syscall":"=a"(result):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(fourth):"rcx","r11","memory");
#else
 __asm__ volatile("int $0x80":"=a"(result):"a"(nr),"b"(a),"c"(b),"d"(c),"S"(d),"D"(0):"memory");
#endif
 return result;
}
static void check(int okay,int code) {if(!okay){call(EXIT,code,0,0);for(;;){}}}
void __attribute__((force_align_arg_pointer)) _start(void) {
 long fd=call(OPEN,(word)"/lockfile",2,0);check(fd>=0,10);
 char next;
 check(call(READ,fd,(word)&next,1)==1 && next=='l',40);
 check(positioned(PWRITE,fd,(word)"X",1,5)==1,41);
 check(call(READ,fd,(word)&next,1)==1 && next=='o',42);
 long directory=call(OPEN,(word)"/home/retroos",65536,0);check(directory>=0,43);
 check(call(FSYNC,directory,0,0)==0,44);call(CLOSE,directory,0,0);
 struct lock lock={1,0,10,20,0};
 check(call(FCNTL,fd,SETLK,(word)&lock)==0,11);
 int notify[2];check(call(PIPE,(word)notify,0,0)==0,12);
 long child=call(FORK,0,0,0);check(child>=0,13);
 if(child==0){
  call(CLOSE,notify[0],0,0);
  struct lock conflict={1,0,20,1,0};
  check(call(FCNTL,fd,GETLK,(word)&conflict)==0,20);
  check(conflict.type==1 && conflict.start==10 && conflict.len==20 && conflict.pid==1,21);
  conflict=(struct lock){1,0,20,1,0};
  check(call(FCNTL,fd,SETLK,(word)&conflict)==-11,22);
  char byte=1;check(call(WRITE,notify[1],(word)&byte,1)==1,23);
  check(call(FCNTL,fd,SETLKW,(word)&conflict)==0,24);
  call(EXIT,0,0,0);for(;;){}
 }
 call(CLOSE,notify[1],0,0);char byte;
 check(call(READ,notify[0],(word)&byte,1)==1,30);
 lock=(struct lock){2,0,20,1,0};check(call(FCNTL,fd,SETLK,(word)&lock)==0,31);
 int status=-1;check(call(WAIT,child,(word)&status,0)==child && status==0,32);
 /* Negative lengths, SEEK_CUR, EOF ranges and offsets beyond 4 GiB. */
 lock=(struct lock){1,0,((long long)1<<40)+20,-10,0};
 check(call(FCNTL,fd,SETLK,(word)&lock)==0,33);
 lock=(struct lock){2,0,(long long)1<<40,0,0};
 check(call(FCNTL,fd,SETLK,(word)&lock)==0,34);
 lock=(struct lock){1,0,-1,1,0};check(call(FCNTL,fd,SETLK,(word)&lock)==-22,35);
 call(CLOSE,fd,0,0);
 long ro=call(OPEN,(word)"/lockfile",0,0);check(ro>=0,36);
 lock=(struct lock){1,0,0,0,0};check(call(FCNTL,ro,SETLK,(word)&lock)==-9,37);
 lock.type=0;check(call(FCNTL,ro,SETLK,(word)&lock)==0,38);
 call(CLOSE,ro,0,0);
 call(WRITE,2,(word)"RECORD LOCK PASS\n",17);call(EXIT,0,0,0);for(;;){}
}
