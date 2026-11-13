/* Check timestamp ABI layouts against independently prepared filesystem times. */
#include <asm/unistd.h>
typedef unsigned long word;
#ifdef __x86_64__
#define STAT __NR_stat
#define LSTAT __NR_lstat
#define FSTAT __NR_fstat
#define FSTATAT __NR_newfstatat
#define MTIME_OFFSET 88
#else
#define STAT __NR_stat64
#define LSTAT __NR_lstat64
#define FSTAT __NR_fstat64
#define FSTATAT __NR_fstatat64
#define MTIME_OFFSET 72
#endif
static long invoke(word nr,word a,word b,word c,word d,word e) {
 long result;
#ifdef __x86_64__
 register word fourth __asm__("r10")=d;
 register word fifth __asm__("r8")=e;
 __asm__ volatile("syscall":"=a"(result):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(fourth),"r"(fifth):"rcx","r11","memory");
#else
 __asm__ volatile("int $0x80":"=a"(result):"a"(nr),"b"(a),"c"(b),"d"(c),"S"(d),"D"(e):"memory");
#endif
 return result;
}
static void check(int ok,int code) {
 if(!ok){invoke(__NR_exit,code,0,0,0,0);for(;;){}}
}
static unsigned long long value(const unsigned char *p) {
 unsigned long long v=0;for(int i=0;i<8;i++)v|=(unsigned long long)p[i]<<(i*8);return v;
}
static unsigned char result[256];
#define HOME "/home/retroos/"
static void path_stat(const char *path,unsigned long expected) {
 check(invoke(STAT,(word)path,(word)result,0,0,0)==0,10);
 check(value(result+MTIME_OFFSET)==expected,11);
}
__attribute__((force_align_arg_pointer)) void _start(void) {
 path_stat(HOME "stamps/file",1700000002);
 path_stat(HOME "long-" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/long-" "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/long-" "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc/file",1700000008);
 path_stat(HOME "stamps",1700000004);
 /* Filesystems without xattr support report EOPNOTSUPP, not ENOSYS. */
 check(invoke(__NR_listxattr,(word)HOME "stamps",0,0,0,0)==-95,54);
 check(invoke(__NR_llistxattr,(word)HOME "stamps/file",0,0,0,0)==-95,55);
 check(invoke(__NR_listxattr,(word)HOME "missing",0,0,0,0)==-2,56);
 check(invoke(__NR_flistxattr,-1,0,0,0,0)==-9,57);
#ifndef SMB
 path_stat(HOME "stamps/link",1700000002);
 check(invoke(LSTAT,(word)HOME "stamps/link",(word)result,0,0,0)==0,12);
 check(value(result+MTIME_OFFSET)==1700000006,13);
#endif
 long fd=invoke(__NR_open,(word)HOME "stamps/file",0,0,0,0);check(fd>=0,14);
 check(invoke(__NR_dup3,fd,60,0x80000,0,0)==60,58);
 check(invoke(__NR_fcntl,60,1,0,0,0)==1,59);
 check(invoke(__NR_dup3,fd,fd,0,0,0)==-22,60);
 check(invoke(__NR_close,60,0,0,0,0)==0,61);
#ifdef __x86_64__
 check(invoke(__NR_lseek,fd,0x82000000UL,0,0,0)==0x82000000L,63);
#else
 check(invoke(__NR__llseek,fd,0,0x82000000UL,(word)result,0)==0,63);
 check(value(result)==0x82000000ULL,64);
#endif
 check(invoke(__NR_lseek,fd,0,0,0,0)==0,65);
 check(invoke(__NR_flistxattr,fd,0,0,0,0)==-95,62);
 check(invoke(FSTAT,fd,(word)result,0,0,0)==0,15);
 check(value(result+MTIME_OFFSET)==1700000002,16);
 check(invoke(FSTATAT,fd,(word)"",(word)result,0x1000,0)==0,17);
 check(value(result+MTIME_OFFSET)==1700000002,18);
 check(invoke(__NR_statx,fd,(word)"",0x1000,0x7ff,(word)result)==0,19);
 check(value(result+112)==1700000002 && (result[0]&0x40),20);
 check(!(result[0]&0xa0),21); /* Do not advertise unavailable atime/ctime. */
#ifndef __x86_64__
 check(invoke(__NR_fstat,fd,(word)result,0,0,0)==0,22);
 check(value(result+40)==1700000002,23);
#endif
 invoke(__NR_close,fd,0,0,0,0);
 long dir=invoke(__NR_open,(word)HOME "stamps",0x10000,0,0,0);check(dir>=0,24);
 check(invoke(FSTAT,dir,(word)result,0,0,0)==0,25);
 check(value(result+MTIME_OFFSET)==1700000004,26);
 check(invoke(FSTATAT,dir,(word)"file",(word)result,0,0)==0,27);
 check(value(result+MTIME_OFFSET)==1700000002,28);
 check(invoke(__NR_statx,dir,(word)"",0x1000,0x7ff,(word)result)==0,29);
 check(value(result+112)==1700000004,30);
 invoke(__NR_close,dir,0,0,0,0);
 /* Update each field independently, preserving UTIME_OMIT and fd semantics. */
 struct { long seconds, nanos; } times[2]={{0,1073741822},{1700000010,123456789}};
 check(invoke(__NR_utimensat,-100,(word)HOME "stamps/file",(word)times,0,0)==0,40);
 path_stat(HOME "stamps/file",1700000010);
 times[0].seconds=1700000011;times[0].nanos=0;times[1].nanos=1073741822;
 fd=invoke(__NR_open,(word)HOME "stamps/file",0,0,0,0);check(fd>=0,41);
 check(invoke(__NR_utimensat,fd,0,(word)times,0,0)==0,42);
 check(invoke(FSTAT,fd,(word)result,0,0,0)==0,43);
 check(value(result+MTIME_OFFSET)==1700000010,44);
 invoke(__NR_close,fd,0,0,0,0);
 times[0].nanos=1073741822;times[1].nanos=1000000000;
 check(invoke(__NR_utimensat,-100,(word)HOME "stamps/file",(word)times,0,0)==-22,45);
 times[1].seconds=1700000012;times[1].nanos=0;
 check(invoke(__NR_utimensat,-100,(word)HOME "stamps",(word)times,0,0)==0,46);
 path_stat(HOME "stamps",1700000012);
#ifndef SMB
 times[1].seconds=1700000014;
 check(invoke(__NR_utimensat,-100,(word)HOME "stamps/link",(word)times,0x100,0)==0,47);
 check(invoke(LSTAT,(word)HOME "stamps/link",(word)result,0,0,0)==0,48);
 check(value(result+MTIME_OFFSET)==1700000014,49);
 path_stat(HOME "stamps/link",1700000010);
#endif
#ifndef __x86_64__
 struct { long long seconds,nanos; } wide[2]={{0,1073741822},{1700000016,0}};
 check(invoke(__NR_utimensat_time64,-100,(word)HOME "stamps/file",(word)wide,0,0)==0,50);
 path_stat(HOME "stamps/file",1700000016);
#endif
 /* tar restores mode before timestamps: the owner of a 0444 file may utime. */
 check(invoke(__NR_chmod,(word)HOME "stamps/file",0444,0,0,0)==0,52);
 times[0].nanos=1073741822;times[1].nanos=0;
#ifdef __x86_64__
 times[1].seconds=1700000010;
#else
 times[1].seconds=1700000016;
#endif
 check(invoke(__NR_utimensat,-100,(word)HOME "stamps/file",(word)times,0,0)==0,53);
 path_stat(HOME "stamps/file",times[1].seconds);
 times[0].nanos=1073741822;times[1].nanos=1073741822;
 check(invoke(__NR_utimensat,-100,(word)HOME "missing",(word)times,0,0)==0,51);

 /* Exercise the native create and flagged chmod syscall numbers on both ABIs. */
 fd=invoke(__NR_creat,(word)HOME "created",0600,0,0,0);check(fd>=0,66);
 check(invoke(452,fd,(word)"",0644,0x1000,0)==0,67);
 check(invoke(452,-100,(word)HOME "created",0600,0x200,0)==-22,68);
#ifndef SMB
 check(invoke(452,-100,(word)HOME "stamps/link",0600,0x100,0)==-95,69);
#endif
 check(invoke(__NR_close,fd,0,0,0,0)==0,70);
 check(invoke(__NR_unlink,(word)HOME "created",0,0,0,0)==0,71);

 invoke(__NR_write,1,(word)"TIMESTAMPS PASS\n",16,0,0);
 invoke(__NR_exit,0,0,0,0,0);for(;;){}
}
