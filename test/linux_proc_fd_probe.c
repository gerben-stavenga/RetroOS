/* A process fd directory must never enumerate the SMB server's host fds. */
#include <asm/unistd.h>
#include <asm/stat.h>
typedef unsigned long word;
typedef struct { word pointer, length; } Iovec;
#ifdef __x86_64__
typedef struct stat Stat;
#define LSTAT __NR_lstat
#define FSTAT __NR_fstat
#define FSTATAT __NR_newfstatat
#else
typedef struct stat64 Stat;
#define LSTAT __NR_lstat64
#define FSTAT __NR_fstat64
#define FSTATAT __NR_fstatat64
#endif
static long call(word n,word a,word b,word c,word d) {
 long r;
#ifdef __x86_64__
 register word fourth __asm__("r10")=d;
 __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c),"r"(fourth):"rcx","r11","memory");
#else
 __asm__ volatile("int $0x80":"=a"(r):"a"(n),"b"(a),"c"(b),"d"(c),"S"(d):"memory");
#endif
 return r;
}
static void check(int ok,int code){if(!ok){call(__NR_exit,code,0,0,0);for(;;){}}}
#ifdef __x86_64__
static long mapping_region(word base,word flags,word file,word protection,word length,word offset){
 long result;register word fourth __asm__("r10")=flags;
 register word fifth __asm__("r8")=file,sixth __asm__("r9")=offset;
 __asm__ volatile("syscall":"=a"(result):"a"(__NR_mmap),"D"(base),"S"(length),"d"(protection),"r"(fourth),"r"(fifth),"r"(sixth):"rcx","r11","memory");
 return result;
}
#else
__attribute__((naked)) static long mapping_region(word base,word flags,word file,word protection,word length,word offset){
 __asm__ volatile("push %ebx; push %esi; push %edi; push %ebp; mov 20(%esp),%ebx; mov 36(%esp),%ecx; mov 32(%esp),%edx; mov 24(%esp),%esi; mov 28(%esp),%edi; mov 40(%esp),%ebp; shr $12,%ebp; mov $192,%eax; int $0x80; pop %ebp; pop %edi; pop %esi; pop %ebx; ret");
}
#endif
static long mapping(word base,word flags,word file,word protection){return mapping_region(base,flags,file,protection,4096,0);}
static unsigned char buffer[96],seen[2048];
static char link[256];
static Stat metadata;
static unsigned char ipc_message[4133];
static void ipc_child(void){
 unsigned char part[97];word total=0;
 while(total<sizeof ipc_message){
  word count=sizeof ipc_message-total;if(count>sizeof part)count=sizeof part;
  word first=count<13?count:13;
  Iovec vectors[]={{(word)part,first},{0,0},{(word)(part+first),count-first}};
  long n=call(__NR_readv,0,(word)vectors,3,0);check(n>0,120);
  for(long i=0;i<n;i++)check(part[i]==(unsigned char)((total+i)*7+5),121);
  total+=n;
 }
 check(call(__NR_write,1,(word)"IPCPASS",7,0)==7,122);
 word delay[2]={0,10000000};check(call(__NR_nanosleep,(word)delay,0,0,0)==0,123);
 call(__NR_exit,17,0,0,0);for(;;){}
}
static void ipc_roundtrips(void){
 for(word i=0;i<sizeof ipc_message;i++)ipc_message[i]=(unsigned char)(i*7+5);
 long previous=0;
 for(int repeat=0;repeat<8;repeat++){
  int input[2],output[2];check(call(__NR_pipe,(word)input,0,0,0)==0,124);
  check(call(__NR_pipe,(word)output,0,0,0)==0,125);
  long child=call(__NR_fork,0,0,0,0);check(child>=0,126);
  if(child==0){
   check(call(__NR_dup2,input[0],0,0,0)==0 && call(__NR_dup2,output[1],1,0,0)==1,127);
   check(call(__NR_dup2,input[0],63,0,0)==63,135);
   call(__NR_close,input[0],0,0,0);call(__NR_close,input[1],0,0,0);
   call(__NR_close,output[0],0,0,0);call(__NR_close,output[1],0,0,0);
   char *args[]={"ipc-child",0},*environment[]={0};
   call(__NR_execve,(word)"/proc/self/exe",(word)args,(word)environment,0);
   check(0,128);
  }
  if(previous)check(child==previous,129);previous=child;
  call(__NR_close,input[0],0,0,0);call(__NR_close,output[1],0,0,0);
  int pending_status=123;
  check(call(__NR_wait4,child,(word)&pending_status,1,0)==0 && pending_status==123,200);
  check(call(__NR_write,input[1],(word)ipc_message,sizeof ipc_message,0)==sizeof ipc_message,130);
  call(__NR_close,input[1],0,0,0);
  unsigned char answer[7];word done=0;
  while(done<sizeof answer){long n=call(__NR_read,output[0],(word)(answer+done),sizeof answer-done,0);check(n>0,131);done+=n;}
  for(word i=0;i<sizeof answer;i++)check(answer[i]=="IPCPASS"[i],132);
  call(__NR_close,output[0],0,0,0);
  int status=123;check(call(__NR_wait4,child,(word)&status,0,0)==child && status==(17<<8),133);
  check(call(__NR_wait4,child,(word)&status,0,0)==-10,134);
 }
}
__attribute__((force_align_arg_pointer)) void _start(void){
 if(call(FSTAT,63,(word)&metadata,0,0)==0)ipc_child();
 check(call(__NR_setpgid,0,0,0,0)==0,195);
 check(call(__NR_getpgrp,0,0,0,0)==call(__NR_getpid,0,0,0,0),196);
 check(call(FSTAT,0,(word)&metadata,0,0)==0 && (metadata.st_mode&0170000)==0020000,116);
 long file=call(__NR_open,(word)"/home/retroos/target",0,0,0);check(file==3,1);
 check(call(__NR_fcntl,file,0,20,0)==20,2);
 long directory=call(__NR_open,(word)"/proc/self/fd",65536,0,0);check(directory==4,3);
 long event=-1;
#ifdef __x86_64__
 event=call(__NR_eventfd2,0,0,0,0);check(event>=1024 && event<2048,4);
#endif
 static const char expected[]="/home/retroos/target";
 check(call(__NR_readlink,(word)"/proc/self/fd/20",(word)link,sizeof link,0)==sizeof expected-1,5);
 for(word i=0;i<sizeof expected-1;i++)check(link[i]==expected[i],6);
 check(call(__NR_readlinkat,directory,(word)"20",(word)link,sizeof link)==sizeof expected-1,7);
 check(call(LSTAT,(word)"/proc/self/fd/20",(word)&metadata,0,0)==0 && (metadata.st_mode&0170000)==0120000,8);
 check(call(FSTATAT,directory,(word)"20",(word)&metadata,0)==0 && (metadata.st_mode&0170000)==0100000 && metadata.st_size==7,9);
 check(call(__NR_getdents64,directory,(word)buffer,1,0)==-22,10);
 check(call(__NR_getdents64,file,(word)buffer,sizeof buffer,0)==-20,22);
 int listed=0;
 for(int rounds=0;rounds<20;rounds++){
  long size=call(__NR_getdents64,directory,(word)buffer,sizeof buffer,0);check(size>=0,11);
  if(size==0)break;
  for(long i=0;i<size;){
   unsigned length=buffer[i+16]|(buffer[i+17]<<8);check(length>=24 && i+length<=size,12);
   if(buffer[i+19]!='.'){
    unsigned fd=0;
    for(unsigned j=19;j<length && buffer[i+j];j++){check(buffer[i+j]>='0' && buffer[i+j]<='9',13);fd=fd*10+buffer[i+j]-'0';}
    check(fd<2048 && !seen[fd],14);seen[fd]=1;listed++;
    check(fd<=4 || fd==20 || (long)fd==event,15);
    check(buffer[i+18]==10,16);
   }
   i+=length;
  }
 }
 check(listed==6+(event>=0),17);
 check(call(__NR_lseek,directory,0,0,0)==0,23);
 check(call(__NR_getdents64,directory,(word)buffer,sizeof buffer,0)>0 && buffer[19]=='.',24);
 for(int fd=0;fd<=4;fd++)check(seen[fd],18);
 check(seen[20],19);
 if(event>=0){check(seen[event],20);call(__NR_close,event,0,0,0);}
 call(__NR_close,20,0,0,0);
 check(call(__NR_readlink,(word)"/proc/self/fd/20",(word)link,sizeof link,0)==-2,21);
 call(__NR_close,directory,0,0,0);call(__NR_close,file,0,0,0);
 int pipes[2],available=99;
 check(call(__NR_pipe,(word)pipes,0,0,0)==0,30);
 check(call(FSTAT,pipes[0],(word)&metadata,0,0)==0 && (metadata.st_mode&0170000)==0010000,113);
 check(call(FSTAT,pipes[1],(word)&metadata,0,0)==0 && (metadata.st_mode&0170000)==0010000,114);
 check(call(FSTAT,2,(word)&metadata,0,0)==0 && (metadata.st_mode&0170000)==0020000,115);
 check(call(__NR_ioctl,pipes[0],0x541b,(word)&available,0)==0 && available==0,31);
 int enabled=1;
 check(call(__NR_ioctl,pipes[0],0x5421,(word)&enabled,0)==0,50);
 check(call(__NR_read,pipes[0],(word)link,1,0)==-11,51);
 int duplicate=call(__NR_dup,pipes[0],0,0,0);check(duplicate>=0,52);
 check((call(__NR_fcntl,duplicate,3,0,0)&0x800)!=0,53);
 enabled=0;check(call(__NR_ioctl,duplicate,0x5421,(word)&enabled,0)==0,54);
 check((call(__NR_fcntl,pipes[0],3,0,0)&0x800)==0,55);
 check(call(__NR_fcntl,duplicate,4,0x800,0)==0,56);
 check((call(__NR_fcntl,pipes[0],3,0,0)&0x800)!=0,57);
 check(call(__NR_ioctl,pipes[0],0x5421,0,0)==-14,58);
 call(__NR_close,duplicate,0,0,0);
 check(call(__NR_write,pipes[1],(word)"abcde",5,0)==5,32);
 check(call(__NR_ioctl,pipes[0],0x541b,(word)&available,0)==0 && available==5,33);
 check(call(__NR_ioctl,pipes[1],0x541b,(word)&available,0)==0 && available==5,34);
 check(call(__NR_read,pipes[0],(word)link,2,0)==2,35);
 check(call(__NR_ioctl,pipes[0],0x541b,(word)&available,0)==0 && available==3,36);
 call(__NR_close,pipes[1],0,0,0);
 check(call(__NR_read,pipes[0],(word)link,sizeof link,0)==3,37);
 check(call(__NR_ioctl,pipes[0],0x541b,(word)&available,0)==0 && available==0,38);
 check(call(__NR_ioctl,pipes[0],0x541b,0,0)==-14,39);
 call(__NR_close,pipes[0],0,0,0);
#ifdef __x86_64__
 for(int type=1;type<=5;type+=4){
  check(call(__NR_socketpair,1,type,0,(word)pipes)==0,40);
  check(call(__NR_write,pipes[0],(word)"ab",2,0)==2,41);
  check(call(__NR_write,pipes[0],(word)"cde",3,0)==3,42);
  check(call(__NR_ioctl,pipes[1],0x541b,(word)&available,0)==0 && available==(type==1?5:2),43);
  check(call(__NR_read,pipes[1],(word)link,1,0)==1,44);
  check(call(__NR_ioctl,pipes[1],0x541b,(word)&available,0)==0 && available==(type==1?4:3),45);
  int remaining=available;
  while(remaining>0){long n=call(__NR_read,pipes[1],(word)link,remaining,0);check(n>0 && n<=remaining,46);remaining-=n;}
  check(call(__NR_ioctl,pipes[1],0x541b,(word)&available,0)==0 && available==0,47);
  enabled=1;check(call(__NR_ioctl,pipes[1],0x5421,(word)&enabled,0)==0,59);
  check(call(__NR_read,pipes[1],(word)link,1,0)==-11,60);
  call(__NR_close,pipes[0],0,0,0);call(__NR_close,pipes[1],0,0,0);
 }
#endif
 int null=call(__NR_open,(word)"/dev/null",0x242,0600,0);check(null>=0,61);
 check(call(__NR_write,null,(word)"discarded",9,0)==9,62);
 check(call(__NR_read,null,(word)link,sizeof link,0)==0,63);
 check(call(__NR_lseek,null,123,0,0)==0,64);
 check(call(LSTAT,(word)"/dev/null",(word)&metadata,0,0)==0 && (metadata.st_mode&0170000)==0020000 && metadata.st_size==0,65);
 check(call(FSTATAT,-100,(word)"/dev/null",(word)&metadata,0)==0 && (metadata.st_mode&0170000)==0020000,66);
 check(call(FSTAT,null,(word)&metadata,0,0)==0 && (metadata.st_mode&0170000)==0020000 && metadata.st_size==0,67);
 call(__NR_close,null,0,0,0);
 int many=call(__NR_open,(word)"/home/retroos/many",0x10000,0,0);check(many>=0,68);
 unsigned char names[300]={0};int total=0;
 for(int rounds=0;rounds<200;rounds++){
  long size=call(__NR_getdents64,many,(word)buffer,sizeof buffer,0);check(size>=0,69);
  if(!size)break;
  for(long i=0;i<size;){
   unsigned length=buffer[i+16]|(buffer[i+17]<<8);check(length>=24 && i+length<=size,70);
   unsigned char *name=buffer+i+19;
   if(name[0]=='.' && (!name[1] || (name[1]=='.' && !name[2]))){i+=length;continue;}
   unsigned number=(name[5]-'0')*100+(name[6]-'0')*10+name[7]-'0';
   check(name[0]=='e' && name[1]=='n' && name[2]=='t' && name[3]=='r' && name[4]=='y' && name[8]==0 && number<300,71);
   check(!names[number],72);names[number]=1;total++;
   i+=length;
  }
 }
 check(total==300,73);call(__NR_close,many,0,0,0);
 int held[48];
 for(int n=0;n<48;n++){held[n]=call(__NR_open,(word)"/home/retroos/many",0x10000,0,0);check(held[n]>=0,74);}
 for(int n=0;n<48;n++){
  check(call(__NR_getdents64,held[n],(word)buffer,sizeof buffer,0)>0,75);
  check(call(FSTAT,held[n],(word)&metadata,0,0)==0 && (metadata.st_mode&0170000)==0040000,76);
  call(__NR_close,held[n],0,0,0);
 }
 /* Private isolation and coherent shared pages across opens, I/O and fork. */
 file=call(__NR_open,(word)"/home/retroos/target",2,0,0);check(file>=0,100);
 Iovec file_vectors[]={{(word)buffer,3},{(word)(buffer+3),4}};
 check(call(__NR_readv,file,(word)file_vectors,2,0)==7,201);
 for(word n=0;n<7;n++)check(buffer[n]==(unsigned char)"PROCFD\n"[n],202);
 check(call(__NR_readv,file,(word)file_vectors,1025,0)==-22,203);
 check(call(__NR_readv,file,(word)-1,1,0)==-14,204);
 check(call(__NR_lseek,file,0,0,0)==0,205);
 word mapped=(word)mapping(0,2,file,3);check(mapped<(word)-4095,101);
 check(call(__NR_madvise,mapped,4096,4,0)==-22 && *(volatile char *)mapped=='P',171);
 check(*(volatile char *)mapped=='P',102);*(volatile char *)mapped='Q';
 check(call(__NR_munmap,mapped,4096,0,0)==0,103);
 check(call(__NR_read,file,(word)link,1,0)==1 && link[0]=='P',104);
 word shared=(word)mapping(0,1,file,3);check(shared<(word)-4095,105);
 long other=call(__NR_open,(word)"/home/retroos/target",2,0,0);check(other>=0,140);
 word alias=(word)mapping(0,3,other,3);check(alias<(word)-4095,141);
 *(volatile char *)shared='S';check(*(volatile char *)alias=='S',142);
 check(call(__NR_lseek,other,0,0,0)==0 && call(__NR_read,other,(word)link,1,0)==1 && link[0]=='S',143);
 check(call(__NR_lseek,other,0,0,0)==0 && call(__NR_write,other,(word)"T",1,0)==1,144);
 check(*(volatile char *)shared=='T' && *(volatile char *)alias=='T',145);
 long child=call(__NR_fork,0,0,0,0);check(child>=0,146);
 if(!child){*(volatile char *)alias='U';call(__NR_exit,17,0,0,0);for(;;){}}
 int shared_status=0;check(call(__NR_wait4,child,(word)&shared_status,0,0)==child && shared_status==(17<<8),147);
 check(*(volatile char *)shared=='U',148);
 call(__NR_close,other,0,0,0);
 *(volatile char *)shared='P';check(call(__NR_msync,alias,4096,4,0)==0,149);
 check(call(__NR_munmap,alias,4096,0,0)==0 && call(__NR_munmap,shared,4096,0,0)==0,150);
 check(mapping(0,1,(word)-9,3)==-9,106);
 mapped=(word)mapping(0,1,file,1);check(mapped<(word)-4095 && *(volatile char *)mapped=='P',107);
 check(call(__NR_munmap,mapped,4096,0,0)==0,111);
 check(call(__NR_read,file,(word)link,1,0)==1 && link[0]=='R',112);
 mapped=0x50000000UL;check((word)mapping(mapped,0x32,(word)-1,3)==mapped,108);
 *(volatile word *)mapped=0x12345678;
 check(mapping(mapped,0x11,(word)-9,3)==-9 && *(volatile word *)mapped==0x12345678,109);
 check(call(__NR_munmap,mapped,4096,0,0)==0,110);call(__NR_close,file,0,0,0);
 /* Overlapping file offsets, partial unmap, fd-close lifetime and writeback. */
 file=call(__NR_open,(word)"/home/retroos/shared-pages",578,0600,0);check(file>=0,151);
 check(call(__NR_ftruncate,file,12288,0,0)==0,152);
 mapped=(word)mapping_region(0,1,file,3,12288,0);check(mapped<(word)-4095,153);
 alias=(word)mapping_region(0,1,file,3,4096,4096);check(alias<(word)-4095,154);
 *(volatile char *)(mapped+4096)='M';check(*(volatile char *)alias=='M',155);
 check(call(__NR_madvise,alias,4096,4,0)==-22 && *(volatile char *)alias=='M',172);
 check((word)mapping_region(mapped+4096,0x11,file,3,4096,8192)==mapped+4096,166);
 *(volatile char *)(mapped+4096)='X';
 check(*(volatile char *)alias=='M' && *(volatile char *)(mapped+8192)=='X',167);
 check(call(__NR_ftruncate,file,4096,0,0)==-16,156);
 check(call(__NR_open,(word)"/home/retroos/shared-pages",514,0600,0)==-16,168);
 check(call(__NR_unlink,(word)"/home/retroos/shared-pages",0,0,0)==-16,169);
 check(call(__NR_rename,(word)"/home/retroos/shared-pages",(word)"/home/retroos/renamed-pages",0,0)==-16,170);
 check(call(__NR_munmap,mapped+4096,4096,0,0)==0,157);
 *(volatile char *)mapped='A';*(volatile char *)(mapped+8192)='Z';
 check(call(__NR_close,file,0,0,0)==0,158);
 *(volatile char *)alias='B';check(call(__NR_msync,alias,4096,4,0)==0,159);
 check(call(__NR_munmap,alias,4096,0,0)==0,160);
 check(call(__NR_munmap,mapped,12288,0,0)==0,161);
 file=call(__NR_open,(word)"/home/retroos/shared-pages",0,0,0);check(file>=0,162);
 check(call(__NR_read,file,(word)link,1,0)==1 && link[0]=='A',163);
 check(call(__NR_lseek,file,4096,0,0)==4096 && call(__NR_read,file,(word)link,1,0)==1 && link[0]=='B',164);
 check(call(__NR_lseek,file,8192,0,0)==8192 && call(__NR_read,file,(word)link,1,0)==1 && link[0]=='Z',165);
 call(__NR_close,file,0,0,0);
 /* Discard releases private anonymous pages, zero-fills reuse, and keeps COW siblings. */
 mapped=(word)mapping_region(0,0x22,(word)-1,3,12288,0);check(mapped<(word)-4095,173);
 for(word n=0;n<12288;n++)((volatile unsigned char *)mapped)[n]=(n/4096)+1;
 check(call(__NR_madvise,mapped+4096,1,4,0)==0,174);
 for(word n=4096;n<8192;n++)check(((volatile unsigned char *)mapped)[n]==0,175);
 check(*(volatile char *)mapped==1 && *(volatile char *)(mapped+8192)==3,176);
 child=call(__NR_fork,0,0,0,0);check(child>=0,177);
 if(!child){
  check(call(__NR_madvise,mapped+8192,4096,4,0)==0 && *(volatile char *)(mapped+8192)==0,178);
  call(__NR_exit,17,0,0,0);for(;;){}
 }
 check(call(__NR_wait4,child,(word)&shared_status,0,0)==child && shared_status==(17<<8),179);
 check(*(volatile char *)(mapped+8192)==3,180);
 check(call(__NR_madvise,mapped,12288,8,0)==0 && *(volatile char *)mapped==1,181);
 check(call(__NR_madvise,mapped+1,4096,4,0)==-22 && call(__NR_madvise,mapped,4096,999,0)==-22,182);
 check(call(__NR_munmap,mapped+4096,4096,0,0)==0,183);
 check(call(__NR_madvise,mapped,12288,4,0)==-22 && *(volatile char *)mapped==1,184);
 check((word)mapping_region(mapped+4096,0x32,(word)-1,3,4096,0)==mapped+4096,185);
 check(call(__NR_madvise,mapped,12288,4,0)==0,186);
 check(*(volatile char *)mapped==0 && *(volatile char *)(mapped+8192)==0,187);
 file=call(__NR_open,(word)"/home/retroos/target",2,0,0);check(file>=0,189);
 check((word)mapping_region(mapped,0x12,file,3,4096,0)==mapped,190);
 check(call(__NR_madvise,mapped,4096,4,0)==-22 && *(volatile char *)mapped=='P',191);
 check((word)mapping_region(mapped,0x32,(word)-1,3,4096,0)==mapped,192);
 check((word)mapping_region(mapped,0x11,file,3,4096,0)==mapped,193);
 check(call(__NR_madvise,mapped,4096,4,0)==-22 && *(volatile char *)mapped=='P',194);
 call(__NR_close,file,0,0,0);
 check(call(__NR_munmap,mapped,12288,0,0)==0,188);
 /* Bazel creates output trees longer than the old 256-byte mutation buffers. */
 char deep[512]="/home/retroos",old[512],overlong[1025];
 unsigned ends[4],length=13;
 for(unsigned level=0;level<4;level++){
  deep[length++]='/';
  for(unsigned j=0;j<80;j++)deep[length++]=(char)('a'+level);
  deep[length]=0;ends[level]=length;
  check(call(__NR_mkdir,(word)deep,0755,0,0)==0,77);
  check(call(LSTAT,(word)deep,(word)&metadata,0,0)==0 && (metadata.st_mode&0170000)==0040000,78);
 }
 deep[length++]='/';
 for(unsigned j=0;j<5;j++)deep[length+j]="first"[j];deep[length+5]=0;
 file=call(__NR_open,(word)deep,0x241,0644,0);check(file>=0,79);call(__NR_close,file,0,0,0);
 check(call(__NR_chmod,(word)deep,0600,0,0)==0,80);
 check(call(LSTAT,(word)deep,(word)&metadata,0,0)==0 && (metadata.st_mode&0777)==0600,81);
 for(unsigned j=0;j<=length+5;j++)old[j]=deep[j];
 for(unsigned j=0;j<5;j++)deep[length+j]="moved"[j];
 check(call(__NR_rename,(word)old,(word)deep,0,0)==0,82);
 check(call(LSTAT,(word)old,(word)&metadata,0,0)==-2,83);
 check(call(__NR_unlink,(word)deep,0,0,0)==0,84);
 check(call(__NR_symlink,(word)"/home/retroos/target",(word)deep,0,0)==0,85);
 check(call(__NR_readlink,(word)deep,(word)link,sizeof link,0)==20,86);
 check(call(__NR_unlinkat,(word)-100,(word)deep,0,0)==0,87);
 deep[--length]=0;
 check(call(__NR_chdir,(word)deep,0,0,0)==0,88);
 check(call(__NR_mkdir,(word)"relative",0755,0,0)==0,89);
 check(call(__NR_rmdir,(word)"relative",0,0,0)==0,90);
 for(unsigned j=0;j<1024;j++)overlong[j]='x';overlong[1024]=0;
 check(call(__NR_mkdir,(word)overlong,0755,0,0)==-36,91);
 check(call(__NR_chmod,(word)overlong,0600,0,0)==-36,92);
 check(call(__NR_rename,(word)deep,(word)overlong,0,0)==-36,93);
 check(call(__NR_unlinkat,(word)-100,(word)overlong,0,0)==-36,94);
 check(call(__NR_rmdir,(word)overlong,0,0,0)==-36,95);
 check(call(__NR_mkdir,(word)"",0755,0,0)==-2,96);
 check(call(__NR_chdir,(word)"/",0,0,0)==0,97);
 for(int level=3;level>=0;level--){deep[ends[level]]=0;check(call(__NR_rmdir,(word)deep,0,0,0)==0,98);}
 ipc_roundtrips();
 call(__NR_exit,0,0,0,0);for(;;){}
}
