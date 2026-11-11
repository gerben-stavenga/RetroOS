#ifdef BITS32
typedef unsigned int u32;
static int sc(int n,unsigned long a,unsigned long b,unsigned long c){int r;__asm__ volatile("int $0x80":"=a"(r):"a"(n),"b"(a),"c"(b),"d"(c):"memory");return r;}
static unsigned char out[136];
static int main32(void){
 const char *path="/home/retroos";
 for(int i=0;i<136;i++)out[i]=0xa5;
 if(sc(99,(unsigned long)path,(unsigned long)out,0)!=0||*(u32 *)out!=0xef53||!*(u32 *)(out+8)||out[64]!=0xa5)return 1;
 int fd=sc(5,(unsigned long)path,0x10000,0);if(fd<0)return 2;
 if(sc(100,fd,(unsigned long)out,0)!=0||*(u32 *)out!=0xef53)return 3;
 for(int i=0;i<136;i++)out[i]=0xa5;
 if(sc(268,(unsigned long)path,84,(unsigned long)out)!=0||*(u32 *)out!=0xef53||!*(u32 *)(out+8)||out[84]!=0xa5)return 4;
 if(sc(269,fd,84,(unsigned long)out)!=0||*(u32 *)(out+56)!=255)return 5;
 if(sc(268,(unsigned long)path,80,(unsigned long)out)!=-22)return 6;
 if(sc(100,999,(unsigned long)out,0)!=-9)return 7;
 if(sc(99,(unsigned long)"/missing",(unsigned long)out,0)!=-2)return 8;
 const char *pass="STATFS_PASS 32\n";sc(4,2,(unsigned long)pass,15);return 0;
}
void _start(void){int result=main32();sc(1,result,0,0);__builtin_unreachable();}
#else
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <unistd.h>
static void check(int ok,int code){if(!ok){dprintf(2,"STATFS FAIL %d errno=%d\n",code,errno);_exit(code);}}
int main(void){
 struct statfs before,after,fdinfo,other;
 check(statfs("/home/retroos",&before)==0,1);
 check(before.f_type==0xef53&&before.f_bsize>0&&before.f_blocks>0&&before.f_files>0,2);
 check(before.f_bavail<=before.f_bfree&&before.f_bfree<=before.f_blocks&&before.f_ffree<=before.f_files,3);
 check(before.f_frsize==before.f_bsize&&before.f_namelen==255&&!(before.f_flags&1),4);
 int fd=open("/home/retroos",O_RDONLY|O_DIRECTORY);check(fd>=0&&fstatfs(fd,&fdinfo)==0,5);
 check(fdinfo.f_type==before.f_type&&!memcmp(&fdinfo.f_fsid,&before.f_fsid,sizeof before.f_fsid),6);close(fd);
 fd=open("/home/retroos/data",O_CREAT|O_EXCL|O_RDWR,0600);check(fd>=0,7);
 static char bytes[8192];memset(bytes,'x',sizeof bytes);
 for(int i=0;i<32;i++)check(write(fd,bytes,sizeof bytes)==sizeof bytes,8);
 check(fsync(fd)==0&&fstatfs(fd,&after)==0,9);close(fd);
 check(after.f_bfree<before.f_bfree&&after.f_ffree<before.f_ffree,10);
 check(unlink("/home/retroos/data")==0&&statfs("/home/retroos",&other)==0&&other.f_bfree>=after.f_bfree,11);
 check(statfs("/tmp",&other)==0&&other.f_type==0x4d44&&other.f_blocks>0&&other.f_bsize>0,12);
 check(statfs("/proc/self/stat",&other)==0&&other.f_type==0x9fa0&&(other.f_flags&1),13);
 errno=0;check(statfs("/missing",&other)==-1&&errno==ENOENT,14);
 errno=0;check(fstatfs(-1,&other)==-1&&errno==EBADF,15);
 errno=0;check(syscall(SYS_statfs,"/home/retroos",0)==-1&&errno==EFAULT,16);
 dprintf(2,"STATFS_PASS 64: filesystem types, real allocation counts, aliases, descriptors and errors\n");return 0;
}
#endif
