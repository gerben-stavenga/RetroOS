/* Large regular-file I/O must span SMB transport packets. */
#include <asm/unistd.h>
typedef unsigned long word;
static long call(word n, word a, word b, word c, word d) {
 long r;
#ifdef __x86_64__
 register word fourth __asm__("r10")=d;
 __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c),"r"(fourth):"rcx","r11","memory");
#else
 __asm__ volatile("int $0x80":"=a"(r):"a"(n),"b"(a),"c"(b),"d"(c),"S"(d):"memory");
#endif
 return r;
}
static void check(int ok, int code) {if(!ok){call(__NR_exit,code,0,0,0);for(;;){}}}
static unsigned char buffer[131072];
static unsigned char output[8*1024*1024+37];
static long read_preserving_simd(word fd) {
#ifdef __x86_64__
 long result;word low,high;
 __asm__ volatile("mov $0x12345678,%%eax\nmovq %%rax,%%xmm0\nmovq %%rax,%%xmm15\nmov $0,%%eax\nsyscall\nmovq %%xmm0,%1\nmovq %%xmm15,%2"
 :"=a"(result),"=r"(low),"=r"(high):"D"(fd),"S"(buffer),"d"((word)sizeof buffer):"rcx","r11","xmm0","xmm15","memory");
 check(low==0x12345678 && high==0x12345678,21);
 return result;
#else
 return call(__NR_read,fd,(word)buffer,sizeof buffer,0);
#endif
}
static void verify(word count,word offset) {
 for(word i=0;i<count;i++) check(buffer[i]==(unsigned char)(((offset+i)*17+3)^((offset+i)>>8)),20);
}
void _start(void) {
 long fd=call(__NR_open,(word)"/home/retroos/payload",0,0,0);
 check(fd>=0,1);
 check(read_preserving_simd(fd)==95013,2);
 verify(95013,0);
 check(call(__NR_read,fd,(word)buffer,1,0)==0,3);
 check(call(__NR_lseek,fd,37,0,0)==37,4);
 check(call(__NR_read,fd,(word)buffer,70001,0)==70001,5);
 verify(70001,37);
 check(call(__NR_pread64,fd,(word)buffer,80003,123)==80003,6);
 verify(80003,123);
 check(call(__NR_lseek,fd,0,1,0)==70038,7);
 buffer[5000]=0xa5;
 check(call(__NR_pread64,fd,(word)buffer,5001,90013)==5000,8);
 verify(5000,90013);
 check(buffer[5000]==0xa5,9);
 check(call(__NR_pread64,fd,(word)buffer,1,95013)==0,10);
 call(__NR_close,fd,0,0,0);
 for(word i=0;i<sizeof output;i++)output[i]=(unsigned char)((i*17+3)^(i>>8));
 fd=call(__NR_open,(word)"/home/retroos/written",577,0600,0);check(fd>=0,30);
 check(call(__NR_write,fd,(word)output,sizeof output,0)==sizeof output,31);
 check(call(__NR_lseek,fd,0,1,0)==sizeof output,32);
 word vectors[4]={(word)output,70001,(word)output,90003};
 check(call(__NR_writev,fd,(word)vectors,2,0)==160004,33);
 check(call(__NR_write,fd,(word)output,0,0)==0,34);
 check(call(__NR_write,fd,0,1,0)==-14,35);
 check(call(__NR_lseek,fd,0,1,0)==sizeof output+160004,36);
 call(__NR_close,fd,0,0,0);
 call(__NR_exit,0,0,0,0);
 for(;;){}
}
