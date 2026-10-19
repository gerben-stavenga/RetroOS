/* An EPOLLET readiness transition must survive before the next epoll_wait. */
#include <asm/unistd.h>
typedef unsigned long word;
static long call(word nr,word a,word b,word c,word d) {
 long result;register word fourth __asm__("r10")=d;
 __asm__ volatile("syscall":"=a"(result):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(fourth):"rcx","r11","memory");
 return result;
}
static void check(int ok,int code){if(!ok){call(__NR_exit,code,0,0,0);for(;;){}}}
struct event {unsigned events; unsigned long long tag;} __attribute__((packed));
void __attribute__((force_align_arg_pointer)) _start(void) {
 long fd=call(__NR_socket,2,2|0x800,0,0);check(fd>=0,10);
 unsigned char address[16]={2,0,PORT>>8,PORT&255,10,0,2,2};
 check(call(__NR_connect,fd,(word)address,16,0)==0,11);
 long ep=call(__NR_epoll_create1,0,0,0,0);check(ep>=0,12);
 struct event event={1u|(1u<<31),123};
 check(call(__NR_epoll_ctl,ep,1,fd,(word)&event)==0,13);
 check(call(__NR_write,fd,(word)"start",5,0)==5,14);
 check(call(__NR_epoll_wait,ep,(word)&event,1,3000)==1,15);
 char byte;
 int available=0;
 check(call(__NR_ioctl,fd,0x541b,(word)&available,0)==0 && available==1,22);
 check(call(__NR_read,fd,(word)&byte,1,0)==1 && byte=='A',16);
 check(call(__NR_ioctl,fd,0x541b,(word)&available,0)==0 && available==0,23);
 check(call(__NR_read,fd,(word)&byte,1,0)==-11,17);
 check(call(__NR_write,fd,(word)"next",4,0)==4,18);
 /* New data arrives while this context sleeps, before epoll samples again. */
 unsigned long long duration[2]={0,100000000};
 check(call(__NR_nanosleep,(word)duration,0,0,0)==0,19);
 check(call(__NR_epoll_wait,ep,(word)&event,1,3000)==1,20);
 check(call(__NR_read,fd,(word)&byte,1,0)==1 && byte=='B',21);
 long tcp=call(__NR_socket,2,1|0x800,0,0);check(tcp>=0,24);
 address[2]=TCP_PORT>>8;address[3]=TCP_PORT&255;
 long result=call(__NR_connect,tcp,(word)address,16,0);check(result==0 || result==-115,25);
 check(call(__NR_epoll_ctl,ep,1,tcp,(word)&event)==0,26);
 check(call(__NR_epoll_wait,ep,(word)&event,1,3000)==1,27);
 check(call(__NR_ioctl,tcp,0x541b,(word)&available,0)==0 && available==5,28);
 char bytes[5];check(call(__NR_read,tcp,(word)bytes,2,0)==2 && bytes[0]=='H' && bytes[1]=='E',29);
 check(call(__NR_ioctl,tcp,0x541b,(word)&available,0)==0 && available==3,30);
 check(call(__NR_read,tcp,(word)bytes,3,0)==3 && bytes[0]=='L' && bytes[2]=='O',31);
 check(call(__NR_ioctl,tcp,0x541b,(word)&available,0)==0 && available==0,32);
 check(call(__NR_write,tcp,(word)"done",4,0)==4,33);
 call(__NR_write,2,(word)"EPOLL SOCKET PASS\n",18,0);
 call(__NR_exit,0,0,0,0);for(;;){}
}
