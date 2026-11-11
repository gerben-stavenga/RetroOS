static long call(long nr,long a,long b,long c){long r;__asm__ volatile("int $0x80":"=a"(r):"a"(nr),"b"(a),"c"(b),"d"(c):"memory");return r;}
static unsigned char buffer[256];
static void check(int ok,int code){if(!ok){call(4,2,(long)"IDENTITY32 FAIL\n",16);call(1,code,0,0);}}
void _start(void){
 check(call(24,0,0,0)==1001&&call(49,0,0,0)==1001&&call(47,0,0,0)==1002&&call(50,0,0,0)==1002,31);
 check(call(199,0,0,0)==1001&&call(201,0,0,0)==1001&&call(200,0,0,0)==1002&&call(202,0,0,0)==1002,32);
 check(call(195,(long)"/foreign",(long)buffer,0)==0&&*(unsigned *)(buffer+24)==2002&&*(unsigned *)(buffer+28)==2003,33);
 check(call(106,(long)"/foreign",(long)buffer,0)==0&&*(unsigned short *)(buffer+12)==2002&&*(unsigned short *)(buffer+14)==2003,34);
 check(call(213,1001,0,0)==0&&call(214,1002,0,0)==0&&call(213,0,0,0)==-1,35);
 call(1,0,0,0);
}
