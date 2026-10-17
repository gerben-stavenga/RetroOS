/* Real VFS calls into the common SMB mount, without libc. */
typedef unsigned long word;
static int sys(int nr, word a, word b, word c) {
    int result;
    __asm__ volatile("int $0x80" : "=a"(result) : "a"(nr), "b"(a), "c"(b), "d"(c) : "memory");
    return result;
}
static void done(int code) {sys(1,code,0,0); for(;;) {}}
static void check(int condition,int code) {if(!condition) done(code);}
static int open(const char *p,int flags) {return sys(5,(word)p,flags,0666);}
static int close(int fd) {return sys(6,fd,0,0);}
static unsigned char data[98317], reply[98317];
void __attribute__((force_align_arg_pointer)) _start(void) {
#ifdef EXPECT_FAILURE
    check(open("/home/retroos/NET/seed.txt",0)<0,90); done(0);
#endif
#ifdef EXPECT_IO_FAILURE
    check(open("/home/retroos/NET/seed.txt",0)<0,91); done(0);
#endif
#ifdef EXPECT_TAMPER
    int f=open("/home/retroos/NET/seed.txt",0);check(f>=0,92);check(sys(3,f,(word)reply,32)==-13,93);done(0);
#endif
    int ro=open("/RO/seed.txt",0);check(ro>=0,94);check(close(ro)==0,95);
    check(open("/RO/forbidden.txt",0101|01000)<0,96);
    int directory=open("/home/retroos/NET/listing",0);check(directory>=0,97);
    int total=0;
    for(;;) {
        int n=sys(220,directory,(word)reply,sizeof(reply));check(n>=0,98);if(n==0)break;
        for(int off=0;off<n;) {int len=reply[off+16]|(reply[off+17]<<8);check(len>19 && off+len<=n,99);if(reply[off+19]=='f')total++;off+=len;}
    }
    check(total==600,100);check(close(directory)==0,101);
    int seed=open("/home/retroos/NET/seed.txt",0); check(seed>=0,2);
    check(sys(3,seed,(word)reply,32)==10,3);
    static const char expected[]="SMB seed!\n";
    for(int i=0;i<10;i++) check(reply[i]==expected[i],4);
    check(close(seed)==0,5);
    check(sys(39,(word)"/home/retroos/NET/work",0777,0)==0,6);
    int fd=open("/home/retroos/NET/work/data.bin",0102|01000); check(fd>=0,7);
    for(int i=0;i<sizeof(data);i++) data[i]=(i*31+(i>>7))&255;
    int pos=0;
    while(pos<sizeof(data)) {int n=sys(4,fd,(word)(data+pos),sizeof(data)-pos);check(n>0,8);pos+=n;}
    check(close(fd)==0,9);
    fd=open("/home/retroos/NET/work/data.bin",0); check(fd>=0,10);
    pos=0;
    while(pos<sizeof(reply)) {int n=sys(3,fd,(word)(reply+pos),sizeof(reply)-pos);check(n>0,11);pos+=n;}
    for(int i=0;i<sizeof(data);i++) check(reply[i]==data[i],12);
    check(sys(3,fd,(word)reply,1)==0,13);check(close(fd)==0,14);
    check(sys(38,(word)"/home/retroos/NET/work/data.bin",(word)"/home/retroos/NET/work/renamed.bin",0)==0,15);
    check(open("/home/retroos/NET/work/data.bin",0)==-2,16);
    fd=open("/home/retroos/NET/work/renamed.bin",2);check(fd>=0,17);
    check(sys(93,fd,(word)-1,0)==-22,102);
    check(sys(93,fd,37,0)==0,18);check(close(fd)==0,19);
    fd=open("/home/retroos/NET/work/renamed.bin",0);check(fd>=0,20);
    check(sys(3,fd,(word)reply,128)==37,21);check(close(fd)==0,22);
    fd=open("/home/retroos/NET",0);check(fd>=0,23);
    int n=sys(220,fd,(word)reply,sizeof(reply));check(n>0,24);
    check(close(fd)==0,25);
    check(sys(10,(word)"/home/retroos/NET/work/renamed.bin",0,0)==0,26);
    check(sys(40,(word)"/home/retroos/NET/work",0,0)==0,27);
    fd=open("/home/retroos/NET/verified.txt",0101|01000);check(fd>=0,28);
    check(sys(4,fd,(word)"RetroOS SMB PASS\n",17)==17,29);check(close(fd)==0,30);
    done(0);
}
