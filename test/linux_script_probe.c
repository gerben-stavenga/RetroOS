/* Interpreter argv, environment, spaces and pre-exec failure semantics. */
#include <asm/unistd.h>
typedef unsigned long word;
#define HOME "/home/retroos/"
static long call(word n,word a,word b,word c){
 long r;
#ifdef __x86_64__
 __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c):"rcx","r11","memory");
#else
 __asm__ volatile("int $0x80":"=a"(r):"a"(n),"b"(a),"c"(b),"d"(c):"memory");
#endif
 return r;
}
static void check(int ok,int code){if(!ok){call(__NR_exit,code,0,0);for(;;){}}}
static int equal(const char *a,const char *b){while(*a && *a==*b){a++;b++;}return *a==*b;}
__attribute__((used)) static void start(word *stack){
 word argc=*stack;char **argv=(char **)(stack+1);char **env=argv+argc+1;
 if(equal(argv[0],HOME "interpreter")){
  check(argc==6,10);
  const char *expected[]={HOME "interpreter","single",HOME "second","optional value",HOME "script with spaces","tail arg"};
  for(word i=0;i<argc;i++)check(equal(argv[i],expected[i]),11+i);
  check(env[0] && equal(env[0],"MARKER=script-env") && env[1]==0,17);
  call(__NR_exit,0,0,0);for(;;){}
 }
 char *args[]={"discard-this-argv-zero","tail arg",0};char *next_env[]={"MARKER=script-env",0};
 check(call(__NR_execve,(word)HOME "bad",(word)args,(word)next_env)==-2,1);
 check(call(__NR_execve,(word)HOME "loop",(word)args,(word)next_env)==-40,2);
 check(call(__NR_execve,(word)HOME "malformed",(word)args,(word)next_env)==-8,3);
 call(__NR_execve,(word)HOME "script with spaces",(word)args,(word)next_env);
 check(0,4);
}
#ifdef __x86_64__
__asm__(".text\n.global _start\n_start: mov %rsp,%rdi\nand $-16,%rsp\ncall start\nud2\n");
#else
__asm__(".text\n.global _start\n_start: mov %esp,%eax\nand $-16,%esp\nsub $12,%esp\npush %eax\ncall start\nud2\n");
#endif
