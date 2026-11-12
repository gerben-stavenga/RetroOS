#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { dprintf(2,"SPLICE_FAIL line=%d errno=%d\n",__LINE__,errno); exit(1); } } while(0)
static long transfer(int input, int output, size_t count, unsigned flags) {
 return syscall(SYS_splice,input,0,output,0,count,flags);
}
int main(void) {
 int p[2]; CHECK(pipe(p)==0); int sink=open("/dev/null",O_WRONLY); CHECK(sink>=0);
 CHECK(write(p[1],"abcdef",6)==6); CHECK(transfer(p[0],sink,3,1)==3);
 char data[8]; CHECK(read(p[0],data,3)==3 && !memcmp(data,"def",3));
 errno=0; CHECK(transfer(p[0],sink,5,2)==-1 && errno==EAGAIN);
 CHECK(fcntl(p[0],F_SETFL,O_NONBLOCK)==0);
 errno=0; CHECK(transfer(p[0],sink,5,0)==-1 && errno==EAGAIN);
 CHECK(fcntl(p[0],F_SETFL,0)==0);
 CHECK(write(p[1],"xyz",3)==3);
 long long offset=0; errno=0; CHECK(syscall(SYS_splice,p[0],&offset,sink,0,3,0)==-1 && errno==ESPIPE);
 errno=0; CHECK(transfer(p[0],sink,3,128)==-1 && errno==EINVAL);
 int append=open("/dev/null",O_WRONLY|O_APPEND); CHECK(append>=0);
 errno=0; CHECK(transfer(p[0],append,3,0)==-1 && errno==EINVAL); CHECK(close(append)==0);
 int other[2]; CHECK(pipe(other)==0);
 errno=0; CHECK(transfer(p[0],other[0],3,0)==-1 && errno==EBADF); CHECK(close(other[0])==0 && close(other[1])==0);
 int readonly=open("/dev/null",O_RDONLY); CHECK(readonly>=0);
 errno=0; CHECK(transfer(p[0],readonly,3,0)==-1 && errno==EBADF); CHECK(close(readonly)==0);
 CHECK(read(p[0],data,3)==3 && !memcmp(data,"xyz",3));
 pid_t child=fork(); CHECK(child>=0);
 if(!child){close(p[0]);usleep(30000);CHECK(write(p[1],"late",4)==4);close(p[1]);_exit(0);}
 CHECK(close(p[1])==0); CHECK(transfer(p[0],sink,100,0)==4);
 CHECK(transfer(p[0],sink,100,0)==0);
 int status; CHECK(waitpid(child,&status,0)==child && status==0);
 CHECK(close(p[0])==0 && close(sink)==0);
 dprintf(2,"SPLICE_PASS: partial drain, blocking, EOF, nonblocking and rejected transfers preserve input\n");return 0;
}
