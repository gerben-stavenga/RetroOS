#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
static void check(int ok,int code){if(!ok){dprintf(2,"PERMISSIONS FAIL %d errno=%d\n",code,errno);_exit(code);}}
static void mode(const char *path,mode_t expected,int code){struct stat st;check(stat(path,&st)==0&&(st.st_mode&07777)==expected,code);}
int main(int argc,char **argv){
 if(argc>1){check(umask(0077)==0027,1);return 0;}
 check(umask(0077)==0022,2);
 check(mkdir("/home/retroos/socket-parent",0700)==0,3);mode("/home/retroos/socket-parent",0700,4);
 check(mkdir("/home/retroos/masked",0777)==0,5);mode("/home/retroos/masked",0700,6);
 int fd=open("/home/retroos/socket-parent",O_RDONLY|O_DIRECTORY);check(fd>=0,7);
 struct stat st;check(fstat(fd,&st)==0&&S_ISDIR(st.st_mode)&&(st.st_mode&07777)==0700,8);
 struct statx sx;check(syscall(SYS_statx,fd,"",AT_EMPTY_PATH,STATX_MODE,&sx)==0&&(sx.stx_mode&07777)==0700,9);
 check(mkdirat(fd,"child",0755)==0,10);mode("/home/retroos/socket-parent/child",0700,11);
 errno=0;check(mkdirat(fd,"child",0777)==-1&&errno==EEXIST,12);mode("/home/retroos/socket-parent/child",0700,13);close(fd);
 fd=open("/home/retroos/socket-parent",O_RDONLY|O_DIRECTORY);check(fd>=0,38);
 int childfd=openat(fd,"child",O_RDONLY|O_DIRECTORY);check(childfd>=0,39);
 check(fstat(childfd,&st)==0&&S_ISDIR(st.st_mode),40);close(childfd);
 int relative=openat(fd,"relative",O_CREAT|O_WRONLY,0600);check(relative>=0,41);close(relative);
 mode("/home/retroos/socket-parent/relative",0600,42);
 check(unlinkat(fd,"relative",0)==0&&unlinkat(fd,"child",AT_REMOVEDIR)==0,43);close(fd);
 errno=0;check(openat(-1,"relative",O_RDONLY)==-1&&errno==EBADF,44);
 fd=openat(-1,"/home/retroos/socket-parent",O_RDONLY|O_DIRECTORY);check(fd>=0,45);close(fd);
 fd=open("/home/retroos/private",O_CREAT|O_EXCL|O_WRONLY,0666);check(fd>=0,14);check(fstat(fd,&st)==0&&(st.st_mode&07777)==0600,30);
 check(fchmod(fd,0640)==0&&fstat(fd,&st)==0&&(st.st_mode&07777)==0640,31);close(fd);
 check(chmod("/home/retroos/private",0600)==0,32);mode("/home/retroos/private",0600,15);
 check(chmod("/home/retroos/private",0640)==0,16);
 fd=open("/home/retroos/private",O_CREAT|O_TRUNC|O_WRONLY,0777);check(fd>=0,17);close(fd);mode("/home/retroos/private",0640,18);
 char temporary[]="/home/retroos/temp-XXXXXX";check(mkdtemp(temporary)!=NULL,19);mode(temporary,0700,20);
 char file[]="/home/retroos/temp-file-XXXXXX";fd=mkstemp(file);check(fd>=0,21);
 FILE *stream=fdopen(fd,"w");check(stream!=NULL,33);
 check(fputs("temporary stream\n",stream)>=0&&fclose(stream)==0,34);mode(file,0600,22);
 fd=open(file,O_RDONLY);check(fd>=0&&(fcntl(fd,F_GETFL)&O_ACCMODE)==O_RDONLY,35);close(fd);
 fd=open(file,O_WRONLY);check(fd>=0&&(fcntl(fd,F_GETFL)&O_ACCMODE)==O_WRONLY,36);close(fd);
 fd=open(file,O_RDWR);check(fd>=0&&(fcntl(fd,F_GETFL)&O_ACCMODE)==O_RDWR,37);close(fd);
 pid_t child=fork();check(child>=0,23);if(!child){check(umask(0027)==0077,24);execl("/probe","probe","exec",(char *)0);_exit(25);}
 int status;check(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0,26);
 check(umask(0000)==0077,27);
 check(mkdirat(AT_FDCWD,"/home/retroos/sticky",01777)==0,28);mode("/home/retroos/sticky",01777,29);
 dprintf(2,"PERMISSIONS_PASS: private directories/files, umask, directory metadata, fork and exec\n");return 0;
}
