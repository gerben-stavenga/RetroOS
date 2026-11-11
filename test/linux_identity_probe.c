#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
static void check(int ok,int code){if(!ok){dprintf(2,"IDENTITY FAIL %d errno=%d\n",code,errno);_exit(code);}}
int main(int argc,char **argv){
 (void)argv;
 check(getuid()==1001&&geteuid()==1001&&getgid()==1002&&getegid()==1002,1);
 check(getauxval(AT_UID)==1001&&getauxval(AT_EUID)==1001&&getauxval(AT_GID)==1002&&getauxval(AT_EGID)==1002,2);
 if(argc>1)return 0;
 struct stat st;check(stat("/home/retroos",&st)==0&&st.st_uid==1001&&st.st_gid==1002,5);
 int fd=open("/home/retroos",O_RDONLY|O_DIRECTORY);check(fd>=0&&fstat(fd,&st)==0&&st.st_uid==1001&&st.st_gid==1002,6);
 struct statx sx;check(statx(fd,"",AT_EMPTY_PATH,STATX_BASIC_STATS,&sx)==0&&sx.stx_uid==1001&&sx.stx_gid==1002,7);close(fd);
 fd=open("/foreign",O_RDONLY);check(fd>=0&&fstat(fd,&st)==0&&st.st_uid==2002&&st.st_gid==2003,8);close(fd);
 check(stat("/foreign",&st)==0&&st.st_uid==2002&&st.st_gid==2003,9);
 check(statx(AT_FDCWD,"/foreign",0,STATX_BASIC_STATS,&sx)==0&&sx.stx_uid==2002&&sx.stx_gid==2003,10);
 check(setuid(1001)==0&&setgid(1002)==0,13);errno=0;check(setuid(0)==-1&&errno==EPERM&&getuid()==1001,14);
 pid_t child=fork();check(child>=0,15);if(!child){char *args[]={"/probe","child",0};char *env[]={"HOME=/foreign",0};execve(args[0],args,env);_exit(16);}
 int status;check(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0,17);
 child=fork();check(child>=0,18);if(!child){char *args[]={"/probe32",0};execv(args[0],args);_exit(19);}
 check(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0,20);
 dprintf(2,"IDENTITY_PASS: session UID/GID, auxv, compat IDs, native backing ownership, fork/exec\n");return 0;
}
