#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
static const char *path="/proc/sys/kernel/random/boot_id";
static void check(int ok,int code) { if(!ok){dprintf(2,"BOOT ID FAIL %d errno=%d\n",code,errno);_exit(code);} }
int main(int argc,char **argv) {
 char id[38]={0},again[38]={0};
 int fd=open(path,O_RDONLY|O_CLOEXEC);check(fd>=0,1);
 struct stat st;check(fstat(fd,&st)==0 && S_ISREG(st.st_mode) && !(st.st_mode&0222),2);
 check(read(fd,id,7)==7 && read(fd,id+7,31)==30 && read(fd,again,1)==0,3);
 for(int i=0;i<36;i++)check((i==8||i==13||i==18||i==23) ? id[i]=='-' : (id[i]>='0'&&id[i]<='9')||(id[i]>='a'&&id[i]<='f'),4);
 check(id[14]=='4' && strchr("89ab",id[19]) && id[36]=='\n',5);
 check(lseek(fd,0,SEEK_SET)==0 && read(fd,again,sizeof again)==37 && !memcmp(id,again,37),6);
 check(pread(fd,again,5,10)==5 && !memcmp(again,id+10,5),7);close(fd);
 fd=open(path,O_WRONLY);
 if(fd>=0){check(write(fd,"bad",3)==-1 && (errno==EROFS||errno==EACCES),8);close(fd);}
 else check(errno==EROFS||errno==EACCES,8);
 fd=open(path,O_RDONLY);check(fd>=0 && read(fd,again,sizeof again)==37 && !memcmp(again,id,37),13);close(fd);
 if(argc>1){check(strlen(argv[1])==37 && !strcmp(argv[1],id),9);return 0;}
 pid_t child=fork();check(child>=0,10);
 if(!child){execl("/proc/self/exe","probe",id,(char *)0);_exit(11);}
 int status;check(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0,12);
 dprintf(2,"BOOT_ID=%s",id);return 0;
}
