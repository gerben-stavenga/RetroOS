#define _GNU_SOURCE
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
static void check(int ok,int code) { if(!ok){dprintf(2,"PERSISTENCE FAIL %d errno=%d\n",code,errno);_exit(code);} }
static unsigned long long birth(pid_t pid) {
 char path[80],buf[4096];snprintf(path,sizeof path,"/proc/%d/stat",pid);
 int fd=open(path,O_RDONLY);check(fd>=0,1);int n=read(fd,buf,sizeof buf-1);close(fd);check(n>0,2);buf[n]=0;
 char *last=strrchr(buf,')');check(last!=NULL,3);
 char *save,*word=strtok_r(last+2," ",&save);
 for(int field=3;field<22;field++){check(word!=NULL,4);word=strtok_r(NULL," ",&save);}
 check(word!=NULL,5);return strtoull(word,NULL,10);
}
static void put(const char *path,const char *text,mode_t mode) {
 int fd=open(path,O_CREAT|O_WRONLY|O_TRUNC,mode);check(fd>=0,20);
 check(fchmod(fd,mode)==0,37);
 check(write(fd,text,strlen(text))==(ssize_t)strlen(text) && fsync(fd)==0,21);close(fd);
}
static void contents(const char *path,const char *expected) {
 char buf[80]={0};int fd=open(path,O_RDONLY);check(fd>=0,22);int n=read(fd,buf,sizeof buf);close(fd);
 check(n==(int)strlen(expected)&&!memcmp(buf,expected,n),23);
}
int main(int argc,char **argv) {
 unsigned long long own=birth(getpid());
 if(argc>1){check(own==strtoull(argv[1],NULL,10),6);return 0;}
 usleep(30000);check(own==birth(getpid()),7);
 int fd=open("/proc/self/stat",O_RDONLY);check(fd>=0,8);close(fd);
 int pipefd[2];check(pipe(pipefd)==0,9);
 pid_t child=fork();check(child>=0,10);
 if(!child){close(pipefd[1]);char byte;check(read(pipefd[0],&byte,1)==1,11);close(pipefd[0]);
  char value[40];snprintf(value,sizeof value,"%llu",birth(getpid()));execl("/probe","probe",value,(char *)0);_exit(12);}
 close(pipefd[0]);unsigned long long child_birth=birth(child);check(child_birth>=own,13);
 usleep(30000);check(birth(child)==child_birth,14);check(write(pipefd[1],"x",1)==1,15);close(pipefd[1]);
 int status;check(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0,16);
 char path[80];snprintf(path,sizeof path,"/proc/%d/stat",child);errno=0;check(open(path,O_RDONLY)==-1&&errno==ENOENT,17);
 // A fake backing /proc must never supply another OS's process identity.
 errno=0;check(open("/proc/987654/stat",O_RDONLY)==-1&&errno==ENOENT,18);
 struct stat st;check(stat("/proc/987654/stat",&st)==-1&&errno==ENOENT,19);
 DIR *directory=opendir("/proc");check(directory!=NULL,38);struct dirent *entry;
 while((entry=readdir(directory)))check(strcmp(entry->d_name,"987654")!=0,39);
 closedir(directory);
 put("/home/retroos/config.toml","old",0644);put("/home/retroos/.config.tmp","trusted",0600);
 check(rename("/home/retroos/.config.tmp","/home/retroos/config.toml")==0,24);contents("/home/retroos/config.toml","trusted");
 check(access("/home/retroos/.config.tmp",F_OK)==-1&&errno==ENOENT,25);
 check(stat("/home/retroos/config.toml",&st)==0&&(st.st_mode&0777)==0600,26);
 check(rename("/home/retroos/config.toml","/home/retroos/config.toml")==0,27);
 put("/home/retroos/.config.tmp","new",0600);check(renameat(AT_FDCWD,"/home/retroos/.config.tmp",AT_FDCWD,"/home/retroos/config.toml")==0,28);contents("/home/retroos/config.toml","new");
 check(rename("/home/retroos/missing","/home/retroos/config.toml")==-1&&errno==ENOENT,29);contents("/home/retroos/config.toml","new");
 check(mkdir("/home/retroos/dir",0700)==0,30);errno=0;check(rename("/home/retroos/config.toml","/home/retroos/dir")==-1&&errno==EISDIR,31);contents("/home/retroos/config.toml","new");
 put("/home/retroos/dir/child","keep",0600);check(mkdir("/home/retroos/empty",0700)==0,32);errno=0;
 check(rename("/home/retroos/empty","/home/retroos/dir")==-1&&errno==ENOTEMPTY,33);contents("/home/retroos/dir/child","keep");
 // Existing readers remain protected until inode lifetime support is added.
 fd=open("/home/retroos/config.toml",O_RDONLY);check(fd>=0,34);put("/home/retroos/.config.tmp","last",0600);
 check(rename("/home/retroos/.config.tmp","/home/retroos/config.toml")==-1&&errno==EBUSY,35);close(fd);contents("/home/retroos/config.toml","new");
 check(rename("/home/retroos/.config.tmp","/home/retroos/config.toml")==0,36);contents("/home/retroos/config.toml","last");
 check(mkdir("/home/retroos/other",0700)==0,40);
 check(rename("/home/retroos/empty","/home/retroos/other")==0,41);
 check(rename("/home/retroos/dir","/home/retroos/dir/subdir")==-1&&errno==EINVAL,42);
 dprintf(2,"PERSISTENCE_PASS: process birth identity and atomic config replacement\n");return 0;
}
