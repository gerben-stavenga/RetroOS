#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static void check(int ok,int code){if(!ok){dprintf(2,"BATCH FAIL %d errno=%d\n",code,errno);_exit(code);}}
int main(void){
 const char *name="/home/retroos/batch";int fd=open(name,O_CREAT|O_TRUNC|O_RDWR,0600);check(fd>=0,1);
 char bytes[1024];memset(bytes,'b',sizeof bytes);struct stat st;
 for(int i=1;i<=64;i++){
  check(write(fd,bytes,sizeof bytes)==sizeof bytes,2);
  check(stat(name,&st)==0&&st.st_size==i*1024,3);
  int other=open("/home/retroos/other",O_RDONLY);check(other>=0,4);close(other);
  DIR *dir=opendir("/home/retroos");check(dir!=0,5);int found=0;struct dirent *entry;
  while((entry=readdir(dir)))if(!strcmp(entry->d_name,"batch"))found=1;
  closedir(dir);check(found,6);
 }
 check(lseek(fd,0,SEEK_SET)==0,8);
 for(int i=0;i<64;i++){
  check(read(fd,bytes,sizeof bytes)==sizeof bytes,9);
  for(unsigned j=0;j<sizeof bytes;j++)check(bytes[j]=='b',10);
 }
 check(fsync(fd)==0,7);close(fd);
 dprintf(2,"BATCH_PASS: pending size visible during metadata and unrelated closes\n");return 0;
}
