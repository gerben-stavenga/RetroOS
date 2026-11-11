#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { dprintf(2,"NAMESPACE FAIL %d errno=%d\n",__LINE__,errno); exit(__LINE__); } } while(0)
static void create(const char *p) { int fd=open(p,O_CREAT|O_WRONLY|O_EXCL,0600); CHECK(fd>=0); CHECK(write(fd,"data",4)==4); CHECK(close(fd)==0); CHECK(chmod(p,0444)==0); }
int main(int argc,char **argv) {
 for (int i=0;i<2;i++) {
  int fd=open(i?"/dev/urandom":"/dev/random",O_RDONLY); CHECK(fd>=0);
  struct stat st; CHECK(fstat(fd,&st)==0 && S_ISCHR(st.st_mode));
  unsigned char x[32],y[32]; CHECK(read(fd,x,sizeof x)==sizeof x);
  CHECK(read(fd,y,sizeof y)==sizeof y); CHECK(memcmp(x,y,sizeof x)!=0); CHECK(close(fd)==0);
 }
 char base[512],a[600],b[600],d[600];
 snprintf(base,sizeof base,"%s/namespace-%d",argc>1?argv[1]:"/home/retroos",getpid());
 CHECK(mkdir(base,0700)==0);
 snprintf(a,sizeof a,"%s/a",base); snprintf(b,sizeof b,"%s/b",base); snprintf(d,sizeof d,"%s/d",base);
 create(a); CHECK(unlink(a)==0);
 create(a); create(b); CHECK(rename(a,b)==0); CHECK(access(a,F_OK)==-1 && errno==ENOENT); CHECK(unlink(b)==0);
 CHECK(mkdir(d,0700)==0); CHECK(chmod(d,0555)==0); CHECK(rmdir(d)==0);
 create(a); CHECK(symlink(a,b)==0); CHECK(unlink(b)==0); CHECK(access(a,F_OK)==0);
 if (argc==1) {
  CHECK(unlink("/home/retroos/sticky/owned")==0);
  errno=0; CHECK(unlink("/home/retroos/sticky/foreign")==-1 && errno==EPERM);
  errno=0; CHECK(rename(a,"/home/retroos/sticky/foreign")==-1 && errno==EPERM);
  errno=0; CHECK(rename("/home/retroos/sticky/foreign",b)==-1 && errno==EPERM);
  CHECK(access(a,F_OK)==0 && access("/home/retroos/sticky/foreign",F_OK)==0);
 }
 CHECK(chmod(base,0600)==0); errno=0; CHECK(unlink(a)==-1 && errno==EACCES);
 CHECK(chmod(base,0700)==0);
 CHECK(chmod(base,0500)==0); errno=0; CHECK(unlink(a)==-1 && errno==EACCES);
 fprintf(stderr,"NAMESPACE_PASS: readonly unlink/rename/rmdir, symlink, parent write/search\n");
 return 0;
}
