#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
static void check(int ok,int code){if(!ok){dprintf(2,"UNIX FAIL %d errno=%d\n",code,errno);_exit(code);}}
static void ready(int fd,short events){struct pollfd p={fd,events,0};check(poll(&p,1,3000)>0,90);}
static socklen_t address(struct sockaddr_un *out,const char *path){memset(out,0,sizeof *out);out->sun_family=AF_UNIX;strcpy(out->sun_path,path);return offsetof(struct sockaddr_un,sun_path)+strlen(path)+1;}
int main(void){
 umask(0077);pid_t own=getpid();struct sockaddr_un addr,got;socklen_t n=address(&addr,"/home/retroos/test.sock");
 int listener=socket(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);check(listener>=0,1);
 check(bind(listener,(struct sockaddr *)&addr,n)==0,2);
 struct stat st;check(lstat(addr.sun_path,&st)==0&&S_ISSOCK(st.st_mode)&&(st.st_mode&0777)==0700&&st.st_uid==geteuid()&&st.st_gid==getegid(),3);ino_t first=st.st_ino;
 check(chmod(addr.sun_path,0600)==0&&lstat(addr.sun_path,&st)==0&&(st.st_mode&0777)==0600,4);
 int duplicate=socket(AF_UNIX,SOCK_STREAM,0);check(duplicate>=0,5);errno=0;
 check(bind(duplicate,(struct sockaddr *)&addr,n)==-1&&errno==EADDRINUSE,6);close(duplicate);
 check(listen(listener,4)==0,7);errno=0;check(accept(listener,0,0)==-1&&(errno==EAGAIN||errno==EWOULDBLOCK),8);
 pid_t child=fork();check(child>=0,9);
 if(!child){
  close(listener);int fd=socket(AF_UNIX,SOCK_STREAM,0);check(fd>=0,10);
  check(connect(fd,(struct sockaddr *)&addr,n)==0,11);
  struct ucred peer;socklen_t length=sizeof peer;check(getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&length)==0&&length==sizeof peer&&peer.pid==own&&peer.uid==geteuid()&&peer.gid==getegid(),12);
  length=sizeof got;check(getsockname(fd,(struct sockaddr *)&got,&length)==0&&length==2&&got.sun_family==AF_UNIX,13);
  check(write(fd,"hello",5)==5,14);
  int total=0;char bytes[8192];while(total<80000){int r=read(fd,bytes,sizeof bytes);check(r>0,15);for(int i=0;i<r;i++)check(bytes[i]=='z',16);total+=r;}check(total==80000,17);
  check(read(fd,bytes,1)==0,18);check(write(fd,"done",4)==4,19);close(fd);_exit(0);
 }
 ready(listener,POLLIN);socklen_t length=sizeof got;
 int fd=accept4(listener,(struct sockaddr *)&got,&length,SOCK_NONBLOCK|SOCK_CLOEXEC);check(fd>=0&&length==2&&got.sun_family==AF_UNIX,20);
 check((fcntl(fd,F_GETFL)&O_NONBLOCK)&&(fcntl(fd,F_GETFD)&FD_CLOEXEC),21);
 struct ucred peer;length=sizeof peer;check(getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&length)==0&&peer.pid==child,22);
 ready(fd,POLLIN);char hello[5];check(recv(fd,hello,5,MSG_PEEK)==5&&!memcmp(hello,"hello",5),23);check(read(fd,hello,5)==5,24);
 static char payload[80000];memset(payload,'z',sizeof payload);struct iovec vectors[2]={{payload,40000},{payload+40000,40000}};
 int done=writev(fd,vectors,2);check(done>0&&done<=80000,25);
 while(done<80000){int r=write(fd,payload+done,80000-done);if(r<0&&(errno==EAGAIN||errno==EWOULDBLOCK)){ready(fd,POLLOUT);continue;}check(r>0,26);done+=r;}
 check(shutdown(fd,SHUT_WR)==0,27);ready(fd,POLLIN);char reply[8];check(read(fd,reply,8)==4&&!memcmp(reply,"done",4),28);
 int status;check(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0,29);ready(fd,POLLIN);check(read(fd,reply,1)==0,30);close(fd);
 check(unlink(addr.sun_path)==0,31);
 int replacement=socket(AF_UNIX,SOCK_STREAM,0);check(replacement>=0&&bind(replacement,(struct sockaddr *)&addr,n)==0,32);
 check(lstat(addr.sun_path,&st)==0&&S_ISSOCK(st.st_mode)&&st.st_ino!=first,33);close(listener);
 check(lstat(addr.sun_path,&st)==0&&S_ISSOCK(st.st_mode),34);close(replacement);
 int client=socket(AF_UNIX,SOCK_STREAM,0);errno=0;check(connect(client,(struct sockaddr *)&addr,n)==-1&&errno==ECONNREFUSED,35);check(unlink(addr.sun_path)==0,36);
 errno=0;check(connect(client,(struct sockaddr *)&addr,n)==-1&&errno==ENOENT,37);close(client);
 memset(&addr,0,sizeof addr);addr.sun_family=AF_UNIX;memcpy(addr.sun_path+1,"retroos-abstract",16);n=offsetof(struct sockaddr_un,sun_path)+17;
 listener=socket(AF_UNIX,SOCK_STREAM,0);client=socket(AF_UNIX,SOCK_STREAM,0);check(listener>=0&&client>=0,38);
 check(bind(listener,(struct sockaddr *)&addr,n)==0&&listen(listener,1)==0&&connect(client,(struct sockaddr *)&addr,n)==0,39);
 fd=accept(listener,0,0);check(fd>=0&&write(client,"ok",2)==2&&read(fd,reply,2)==2&&!memcmp(reply,"ok",2),40);
 int ep=epoll_create1(0);check(ep>=0,41);
 struct epoll_event event={.events=EPOLLIN|EPOLLET,.data.fd=fd};
 check(epoll_ctl(ep,EPOLL_CTL_ADD,fd,&event)==0,42);
 check(write(client,"AB",2)==2&&epoll_wait(ep,&event,1,1000)==1,43);
 check(read(fd,reply,1)==1&&reply[0]=='A',44);
 check(write(client,"C",1)==1&&epoll_wait(ep,&event,1,1000)==1,45);
 check(read(fd,reply,2)==2&&!memcmp(reply,"BC",2),46);close(ep);
 close(client);close(fd);close(listener);
 dprintf(2,"UNIX_PASS: named streams, credentials, poll, fork, vectors, close, unlink and abstract names\n");return 0;
}
