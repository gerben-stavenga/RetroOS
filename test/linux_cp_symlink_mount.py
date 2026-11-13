#!/usr/bin/env python3
"""Copy an SMB source through a native symlink, checking dirent inode identity."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from boot_fixture import ROOT

SOURCE = r'''
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { perror("SMB_COPY_FAIL"); dprintf(2,"line=%d\n",__LINE__); exit(1); } } while(0)
struct entry { uint64_t ino; int64_t off; unsigned short len; unsigned char type; char name[]; };
int main(void) {
    int dir=open("/home/retroos/source",O_RDONLY|O_DIRECTORY); CHECK(dir>=0);
    char bytes[4096]; unsigned count=0;
    for (;;) {
        long n=syscall(SYS_getdents64,dir,bytes,sizeof bytes); CHECK(n>=0);
        if (!n) break;
        for (long pos=0;pos<n;) {
            struct entry *entry=(void *)(bytes+pos); CHECK(entry->len && pos+entry->len<=n);
            if (strcmp(entry->name,".") && strcmp(entry->name,"..")) {
                struct stat st; CHECK(!fstatat(dir,entry->name,&st,0));
                CHECK(st.st_ino==entry->ino); count++;
                int fd=openat(dir,entry->name,O_RDONLY); CHECK(fd>=0);
                struct stat opened; CHECK(!fstat(fd,&opened));
                if (opened.st_ino!=st.st_ino) dprintf(2,"inode mismatch %s stat=%llu fstat=%llu\n",entry->name,(unsigned long long)st.st_ino,(unsigned long long)opened.st_ino);
                CHECK(opened.st_ino==st.st_ino && !close(fd));
            }
            pos+=entry->len;
        }
    }
    CHECK(count==25 && !close(dir));
    pid_t child=fork(); CHECK(child>=0);
    if (!child) { execl("/usr/bin/cp","cp","-L","-R","/home/retroos/source/.","/home/retroos/copied",(char *)0); _exit(127); }
    int status; CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    for (int i=0;i<24;i++) {
        char path[128],expected[32]; snprintf(path,sizeof path,"/home/retroos/copied/file-%d",i);
        int fd=open(path,O_RDONLY); CHECK(fd>=0);
        int n=snprintf(expected,sizeof expected,"copied-file-%d",i);
        CHECK(read(fd,bytes,sizeof bytes)==n && !memcmp(bytes,expected,n) && !close(fd));
    }
    int fd=open("/home/retroos/copied/configure",O_RDONLY); CHECK(fd>=0);
    CHECK(read(fd,bytes,sizeof bytes)==10 && !memcmp(bytes,"#!/bin/sh\n",10) && !close(fd));
    dprintf(2,"SMB_SYMLINK_COPY_PASS\n"); return 0;
}
'''


def main():
    artifacts=ROOT/'build/ci'; artifacts.mkdir(parents=True,exist_ok=True)
    # Guest /tmp is a RAM mount, so keep the exported source under the project.
    with tempfile.TemporaryDirectory(prefix='retroos-copy-mount-',dir=artifacts) as directory:
        work=Path(directory); source=work/'source'; source.mkdir()
        for i in range(24): (source/f'file-{i}').write_text(f'copied-file-{i}')
        (source/'configure').write_text('#!/bin/sh\n')
        tree=work/'root'; home=tree/'home/retroos'; (home/'RETROOS').mkdir(parents=True)
        (home/'source').symlink_to(source)
        shutil.copyfile(ROOT/'etc/RETROOS.INI',home/'RETROOS/RETROOS.INI')
        probe=work/'probe.c'; probe.write_text(SOURCE)
        subprocess.run(['gcc','-static','-O2',str(probe),'-o',str(home/'probe')],check=True)
        image=work/'home.ext4'
        with image.open('wb') as out: out.truncate(64*1024*1024)
        subprocess.run(['mkfs.ext4','-q','-F','-d',str(tree),str(image)],check=True)
        profile=work/'profile.json'; profile.write_text(json.dumps({'root':'/','c_root':str(home),'native_home_image':str(image)}))
        env=os.environ.copy(); env.pop('RETROOS_DATA_IMAGE',None); env['RETROOS_QEMU_LIVE_PROFILE']=str(profile)
        log=artifacts/'linux-cp-symlink-mount.log'
        with log.open('w') as output:
            result=subprocess.run([str(ROOT/'run.sh'),'qemu','--kvm','--headless','--sound','none','--cmd','/home/retroos/probe','--',
                '-smp','5','-m','1024','-drive',f'file={image},format=raw,if=none,id=copyhome','-device','nvme,drive=copyhome,serial=SMBCOPY'],
                cwd=ROOT,env=env,stdout=output,stderr=subprocess.STDOUT,timeout=60)
        text=log.read_text()
        assert result.returncode==0 and 'SMB_SYMLINK_COPY_PASS' in text,text[-3500:]
        print('PASS: SMB source through native directory symlink, stat/dirent identity and GNU cp -LR')


if __name__=='__main__': main()
