#!/usr/bin/env python3
"""Verify file and directory fsync survive killing a running native guest."""
from pathlib import Path
import subprocess
import tempfile
import time
from boot_fixture import ROOT, prepare_boot

SOURCE = r'''
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static void check(int yes,int code){if(!yes){dprintf(2,"FSYNC_FAIL %d\n",code);_exit(code);}}
int main(void){
 check(mkdir("/home/retroos/durable",0700)==0,1);
 int fd=open("/home/retroos/durable/tmp",O_CREAT|O_WRONLY,0600);check(fd>=0,2);
 char bytes[4096];memset(bytes,0x5a,sizeof bytes);
 for(int i=0;i<16;i++)check(write(fd,bytes,sizeof bytes)==sizeof bytes,3);
 check(fsync(fd)==0,4);
 check(rename("/home/retroos/durable/tmp","/home/retroos/durable/final")==0,5);
 int dir=open("/home/retroos/durable",O_RDONLY|O_DIRECTORY);check(dir>=0&&fsync(dir)==0,6);
 int parent=open("/home/retroos",O_RDONLY|O_DIRECTORY);check(parent>=0&&fsync(parent)==0,7);
 dprintf(2,"FSYNC_READY\n");
 for(;;)__asm__ volatile("pause");
}
'''

def main():
    artifacts = ROOT / 'build/ci'
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-fsync-crash-') as directory:
        work = Path(directory)
        tree = work / 'root'
        (tree / 'home/retroos/RETROOS').mkdir(parents=True)
        subprocess.run(['gcc', '-static', '-O2', '-x', 'c', '-', '-o', str(tree / 'probe')], input=SOURCE, text=True, check=True)
        image = work / 'data.img'
        with image.open('wb') as output:
            output.truncate(32 * 1024 * 1024)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(image)], check=True)
        boot = prepare_boot(work, image, '[environment]\nTEST=/probe\n')
        log = artifacts / 'linux-fsync-crash.log'
        with log.open('w') as output:
            process = subprocess.Popen(['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host', '-m', '256',
                '-display', 'none', '-serial', 'none', '-no-reboot', '-nic', 'none', '-debugcon', 'stdio',
                '-drive', f'file={boot},format=raw,snapshot=on', '-drive', f'file={image},format=raw,if=none,id=data',
                '-device', 'nvme,drive=data,serial=FSYNC-CRASH'], stdout=output, stderr=subprocess.STDOUT)
            try:
                end = time.monotonic() + 45
                while time.monotonic() < end:
                    text = log.read_text(errors='replace')
                    assert 'FSYNC_FAIL' not in text and 'PANIC' not in text, text[-2000:]
                    if 'FSYNC_READY' in text:
                        break
                    assert process.poll() is None, text[-2000:]
                    time.sleep(.001)
                else:
                    raise RuntimeError('Guest did not acknowledge fsync')
            finally:
                process.kill()  # No guest close, orderly shutdown or unmount.
                process.wait(timeout=5)
        recovered = work / 'recovered'
        subprocess.run(['debugfs', '-R', f'dump /home/retroos/durable/final {recovered}', str(image)], capture_output=True, check=True)
        assert recovered.read_bytes() == b'Z' * 65536
        check = subprocess.run(['e2fsck', '-fn', str(image)], capture_output=True, text=True)
        assert check.returncode == 0, check.stdout + check.stderr
        print('PASS: file data, rename and parent directories survive abrupt guest termination after fsync')

if __name__ == '__main__':
    main()
