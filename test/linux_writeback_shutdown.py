#!/usr/bin/env python3
"""Verify orderly shutdown persists unsynced data before background writeback."""
from pathlib import Path
import subprocess
import tempfile
from boot_fixture import ROOT, prepare_boot


def main():
    with tempfile.TemporaryDirectory(prefix='retroos-writeback-shutdown-') as directory:
        work=Path(directory);tree=work/'root'
        (tree/'home/retroos/RETROOS').mkdir(parents=True)
        subprocess.run(['gcc','-O2','-static',str(ROOT/'test/linux_writeback_shutdown_probe.c'),
                        '-o',str(tree/'probe')],check=True)
        data=work/'data.ext4'
        with data.open('wb') as output:output.truncate(32*1024*1024)
        subprocess.run(['mkfs.ext4','-q','-F','-d',str(tree),str(data)],check=True)
        boot=prepare_boot(work,data,'[environment]\nTEST=/probe\n')
        log=ROOT/'build/ci/linux-writeback-shutdown.log';log.parent.mkdir(parents=True,exist_ok=True)
        with log.open('w') as output:
            process=subprocess.Popen(['qemu-system-x86_64','-accel','kvm','-cpu','host','-m','512',
                '-display','none','-serial','none','-no-reboot','-nic','none','-debugcon','stdio',
                '-drive',f'file={boot},format=raw,snapshot=on',
                '-drive',f'file={data},format=raw'],stdout=output,stderr=subprocess.STDOUT)
            try:process.wait(timeout=40)
            finally:
                if process.poll() is None:process.terminate();process.wait(timeout=5)
        text=log.read_text()
        assert process.returncode==0 and 'WRITEBACK_SHUTDOWN_PASS:' in text and '[mem] exit tid=1 code=0' in text,text[-3000:]
        assert 'Storage sync failed' not in text,text[-3000:]
        extracted=work/'data.bin'
        subprocess.run(['debugfs','-R',f'dump /home/retroos/shutdown-data {extracted}',str(data)],check=True,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        assert extracted.read_bytes()==bytes((i*37+11)&255 for i in range(70003))
        check=subprocess.run(['e2fsck','-fn',str(data)],capture_output=True,text=True)
        assert check.returncode==0,check.stdout+check.stderr
    print('PASS: unsynced file persisted on shutdown; e2fsck clean')


if __name__=='__main__':main()
