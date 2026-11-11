#!/usr/bin/env python3
"""Time native ext4 reads while live mappings exceed the clean-cache budget."""
import argparse
from pathlib import Path
import subprocess
import tempfile
from boot_fixture import ROOT, prepare_boot

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--boot-image',type=Path,default=ROOT/'bazel-bin/boot_disk.bin')
    parser.add_argument('--label',default='after')
    args=parser.parse_args()
    log=ROOT/'build/ci'/('cache-budget-'+args.label+'.log')
    log.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-cache-budget-') as directory:
        work=Path(directory);tree=work/'root';(tree/'home/retroos/RETROOS').mkdir(parents=True)
        subprocess.run(['gcc','-O2','-static',str(ROOT/'test/linux_cache_budget_probe.c'),'-o',str(tree/'probe')],check=True)
        (tree/'pins').write_bytes(b'p'*(3*1024*1024));(tree/'data').write_bytes(b'a'*(16*1024*1024))
        image=work/'data.ext4'
        with image.open('wb') as f:f.truncate(64*1024*1024)
        subprocess.run(['mkfs.ext4','-q','-F','-d',str(tree),str(image)],check=True)
        boot=prepare_boot(work,image,'[environment]\nTEST=/probe\n',boot_image=args.boot_image)
        with log.open('w') as output:
            r=subprocess.run(['qemu-system-x86_64','-accel','kvm','-cpu','host','-m','512','-display','none','-serial','none','-no-reboot','-nic','none','-debugcon','stdio','-drive',f'file={boot},format=raw,snapshot=on','-drive',f'file={image},format=raw,if=none,id=data','-device','nvme,drive=data,serial=CACHEBUDGET'],stdout=output,stderr=subprocess.STDOUT,timeout=60)
        text=log.read_text();assert r.returncode==0 and 'CACHE_BUDGET_PASS' in text and '[mem] exit tid=1 code=0' in text,text[-3000:]
        print(next(line for line in text.splitlines() if 'CACHE_BUDGET_PASS' in line))
if __name__=='__main__':main()
