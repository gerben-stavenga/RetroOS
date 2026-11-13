#!/usr/bin/env python3
"""Native KVM: fork/COW on distinct CPUs, stable process affinity, BSP services."""
from pathlib import Path
import argparse
import re
import subprocess
import tempfile
from boot_fixture import ROOT, prepare_boot

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cpus', type=int, default=5)
    parser.add_argument('--boot-image', type=Path, help='Validate a supplied self-built boot disk')
    parser.add_argument('--bits', type=int, choices=(32,64), default=64)
    args = parser.parse_args()
    expected=min(16,max(1,args.cpus-1)) if args.cpus>=3 else 1
    artifacts = ROOT/'build/ci/linux-parallel'
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-parallel-') as temp:
        work=Path(temp); tree=work/'root'
        (tree/'home/retroos/RETROOS').mkdir(parents=True)
        source = ROOT / ('test/linux_parallel_probe.c' if args.bits == 64 else 'test/linux_parallel_probe32.c')
        flags = [] if args.bits == 64 else ['-m32','-nostdlib','-fno-pie','-fno-stack-protector',f'-DEXPECTED={expected}']
        subprocess.run(['gcc','-O2','-static','-no-pie',*flags,str(source),'-o',str(tree/'probe')],check=True)
        (tree/'shared').write_bytes(bytes(4096))
        (tree/'shared').chmod(0o666)
        image=work/'root.ext4'
        with image.open('wb') as out: out.truncate(64*1024*1024)
        subprocess.run(['mkfs.ext4','-q','-F','-d',str(tree),str(image)],check=True)
        boot=prepare_boot(work,image,f'[environment]\nTEST=/probe {expected}\n', boot_image=args.boot_image)
        log=artifacts/f'cpus-{args.cpus}-bits-{args.bits}.log'
        with log.open('w') as out:
            result=subprocess.run(['qemu-system-x86_64','-accel','kvm','-cpu','host','-smp',str(args.cpus),'-m','512',
                '-display','none','-serial','none','-monitor',f'unix:{artifacts}/cpus-{args.cpus}-bits-{args.bits}.monitor,server=on,wait=off','-no-reboot','-nic','none','-debugcon','stdio',
                '-drive',f'file={boot},format=raw,snapshot=on','-drive',f'file={image},format=raw,snapshot=on'],
                stdout=out,stderr=subprocess.STDOUT,timeout=90)
        text=log.read_text()
        assert result.returncode==0 and 'PARALLEL_PROCESS_PASS' in text and '[mem] exit tid=1 code=0' in text,text[-8000:]
        if args.bits == 64:
            if expected > 2:
                assert int(re.search(r"peak_concurrent_handlers=(\d+)",text)[1]) > 1, text[-3000:]
                assert int(re.search(r"parallel_lifecycles=(\d+)",text)[1]) > 0, text[-3000:]
            handlers={int(cpu):int(count) for cpu,count in re.findall(r'SMP: CPU (\d+) syscalls=(\d+)',text)}
            assert sum(count>0 for count in handlers.values())>=expected-1,handlers
        print('\n'.join(line for line in text.splitlines() if 'PARALLEL_' in line),flush=True)
if __name__=='__main__': main()
