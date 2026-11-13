#!/usr/bin/env python3
"""Verify Linux time calls write to full-width pointers without low aliases."""
import argparse
import re
import shutil
from pathlib import Path
import subprocess
import tempfile
from boot_fixture import ROOT, prepare_boot


def main(source='linux_time_high_probe.c', marker='HIGH_TIME_PASS:', label='linux-time-high', extra_binaries=()):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path)
    parser.add_argument('--cpus', type=int, default=1)
    parser.add_argument('--label', default=label)
    args = parser.parse_args()
    artifacts = ROOT/'build/ci'
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-time-high-') as directory:
        work=Path(directory);tree=work/'root'
        (tree/'home/retroos/RETROOS').mkdir(parents=True)
        subprocess.run(['gcc', '-O2', '-static', '-pthread', str(ROOT/'test'/source), '-o', str(tree/'probe')], check=True)
        subprocess.run([str(tree/'probe')], check=True, timeout=10)
        for binary in extra_binaries:
            dependencies=subprocess.run(['ldd', binary],capture_output=True,text=True,check=True).stdout
            for path in [binary, *re.findall(r'(/[^\s()]+)', dependencies)]:
                target=tree/path.lstrip('/');target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copy2(path,target)
        image=work/'data.ext4'
        with image.open('wb') as output:output.truncate(32*1024*1024)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(image)], check=True)
        boot=prepare_boot(work, image, '[environment]\nTEST=/probe\n')
        if args.kernel:
            subprocess.run(['mcopy', '-o', '-i', str(boot)+'@@1048576', str(args.kernel.resolve(strict=True)), '::kernel.elf'], check=True)
        log=artifacts/(args.label+'.log')
        with log.open('w') as output:
            result=subprocess.run(['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host', '-smp', str(args.cpus), '-m', '512',
                '-display', 'none', '-serial', 'none', '-no-reboot', '-nic', 'none', '-debugcon', 'stdio',
                '-drive', f'file={boot},format=raw,snapshot=on', '-drive', f'file={image},format=raw,snapshot=on'],
                stdout=output, stderr=subprocess.STDOUT, timeout=40)
        text=log.read_text()
        assert result.returncode == 0 and marker in text and '[mem] exit tid=1 code=0' in text, text[-2500:]
    print('PASS: '+marker)


if __name__ == '__main__': main()
