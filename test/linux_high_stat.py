#!/usr/bin/env python3
"""Check stat-family syscalls with high guest buffers and paths."""
import argparse
import subprocess
import tempfile
from boot_fixture import ROOT, prepare_boot
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpus", type=int, default=1)
    args = parser.parse_args()
    artifacts = ROOT/'build/ci'
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-high_stat-') as directory:
        work = Path(directory)
        tree = work/'root'
        (tree/'home/retroos/RETROOS').mkdir(parents=True)
        subprocess.run(['gcc', '-O2', '-pthread', '-static', str(ROOT/'test/linux_high_stat_probe.c'), '-o', str(tree/'probe')], check=True)
        image = work/'data.ext4'
        with image.open('wb') as stream: stream.truncate(32*1024*1024)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(image)], check=True)
        boot = prepare_boot(work, image, '[environment]\nTEST=/probe\n')
        log = artifacts/'linux-high_stat.log'
        with log.open('w') as output:
            result = subprocess.run(['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host', '-smp', str(args.cpus), '-m', '512',
                '-display', 'none', '-serial', 'none', '-no-reboot', '-nic', 'none', '-debugcon', 'stdio',
                '-drive', f'file={boot},format=raw,snapshot=on',
                '-drive', f'file={image},format=raw,snapshot=on'], stdout=output, stderr=subprocess.STDOUT, timeout=40)
        text = log.read_text()
        assert result.returncode == 0 and 'HIGH_STAT_PASS:' in text and '[mem] exit tid=1 code=0' in text, text[-3000:]
    print('PASS: high stat buffers and paths')


if __name__ == '__main__': main()
