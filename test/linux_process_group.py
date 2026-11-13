#!/usr/bin/env python3
"""Check Inherited process groups and cleanup after group-leader exit."""
import argparse
import subprocess
import tempfile
from boot_fixture import ROOT, prepare_boot
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpus", type=int, default=1)
    parser.add_argument('--boot-image', type=Path)
    args = parser.parse_args()
    artifacts = ROOT/'build/ci'
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-thread_signal-') as directory:
        work = Path(directory)
        tree = work/'root'
        (tree/'home/retroos/RETROOS').mkdir(parents=True)
        subprocess.run(['gcc', '-O2', '-pthread', '-static', str(ROOT/'test/linux_process_group_probe.c'), '-o', str(tree/'probe')], check=True)

        image = work/'data.ext4'
        with image.open('wb') as stream: stream.truncate(32*1024*1024)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(image)], check=True)
        boot = prepare_boot(work, image, '[environment]\nTEST=/probe\n', boot_image=args.boot_image)
        log = artifacts/'linux-process-group.log'
        with log.open('w') as output:
            result = subprocess.run(['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host', '-smp', str(args.cpus), '-m', '512',
                '-display', 'none', '-serial', 'none', '-no-reboot', '-nic', 'none', '-debugcon', 'stdio',
                '-drive', f'file={boot},format=raw,snapshot=on',
                '-drive', f'file={image},format=raw,snapshot=on'], stdout=output, stderr=subprocess.STDOUT, timeout=40)
        text = log.read_text()
        assert result.returncode == 0 and 'PROCESS_GROUP_PASS:' in text and '[mem] exit tid=1 code=0' in text, text[-3000:]
    print('PASS: inherited process groups and isolated group cleanup')


if __name__ == '__main__': main()
