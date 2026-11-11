#!/usr/bin/env python3
"""Check private futex wakeups, thread joins and timeouts under load."""
import subprocess
import tempfile
from boot_fixture import ROOT, prepare_boot
from pathlib import Path


def main():
    artifacts = ROOT/'build/ci'
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-private_futex-') as directory:
        work = Path(directory)
        tree = work/'root'
        (tree/'home/retroos/RETROOS').mkdir(parents=True)
        subprocess.run(['gcc', '-O2', '-pthread', '-static', str(ROOT/'test/linux_private_futex_probe.c'), '-o', str(tree/'probe')], check=True)
        subprocess.run([str(tree/'probe')], check=True, timeout=15)
        image = work/'data.ext4'
        with image.open('wb') as stream: stream.truncate(32*1024*1024)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(image)], check=True)
        boot = prepare_boot(work, image, '[environment]\nTEST=/probe\n')
        log = artifacts/'linux-private_futex.log'
        with log.open('w') as output:
            result = subprocess.run(['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host', '-m', '512',
                '-display', 'none', '-serial', 'none', '-no-reboot', '-nic', 'none', '-debugcon', 'stdio',
                '-drive', f'file={boot},format=raw,snapshot=on',
                '-drive', f'file={image},format=raw,snapshot=on'], stdout=output, stderr=subprocess.STDOUT, timeout=40)
        text = log.read_text()
        assert result.returncode == 0 and 'PRIVATE_FUTEX_PASS:' in text and '[mem] exit tid=1 code=0' in text, text[-3000:]
    print('PASS: private futex wakeups and timeouts')


if __name__ == '__main__': main()
