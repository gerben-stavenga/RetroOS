#!/usr/bin/env python3
"""A kernel boot UUID on a real ext4 root without a host /proc mount."""
from pathlib import Path
import re
import subprocess
import tempfile
from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parents[1]


def main():
    artifacts = ROOT / 'build/ci'
    artifacts.mkdir(parents=True, exist_ok=True)
    identifiers = []
    with tempfile.TemporaryDirectory(prefix='retroos-boot-id-') as directory:
        work = Path(directory)
        tree = work / 'root'
        (tree / 'home/retroos/RETROOS').mkdir(parents=True)
        subprocess.run(['gcc', '-static', '-O2', str(ROOT / 'test/linux_boot_id_probe.c'), '-o', str(tree / 'probe')], check=True)
        data = work / 'data.img'
        with data.open('wb') as output:
            output.truncate(32 * 1024 * 1024)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(data)], check=True)
        boot = prepare_boot(work, data, '[environment]\nTEST=/probe\n')
        for number in range(2):
            log = artifacts / f'linux-boot-id-{number}.log'
            with log.open('w') as output:
                process = subprocess.Popen(['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host',
                    '-m', '256', '-display', 'none', '-serial', 'none', '-no-reboot', '-nic', 'none',
                    '-debugcon', 'stdio', '-drive', f'file={boot},format=raw,snapshot=on',
                    '-drive', f'file={data},format=raw,snapshot=on'], stdout=output, stderr=subprocess.STDOUT)
                try:
                    process.wait(timeout=45)
                finally:
                    if process.poll() is None:
                        process.terminate()
                        process.wait(timeout=5)
            text = log.read_text()
            assert process.returncode == 0 and '[mem] exit tid=1 code=0' in text and 'PANIC' not in text, text[-3000:]
            match = re.search(r'BOOT_ID=([0-9a-f-]{36})', text)
            assert match, text[-3000:]
            identifiers.append(match[1])
            print('PASS: native boot ID reads, seek, fork/exec and read-only metadata', flush=True)
    assert identifiers[0] != identifiers[1], identifiers
    print('PASS: boot ID changes across kernel boots')


if __name__ == '__main__':
    main()
