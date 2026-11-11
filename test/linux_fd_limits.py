#!/usr/bin/env python3
"""Exercise descriptor-heavy fork/exec and high fd sets on native ext4."""
from pathlib import Path
import subprocess
import tempfile
from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parents[1]

def main():
    artifacts = ROOT / 'build/ci'
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-fd-limits-') as directory:
        for bits in (64, 32):
            work = Path(directory) / str(bits)
            tree = work / 'root'
            (tree / 'home/retroos/RETROOS').mkdir(parents=True)
            subprocess.run(['gcc', f'-m{bits}', '-nostdlib', '-static', '-no-pie', '-fno-pie',
                '-fno-stack-protector', '-O2', str(ROOT / 'test/linux_fd_limits_probe.c'), '-o', str(tree / 'probe')], check=True)
            data = work / 'data.img'
            with data.open('wb') as output: output.truncate(32 * 1024 * 1024)
            subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(data)], check=True)
            boot = prepare_boot(work, data, '[environment]\nTEST=/probe\n')
            log = artifacts / f'fd-limits-{bits}.log'
            with log.open('w') as output:
                process = subprocess.Popen(['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host',
                    '-m', '512', '-display', 'none', '-serial', 'none', '-no-reboot', '-nic', 'none',
                    '-debugcon', 'stdio', '-drive', f'file={boot},format=raw,snapshot=on',
                    '-drive', f'file={data},format=raw,snapshot=on'], stdout=output, stderr=subprocess.STDOUT)
                try: process.wait(timeout=90)
                finally:
                    if process.poll() is None: process.terminate(); process.wait(timeout=10)
            text = log.read_text()
            assert process.returncode == 0 and '[mem] exit tid=1 code=0' in text and 'PANIC' not in text, text[-3000:]
            print(f'PASS: {bits}-bit high descriptors, pselect, CLOEXEC and repeated fork/exec cleanup', flush=True)

if __name__ == '__main__': main()
