#!/usr/bin/env python3
"""Process liveness, self delivery, masked signals and killing a blocked child."""
import subprocess
import tempfile
from pathlib import Path
from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parents[1]

def main():
    artifacts = ROOT / 'build/ci'
    artifacts.mkdir(parents=True, exist_ok=True)
    for bits in (64, 32):
        with tempfile.TemporaryDirectory(prefix='retroos-kill-') as directory:
            work = Path(directory)
            tree = work / 'root'
            (tree / 'home/retroos/RETROOS').mkdir(parents=True)
            subprocess.run(['gcc', f'-m{bits}', '-static', '-O2', str(ROOT / 'test/linux_kill_probe.c'), '-o', str(tree / 'probe')], check=True)
            data = work / 'data.img'
            with data.open('wb') as output:
                output.truncate(32 * 1024 * 1024)
            subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(data)], check=True)
            boot = prepare_boot(work, data, '[environment]\nTEST=/probe\n')
            log = artifacts / f'linux-kill-{bits}.log'
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
            assert process.returncode == 0 and 'KILL_PASS' in text and '[mem] exit tid=1 code=0' in text, text[-3000:]
            print(f'PASS: kill {bits}-bit', flush=True)

if __name__ == '__main__':
    main()
