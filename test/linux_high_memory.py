#!/usr/bin/env python3
"""Exercise sparse long-mode page tables with only 256 MiB of guest RAM."""
from pathlib import Path
import argparse
import subprocess
import tempfile
from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpus", type=int, default=1)
    args = parser.parse_args()
    artifacts = ROOT / 'build/ci'
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-high-memory-') as directory:
        work = Path(directory)
        tree = work / 'root'
        (tree / 'home/retroos/RETROOS').mkdir(parents=True)
        cases = [None, 'READ_ONLY', 'NO_ACCESS', 'UNMAPPED', 'NO_EXECUTE']
        for failure in cases:
            label = failure or 'main'
            subprocess.run(['gcc', '-m64', '-nostdlib', '-static', '-no-pie',
                '-fno-pie', '-fno-stack-protector', '-mno-red-zone',
                *(['-D' + failure] if failure else []),
                str(ROOT / 'test/linux_high_memory_probe.c'), '-o', str(tree / label)], check=True)
        data = work / 'data.img'
        with data.open('wb') as output:
            output.truncate(32 * 1024 * 1024)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(data)], check=True)
        for failure in cases:
            label = failure or 'main'
            boot = prepare_boot(work, data, '[environment]\nTEST=/' + label + '\n')
            log = artifacts / ('high-memory-' + label + '.log')
            with log.open('w') as output:
                process = subprocess.Popen(['qemu-system-x86_64', '-accel', 'kvm',
                    '-cpu', 'host', '-smp', str(args.cpus), '-m', '256', '-display', 'none', '-serial', 'none',
                    '-no-reboot', '-nic', 'none', '-debugcon', 'stdio',
                    '-drive', f'file={boot},format=raw,snapshot=on',
                    '-drive', f'file={data},format=raw,snapshot=on'],
                    stdout=output, stderr=subprocess.STDOUT)
                try:
                    process.wait(timeout=45)
                finally:
                    if process.poll() is None:
                        process.terminate()
                        process.wait(timeout=5)
            text = log.read_text()
            expected = '[mem] exit tid=1 code=' + ('-11' if failure else '0')
            assert process.returncode == 0 and expected in text and 'PANIC' not in text, text[-4500:]
            print('PASS: high-memory ' + label, flush=True)


if __name__ == '__main__':
    main()
