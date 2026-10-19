#!/usr/bin/env python3
"""Native Linux getcpu and legacy x86-64 vsyscalls; invalid entries still fault."""
from pathlib import Path
import subprocess
import tempfile
from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parents[1]


def main():
    subprocess.run(['bazelisk', 'build', '//:boot_disk'], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix='retroos-vsyscall-') as directory:
        work = Path(directory)
        tree = work / 'root'
        (tree / 'home/retroos/RETROOS').mkdir(parents=True)
        cases = [(64, None), (32, None), (64, 'BAD_ENTRY'),
                 (64, 'BAD_OUTPUT'), (64, 'READ_GATE')]
        for bits, failure in cases:
            label = failure or str(bits)
            subprocess.run(['gcc', f'-m{bits}', '-nostdlib', '-static', '-no-pie',
                '-fno-pie', '-fno-stack-protector', *(['-mno-red-zone'] if bits == 64 else []),
                *(['-D' + failure] if failure else []),
                str(ROOT / 'test/linux_vsyscall_probe.c'), '-o', str(tree / label)], check=True)
        data = work / 'data.img'
        with data.open('wb') as output:
            output.truncate(32 * 1024 * 1024)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(data)], check=True)
        for bits, failure in cases:
            label = failure or str(bits)
            boot = prepare_boot(work, data, '[environment]\nTEST=/' + label + '\n')
            log = ROOT / 'build/ci' / ('vsyscall-' + label + '.log')
            with log.open('w') as output:
                process = subprocess.Popen(['qemu-system-x86_64', '-accel', 'kvm',
                    '-cpu', 'host', '-m', '256', '-display', 'none', '-serial', 'none',
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
            assert process.returncode == 0 and expected in text and 'PANIC' not in text, text[-3000:]
            print('PASS: vsyscall ' + label, flush=True)


if __name__ == '__main__':
    main()
