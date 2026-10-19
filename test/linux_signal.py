#!/usr/bin/env python3
"""Native Linux fault signal frames, alternate stacks and signal return."""
from pathlib import Path
import subprocess
import tempfile
from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parents[1]


def run_case(failure):
    with tempfile.TemporaryDirectory(prefix='retroos-signal-') as directory:
        work = Path(directory)
        tree = work / 'root'
        (tree / 'home/retroos/RETROOS').mkdir(parents=True)
        subprocess.run(['gcc', '-nostdlib', '-static', '-no-pie', '-fno-pie',
            *(['-D' + failure] if failure else []), str(ROOT / 'test/linux_signal_probe.c'), '-o', str(tree / 'probe')], check=True)
        data = work / 'data.img'
        with data.open('wb') as output:
            output.truncate(32 * 1024 * 1024)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(data)], check=True)
        boot = prepare_boot(work, data, '[environment]\nTEST=/probe\n')
        log = ROOT / 'build/ci' / ('linux-signal-' + (failure or 'restore') + '.log')
        with log.open('w') as output:
            process = subprocess.Popen(['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host',
                '-m', '256', '-display', 'none', '-serial', 'none', '-no-reboot', '-nic', 'none',
                '-debugcon', 'stdio', '-drive', f'file={boot},format=raw,snapshot=on',
                '-drive', f'file={data},format=raw,snapshot=on'], stdout=output, stderr=subprocess.STDOUT)
            try:
                process.wait(timeout=40)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
        text = log.read_text()
        expected = '[mem] exit tid=1 code=' + ('-11' if failure else '0')
        assert process.returncode == 0 and expected in text and 'PANIC' not in text, text[-2500:]
        print('PASS: native Linux signals ' + (failure or 'context restore'), flush=True)


def main():
    subprocess.run(['bazelisk', 'build', '//:boot_disk'], cwd=ROOT, check=True)
    for failure in (None, 'BAD_MXCSR', 'BAD_PC'):
        run_case(failure)


if __name__ == '__main__':
    main()
