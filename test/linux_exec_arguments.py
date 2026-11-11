#!/usr/bin/env python3
"""Exec must preserve long arguments and reject oversized inputs without truncation."""
import subprocess
import tempfile
from pathlib import Path
from boot_fixture import ROOT, prepare_boot


def main():
    artifacts = ROOT / 'build/ci'
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-exec-arguments-') as directory:
        work = Path(directory)
        tree = work / 'root'
        (tree / 'home/retroos/RETROOS').mkdir(parents=True)
        subprocess.run(['gcc', '-O2', '-static',
                        str(ROOT / 'test/linux_exec_arguments_probe.c'),
                        '-o', str(tree / 'probe')], check=True)
        subprocess.run([str(tree / 'probe')], check=True, timeout=5)
        data = work / 'data.img'
        with data.open('wb') as output:
            output.truncate(32 * 1024 * 1024)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(data)], check=True)
        boot = prepare_boot(work, data, '[environment]\nTEST=/probe\n')
        log = artifacts / 'linux-exec-arguments.log'
        with log.open('w') as output:
            process = subprocess.Popen(['qemu-system-x86_64', '-accel', 'kvm',
                '-cpu', 'host', '-m', '256', '-display', 'none', '-serial', 'none',
                '-no-reboot', '-nic', 'none', '-debugcon', 'stdio',
                '-drive', f'file={boot},format=raw,snapshot=on',
                '-drive', f'file={data},format=raw,snapshot=on'],
                stdout=output, stderr=subprocess.STDOUT)
            try:
                process.wait(timeout=40)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
        text = log.read_text()
        assert process.returncode == 0 and 'EXEC_ARGUMENTS_PASS:' in text \
            and '[mem] exit tid=1 code=0' in text and 'SEGV' not in text, text[-3000:]
        print('PASS: exec argument and environment bounds')


if __name__ == '__main__':
    main()
