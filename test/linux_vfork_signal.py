#!/usr/bin/env python3
"""A SIGCHLD must not schedule a vfork parent without its address space."""
import argparse
import subprocess
import tempfile
from pathlib import Path
from boot_fixture import ROOT, prepare_boot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpus", type=int, default=1)
    args = parser.parse_args()
    artifacts = ROOT / 'build/ci'
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-vfork-signal-') as directory:
        work = Path(directory)
        tree = work / 'root'
        (tree / 'home/retroos/RETROOS').mkdir(parents=True)
        subprocess.run(['gcc', '-O2', '-static',
                        str(ROOT / 'test/linux_vfork_signal_probe.c'),
                        '-o', str(tree / 'probe')], check=True)
        subprocess.run([str(tree / 'probe')], check=True, timeout=5)
        data = work / 'data.img'
        with data.open('wb') as output:
            output.truncate(32 * 1024 * 1024)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(data)], check=True)
        boot = prepare_boot(work, data, '[environment]\nTEST=/probe\n')
        log = artifacts / 'linux-vfork-signal.log'
        with log.open('w') as output:
            process = subprocess.Popen(['qemu-system-x86_64', '-accel', 'kvm',
                '-cpu', 'host', '-smp', str(args.cpus), '-m', '256', '-display', 'none', '-serial', 'none',
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
        assert process.returncode == 0 and 'VFORK SIGNAL PASS:' in text \
            and '[mem] exit tid=1 code=0' in text and 'SEGV' not in text, text[-3000:]
        print('PASS: vfork parent remains suspended across sibling SIGCHLD')


if __name__ == '__main__':
    main()
