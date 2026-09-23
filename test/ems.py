#!/usr/bin/env python3
"""Exercise the EMS services used by Aladdin, without proprietary assets.

ENGINE=tcg|kvm python3 test/ems.py
python3 test/ems.py --qemu [--kvm]
"""
import argparse
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', action='store_true')
    parser.add_argument('--kvm', action='store_true')
    args = parser.parse_args()
    os.chdir(ROOT)
    engine = os.environ.get('ENGINE', 'tcg')
    if engine not in ('tcg', 'kvm'):
        parser.error('ENGINE must be tcg or kvm')
    subprocess.run(['bazelisk', 'build', '//test/dos/emsprobe:emsprobe_com'], check=True)
    with tempfile.TemporaryDirectory(prefix='retroos-ems-') as tmp:
        work = Path(tmp)
        probe = ROOT / 'bazel-bin/test/dos/emsprobe/EMSPROBE.COM'
        if args.qemu:
            subprocess.run(['bazelisk', 'build', '//:data_disk'], check=True)
            disk = work / 'data.bin'
            subprocess.run(['python3', 'test/private_data_disk.py',
                            'bazel-bin/data_disk.bin', str(disk)], check=True)
            with disk.open('rb') as source:
                offset = struct.unpack_from('<I', source.read(512), 454)[0] * 512
            subprocess.run(['mcopy', '-o', '-i', f'{disk}@@{offset}',
                            str(probe), '::EMSPROBE.COM'], check=True)
            command = ['./run.sh', 'qemu', '--headless', '--sound', 'none',
                       '--data-image', str(disk), '--cmd', 'EMSPROBE.COM']
            if args.kvm:
                command.append('--kvm')
        else:
            target = 'retroos-host' + ('-kvm' if args.kvm or engine == 'kvm' else '')
            subprocess.run(['bazelisk', 'build', f'//kernel:{target}',
                            '--platforms=@platforms//host'], check=True)
            root = work / 'home/retroos'
            root.mkdir(parents=True)
            shutil.copyfile(probe, root / 'EMSPROBE.COM')
            command = [f'bazel-bin/kernel/{target}', '--host', tmp, '--cmd', 'EMSPROBE.COM']
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                start_new_session=True)
        try:
            output, _ = proc.communicate(timeout=180 if args.qemu else 60)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            output, _ = proc.communicate()
            raise AssertionError('EMS probe timed out\n' + output.decode(errors='replace'))
        text = output.decode(errors='replace')
        if proc.returncode or 'EMSPROBE PASS' not in text or 'EMSPROBE FAIL' in text:
            raise AssertionError(text)
        print('PASS: EMS aliases, saved maps, move/exchange, validation and resize')


if __name__ == '__main__':
    main()
