#!/usr/bin/env python3
"""Persistent SMB symlinks through Linux ABIs and independent MF wire checks."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from linux_symlink import LONG_DIR

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / 'build/ci'


def launch(work, program, label, timeout=120, memory=None):
    env = os.environ.copy()
    env.pop('RETROOS_DATA_IMAGE', None)
    env['RETROOS_QEMU_LIVE_PROFILE'] = str(work / 'profile.json')
    log = ARTIFACTS / (label + '.log')
    command = [str(ROOT / 'run.sh'), 'qemu', '--kvm', '--headless',
        '--sound', 'none', '--cmd', '/home/retroos/' + program]
    if memory is not None:
        command += ['--', '-m', str(memory)]
    with log.open('w') as output:
        process = subprocess.Popen(command, cwd=ROOT,
            env=env, stdout=output, stderr=subprocess.STDOUT)
        try:
            process.wait(timeout=timeout)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=15)
    assert process.returncode == 0 and '[mem] exit tid=1 code=0' in log.read_text(), str(log)
    print('PASS: ' + label, flush=True)


def main():
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-smb-links-') as directory:
        for bits in (64, 32):
            work = Path(directory) / str(bits)
            home = work / 'c'
            (home / 'RETROOS').mkdir(parents=True)
            (home / LONG_DIR).mkdir()
            (home / 'target').write_bytes(b'LINKOK')
            (home / LONG_DIR / 'target').write_bytes(b'LINKOK')
            shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
            (work / 'profile.json').write_text(json.dumps({'root': '/', 'c_root': str(home)}))
            for program, flags in [('probe', []), ('verify', ['-DVERIFY_SMB'])]:
                subprocess.run(['gcc', f'-m{bits}', '-nostdlib', '-static', '-no-pie',
                    '-fno-pie', '-fno-stack-protector', '-DSMB', *flags,
                    str(ROOT / 'test/linux_symlink_probe.c'), '-o', str(home / program)], check=True)
            launch(work, 'probe', f'smb-symlink-{bits}')
            for name, target in [('relative', 'target'), ('absolute', '/home/retroos/target'),
                                 ('dangling', 'missing'), ('long', LONG_DIR + '/target'),
                                 ('boundary59', 'x' * 59), ('boundary60', 'x' * 60)]:
                data = (home / name).read_bytes()
                expected = target.encode()
                assert len(data) == 1067 and data[:5] == b'XSym\n', name
                assert int(data[5:9]) == len(expected), name
                assert data[10:42] == hashlib.md5(expected).hexdigest().encode(), name
                assert data[43:43 + len(expected)] == expected, name
            launch(work, 'verify', f'smb-symlink-{bits}-reboot')


if __name__ == '__main__':
    main()
