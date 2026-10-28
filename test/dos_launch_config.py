#!/usr/bin/env python3
"""Launch settings beyond 32 entries and live edits in one DOS shell."""
from pathlib import Path
import re
import os
import signal
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    if not os.access('/dev/kvm', os.R_OK | os.W_OK):
        raise SystemExit('KVM access is required for CPU-policy checks')
    host = 'retroos-host-kvm'
    subprocess.run(['bazelisk', 'build', '//tools/command:command_com'], cwd=ROOT, check=True)
    command = (ROOT / 'bazel-bin/tools/command/COMMAND.COM').resolve()
    subprocess.run(['bazelisk', 'build', f'//kernel:{host}', '--platforms=@platforms//host'],
                   cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix='retroos-launch-config-') as directory:
        root = Path(directory)
        (root / 'RETROOS').mkdir()
        shutil.copyfile(command, root / 'COMMAND.COM')
        # A tiny, terminating COM is enough: the kernel logs the selected duty.
        (root / 'PROBE.COM').write_bytes(bytes.fromhex('b8004ccd21'))
        entries = ''.join(f'GAME{i}.EXE=repair\n' for i in range(128))
        initial = '[launch]\n' + entries + 'PROBE.COM=cpu25\n'
        (root / 'RETROOS/RETROOS.INI').write_text(initial)
        (root / 'SECOND.INI').write_text('[launch]\n' + entries + 'probe.com=cpu75\n')
        (root / 'EMPTY.INI').write_text('[launch]\n' + entries)
        (root / 'CHECK.BAT').write_text(
            '@echo off\n'
            'PROBE.COM\n'
            'COPY SECOND.INI C:\\RETROOS\\RETROOS.INI\n'
            'PROBE.COM\n'
            'COPY EMPTY.INI C:\\RETROOS\\RETROOS.INI\n'
            'PROBE.COM\n'
            'ECHO LAUNCH-CONFIG-PASS\n')
        process = subprocess.Popen([
            'python3', 'test/disk_fixture.py', '--root', directory, '--',
            str(ROOT / f'bazel-bin/kernel/{host}'), '--c-root', '/',
            '--cmd', '/COMMAND.COM /B C:\\CHECK.BAT', '--cwd', '/',
        ], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            start_new_session=True)
        try:
            log, _ = process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            log, _ = process.communicate(timeout=10)
            raise SystemExit('Launch test timed out:\n' + log)
        limits = re.findall(r'DOS CPU limit: (\d+)%', log)
        if (process.returncode or limits != ['25', '75'] or 'LAUNCH-CONFIG-PASS' not in log
                or any(error in log for error in ('PANIC', 'FATAL', 'Bad command', 'SEGV'))):
            raise SystemExit(log)
        print('PASS: >32 launch entries, live replacement and removal in one shell (kvm)')


if __name__ == '__main__':
    main()
