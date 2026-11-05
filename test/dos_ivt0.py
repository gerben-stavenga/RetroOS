#!/usr/bin/env python3
"""Check scoped IVT0 aliases, handler chaining, restoration and shell wrappers."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix='retroos-ivt0-') as directory:
        root = Path(directory)
        (root / 'RETROOS').mkdir()
        shutil.copyfile(ROOT / 'bazel-bin/tools/command/COMMAND.COM', root / 'COMMAND.COM')
        probe = ROOT / 'bazel-bin/test/dos/ivt0/IVT0.COM'
        for name in ('PROBE.COM', 'GUARD.COM', 'PUSH.COM'):
            shutil.copyfile(probe, root / name)
        (root / 'RETROOS/RETROOS.INI').write_text(
            '[launch]\nGUARD.COM=ivt0\nPUSH.COM=ivt0 loadfix\n')
        (root / 'CHECK.BAT').write_text(
            '@echo off\nPROBE.COM I\n'
            'GUARD.COM C\nPROBE.COM R\n'
            'PUSH.COM C\nPROBE.COM R\n'
            'COMMAND.COM /V GUARD.COM A\nPROBE.COM R\n'
            'COMMAND.COM /V MISSING.COM\nPROBE.COM R\n'
            'ECHO IVT0 SUITE PASS\n')
        for command, expected in (
            ('/COMMAND.COM /B C:\\CHECK.BAT', 7),
            ('/COMMAND.COM /C C:\\GUARD.COM A', 1),
            ('/COMMAND.COM /E C:\\GUARD.COM A', 1),
        ):
            result = subprocess.run([
                'python3', 'test/disk_fixture.py', '--root', directory, '--',
                'bazel-bin/kernel/retroos-host', '--c-root', '/',
                '--cmd', command, '--cwd', '/',
            ], cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, timeout=60)
            log = result.stdout
            if (result.returncode or log.count('IVT0 PROBE PASS') != expected
                    or any(error in log for error in ('IVT0 PROBE FAIL', 'PANIC', 'SEGV'))):
                raise AssertionError(log)
            print(f'PASS: {command}')


if __name__ == '__main__':
    main()
