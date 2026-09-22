#!/usr/bin/env python3
"""Exercise per-program XMS reports through COMMAND.COM and batch EXEC."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    os.chdir(ROOT)
    subprocess.run(['bazelisk', 'build', '//tools/command:command_com',
                    '//test/dos/xmsprobe:xmsprobe_com'], check=True)
    subprocess.run(['bazelisk', 'build', '//kernel:retroos-host',
                    '--platforms=@platforms//host'], check=True)
    with tempfile.TemporaryDirectory(prefix='retroos-xms-loadfix-') as tmp:
        root = Path(tmp) / 'home/retroos'
        (root / 'CONFIG').mkdir(parents=True)
        shutil.copyfile('bazel-bin/tools/command/COMMAND.COM', root / 'COMMAND.COM')
        for name in ('LIMITED', 'NORMAL', 'WRAPPED'):
            shutil.copyfile('bazel-bin/test/dos/xmsprobe/XMSPROBE.COM', root / (name + '.COM'))
        (root / 'CONFIG/LOADFIX.CFG').write_text(
            'LIMITED.COM xms32k repair\nWRAPPED.COM loadfix xms32k\n')
        # The second program must not inherit the first one's report limit.
        (root / 'CHECK.BAT').write_bytes(b'LIMITED.COM L\r\nNORMAL.COM U\r\n')
        for command, passes in (
            ('COMMAND.COM /C LIMITED.COM L', 1),
            ('COMMAND.COM /C NORMAL.COM U', 1),
            ('COMMAND.COM /C WRAPPED.COM L', 1),
            ('COMMAND.COM /C CHECK.BAT', 2),
        ):
            result = subprocess.run(
                ['bazel-bin/kernel/retroos-host', '--host', tmp, '--cmd', command],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, timeout=60)
            output = result.stdout.decode(errors='replace')
            if result.returncode or output.count('XMSPROBE PASS') != passes or 'XMSPROBE FAIL' in output:
                raise AssertionError(command + '\n' + output)
            print('PASS:', command)


if __name__ == '__main__':
    main()
