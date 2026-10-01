#!/usr/bin/env python3
"""Check that nested COMMAND.COM keeps both DOS TSR forms visible."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    os.chdir(ROOT)
    subprocess.run(['bazelisk', 'build', '//tools/command:command_com',
                    '//test/dos/tsrsession:tsrsession_com'], check=True)
    subprocess.run(['bazelisk', 'build', '//kernel:retroos-host',
                    '--platforms=@platforms//host'], check=True)
    with tempfile.TemporaryDirectory(prefix='retroos-tsr-session-') as tmp:
        root = Path(tmp) / 'home/retroos'
        root.mkdir(parents=True)
        shutil.copyfile('bazel-bin/tools/command/COMMAND.COM', root / 'COMMAND.COM')
        shutil.copyfile('bazel-bin/test/dos/tsrsession/TSRSESS.COM', root / 'TSRSESS.COM')
        for mode in ('I', 'L'):
            (root / 'SESSION.BAT').write_bytes(
                f'TSRSESS.COM {mode}\r\nCOMMAND.COM /C TSRSESS.COM C\r\n'.encode())
            result = subprocess.run(
                ['bazel-bin/kernel/retroos-host', '--host', tmp,
                 '--cmd', 'COMMAND.COM /B SESSION.BAT', '--cwd', '.'],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, timeout=30)
            output = result.stdout.decode(errors='replace')
            if result.returncode or 'TSR SESSION PASS' not in output or 'TSR SESSION FAIL' in output:
                raise AssertionError(output)
            print(f'PASS: nested COMMAND.COM sees {"INT 27h" if mode == "L" else "AH=31h"} TSR')

        result = subprocess.run(
            ['bazel-bin/kernel/retroos-host', '--host', tmp,
             '--cmd', 'COMMAND.COM /C COMMAND.COM /C TSRSESS.COM I', '--cwd', '.'],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=30)
        output = result.stdout.decode(errors='replace')
        if result.returncode or output.count('synth_fork_exec: filename=') != 1 \
                or 'code=0' not in output:
            raise AssertionError(output)
        print('PASS: outer /C forks once; nested /C uses DOS EXEC')


if __name__ == '__main__':
    main()
