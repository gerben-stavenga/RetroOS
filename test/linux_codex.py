#!/usr/bin/env python3
"""Run the installed native Codex CLI in RetroOS, using live SMB files.

No model request by default. --request uses a private temporary copy of saved
CLI authentication and asks for one response without tool calls.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from setup_codex import setup, DEFAULT_BINARY


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=DEFAULT_BINARY)
    parser.add_argument('--request', action='store_true')
    parser.add_argument('--direct', action='store_true', help='Start /bin/sh directly, bypassing shell.elf as RC does')
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='retroos-codex-') as directory:
        work = Path(directory)
        c_root = work / 'c'
        for child in ('RETROOS', 'TEMP', 'work'):
            (c_root / child).mkdir(parents=True)
        shutil.copyfile(ROOT / 'etc/RETROOS.INI', c_root / 'RETROOS/RETROOS.INI')
        auth_home = Path(os.environ.get('CODEX_HOME', Path.home() / '.codex')) if args.request else work / 'no-auth'
        setup(c_root, binary, auth_home)
        with (c_root / 'RETROOS/RETROOS.INI').open('a') as ini:
            ini.write('\n[linux.environment]\nMixed_case=from-linux-settings\n')
        if args.request:
            command = ['codex', 'exec', '--ephemeral', '--ignore-user-config',
                       '--skip-git-repo-check', '--sandbox', 'read-only', '--color', 'never',
                       '-C', '/home/retroos/work',
                       'Reply with exactly: Hello from Codex on RetroOS. '
                       'Do not use any tools or read any files.']
        else:
            command = ['codex', '--version']
        (c_root / 'input.txt').write_text('')
        (c_root / 'run.sh').write_text(
            'set -eu\n'
            'test "$HOME" = /home/retroos\n'
            'test "$TMPDIR" = /home/retroos/TEMP\n'
            'test "$SHELL" = /bin/sh\n'
            'test "$TERM" = linux\n'
            'test "$Mixed_case" = from-linux-settings\n'
            'test -z "${BLASTER+x}"\n'
            'test "$(command -v codex)" = /home/retroos/bin/codex\n'
            'exec ' + shlex.join(command) +
            ' < /home/retroos/input.txt > /home/retroos/out.txt 2> /home/retroos/err.txt\n')
        profile = work / 'profile.json'
        profile.write_text(json.dumps({'root': '/', 'c_root': str(c_root)}))
        env = os.environ.copy()
        env.pop('RETROOS_DATA_IMAGE', None)
        env['RETROOS_QEMU_LIVE_PROFILE'] = str(profile)
        artifacts = ROOT / 'build/ci'
        artifacts.mkdir(parents=True, exist_ok=True)
        mode = ('request' if args.request else 'version') + ('-direct' if args.direct else '')
        log_path = artifacts / f'codex-{mode}.log'
        with log_path.open('w') as log:
            process = subprocess.Popen(
                [str(ROOT / 'run.sh'), 'qemu', '--kvm', '--headless', '--sound', 'none',
                 '--cmd', ('/bin/sh' if args.direct else '/home/retroos/RETROOS/SHELL.ELF') + ' /home/retroos/run.sh', '--', '-m', '2048'],
                cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                process.wait(timeout=180)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=15)
                raise RuntimeError(f'Codex {mode} timed out; see {log_path}') from None
        output = (c_root / 'out.txt').read_text() if (c_root / 'out.txt').exists() else ''
        error = (c_root / 'err.txt').read_text() if (c_root / 'err.txt').exists() else ''
        (artifacts / f'codex-{mode}-stdout.txt').write_text(output)
        (artifacts / f'codex-{mode}-stderr.txt').write_text(error)
        log = log_path.read_text(errors='replace')
        assert process.returncode == 0 and '[mem] exit tid=1 code=0' in log, (
            f'Codex {mode} failed; see {log_path} and its stderr artifact')
        if args.request:
            assert output.strip() == 'Hello from Codex on RetroOS.', output
        else:
            assert output.startswith('codex-cli '), output
        print(f'PASS: native Codex {mode} inside RetroOS: {output.strip()}')


if __name__ == '__main__':
    main()
