#!/usr/bin/env python3
"""Expose the installed native Codex executables in RetroOS's Linux home."""
import argparse
import os
from pathlib import Path
import shlex
import shutil
import tempfile

DEFAULT_BINARY = Path('/usr/local/lib/node_modules/@openai/codex/node_modules/'
                      '@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex')
LAUNCHER_HEADER = '#!/bin/sh\n# Managed by RetroOS tools/setup_codex.py.\n'


def setup(home, binary, auth_from):
    home = home.resolve(strict=True)
    binary = binary.resolve(strict=True)
    with binary.open('rb') as source:
        if source.read(4) != b'\x7fELF':
            raise ValueError('--binary must be the native ELF executable, not the Node launcher')
    destination = home / 'bin'
    destination.mkdir(exist_ok=True)
    for name in ('codex', 'codex-code-mode-host'):
        target = binary if name == 'codex' else binary.with_name(name)
        if not target.is_file():
            continue
        link = destination / name
        # Samba follows native host symlinks without exposing their target.
        # Exec the real path so /proc/self/exe identifies the installed package,
        # allowing Codex to locate its manifest and background-server resources.
        launcher = LAUNCHER_HEADER + 'exec ' + shlex.quote(str(target)) + ' "$@"\n'
        if not link.is_symlink() and link.exists():
            if not link.is_file():
                raise ValueError(f'Refusing to replace existing file: {link}')
            with link.open('rb') as existing:
                current = existing.read(len(launcher.encode()) + 1)
            if not current.startswith(LAUNCHER_HEADER.encode()):
                raise ValueError(f'Refusing to replace existing file: {link}')
            if current == launcher.encode():
                continue
        with tempfile.NamedTemporaryFile(mode='w', dir=destination,
                                         prefix='.' + name + '.', delete=False) as output:
            pending = Path(output.name)
            try:
                output.write(launcher)
                output.flush()
                pending.chmod(0o755)
                pending.replace(link)
            finally:
                pending.unlink(missing_ok=True)
    state = home / '.codex'
    if state.is_symlink():
        raise ValueError('RetroOS .codex must be a separate directory')
    state.mkdir(mode=0o700, exist_ok=True)
    state.chmod(0o700)
    target = state / 'auth.json'
    source = auth_from / 'auth.json'
    if target.is_symlink():
        raise ValueError('Refusing a shared authentication symlink')
    if target.exists():
        print('Preserved existing RetroOS Codex authentication.')
    elif source.is_file():
        # Keep credentials out of command arguments, logs and repository files.
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(fd, 'wb') as output, source.open('rb') as input_file:
                shutil.copyfileobj(input_file, output)
        except BaseException:
            target.unlink(missing_ok=True)
            raise
        print('Copied saved login into private RetroOS Codex state.')
    else:
        print('No saved login found; authentication will need to be configured.')
    print(f'Native launcher: {destination / "codex"}')
    print(f'Codex state: {state}')
    print('After installing the updated shell/kernel, start shell.elf and run codex --version.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path, default=Path('/home/retroos'))
    parser.add_argument('--binary', type=Path, default=DEFAULT_BINARY)
    parser.add_argument('--auth-from', type=Path,
                        default=Path(os.environ.get('CODEX_HOME', Path.home() / '.codex')))
    args = parser.parse_args()
    setup(args.home, args.binary, args.auth_from)


if __name__ == '__main__':
    main()
