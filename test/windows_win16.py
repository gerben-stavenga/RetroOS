#!/usr/bin/env python3
"""Exercise real NE -> guest Rust -> nested NE callbacks on both CPU backends."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent

def main():
    engine = os.environ.get('ENGINE', 'kvm')
    if engine not in ('kvm', 'tcg'):
        raise SystemExit('ENGINE must be kvm or tcg')
    host = 'retroos-host-kvm' if engine == 'kvm' else 'retroos-host'
    targets = [f'//kernel:{host}', '//test/windows/win16:bridge', '//test/windows/win16:window',
               '//lib/windows/user32:user32_dll', '//lib/windows/kernel32:kernel32_dll',
               '//lib/windows/compat:gdi32_dll']
    targets += [f'//lib/windows/win16:{name}_dll' for name in ('user','kernel','gdi','sound','shell','keyboard')]
    subprocess.run(['bazelisk', 'build', *targets, '--platforms=@platforms//host'], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix='retroos-win16-') as directory:
        root = Path(directory)
        system = root / 'RETROOS/WINDOWS/SYSTEM'
        system.mkdir(parents=True)
        system32 = root / 'RETROOS/WINDOWS/SYSTEM32'
        system32.mkdir()
        for name in ('USER','KERNEL','GDI','SOUND','SHELL','KEYBOARD'):
            shutil.copyfile(ROOT / f'bazel-bin/lib/windows/win16/{name}.DLL', system / f'{name}.DLL')
        for name, folder in [('USER32','user32'), ('KERNEL32','kernel32'), ('GDI32','compat')]:
            shutil.copyfile(ROOT / f'bazel-bin/lib/windows/{folder}/{name}.DLL', system32 / f'{name}.DLL')
        for program in ('bridge', 'window'):
            shutil.copyfile(ROOT / f'bazel-bin/test/windows/win16/{program}.exe', root / 'BRIDGE.EXE')
            result = subprocess.run(['python3', str(ROOT/'test/disk_fixture.py'), '--root', directory, '--',
                str(ROOT/f'bazel-bin/kernel/{host}'), '--c-root', '/', '--cmd', '/BRIDGE.EXE'],
                cwd=ROOT, capture_output=True, text=True, timeout=40)
            log = result.stdout + result.stderr
            if result.returncode or f'WIN16 {program.upper()} PASS' not in log or any(x in log for x in ('PANIC', 'SEGV', ' FAIL')):
                raise SystemExit(log)
        print(f'PASS: Win16 recursive callbacks, shared windows/GDI, messages, dialogs and exit ({engine})')

if __name__ == '__main__':
    main()
