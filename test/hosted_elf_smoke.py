#!/usr/bin/env python3
"""Run fixed ELF probes on the declared hosted backend."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    target = 'retroos-host-kvm' if os.environ.get('ENGINE') == 'kvm' else 'retroos-host'
    with tempfile.TemporaryDirectory(prefix='retroos-elf-') as directory:
        root = Path(directory)
        for name in ('hello', 'outlive_composite'):
            shutil.copyfile(ROOT / f'bazel-bin/tests/hosted_{name}.elf', root / (name + '.elf'))
            result = subprocess.run([
                'python3', str(ROOT / 'test/disk_fixture.py'), '--root', str(root), '--',
                str(ROOT / 'bazel-bin/kernel' / target), '--cmd', '/' + name + '.elf',
            ], capture_output=True, text=True, timeout=30)
            output = result.stdout + result.stderr
            assert result.returncode == 0, output
            assert 'Hello from an interpreted 32-bit Linux ELF!' in output, output
            assert 'panicked' not in output, output
            print('PASS:', target, name)


if __name__ == '__main__':
    main()
