#!/usr/bin/env python3
"""Exercise Wine wave output through RetroOS PCM, including buffer completion."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from wine_runtime import ROOT, install


def main():
    engine = os.environ.get('ENGINE', 'kvm')
    if engine not in ('kvm', 'tcg'):
        raise SystemExit('ENGINE must be kvm or tcg')
    host = 'retroos-host-kvm' if engine == 'kvm' else 'retroos-host'
    with tempfile.TemporaryDirectory(prefix='retroos-wave-') as directory:
        root = Path(directory)
        install(root)
        shutil.copyfile(ROOT / 'bazel-bin/test/windows/callbacks/wine_wave.exe', root / 'TEST.EXE')
        result = subprocess.run(['python3', str(ROOT / 'test/disk_fixture.py'), '--root', directory, '--',
            str(ROOT / 'bazel-bin/kernel' / host), '--c-root', '/', '--cmd', '/TEST.EXE'],
            cwd=ROOT, capture_output=True, text=True, timeout=30)
        log = result.stdout + result.stderr
        if result.returncode or 'WAVE PASS' not in log or any(s in log for s in ('WAVE FAIL', 'PANIC', 'not implemented', 'SEGV')):
            raise SystemExit(log)
    print(f'PASS: Wine PCM output, pause/restart, playback position and buffer callbacks ({engine})')


if __name__ == '__main__':
    main()
