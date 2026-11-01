#!/usr/bin/env python3
"""Check Win16 DOS/Windows file interop, command tails and full MMIO buffers."""
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
    with tempfile.TemporaryDirectory(prefix='retroos-wine-dos-') as directory:
        root = Path(directory)
        install(root)
        for program, tail in [('dos_files', ''), ('dos_files', ' probe'), ('mmio_buffer', '')]:
            shutil.copyfile(ROOT / f'bazel-bin/test/windows/win16/{program}.exe', root / 'TEST.EXE')
            result = subprocess.run(['python3', str(ROOT / 'test/disk_fixture.py'), '--root', directory, '--',
                str(ROOT / 'bazel-bin/kernel' / host), '--c-root', '/', '--cmd', '/TEST.EXE' + tail],
                cwd=ROOT, capture_output=True, text=True, timeout=30)
            log = result.stdout + result.stderr
            if result.returncode or f'WIN16 {program.upper()} PASS' not in log or any(s in log for s in ('PANIC', 'WIN16 DOS_FILES FAIL', 'WIN16 MMIO_BUFFER FAIL', 'unhandled event', '[win16] unhandled')):
                raise SystemExit(log)
    print(f'PASS: shared DOS handles, empty/nonempty Win16 command tails and 64 KiB MMIO buffers ({engine})')


if __name__ == '__main__':
    main()
