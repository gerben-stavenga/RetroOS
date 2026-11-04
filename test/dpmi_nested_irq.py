#!/usr/bin/env python3
"""Verify active handler stacks survive nesting and raw switches stay separate."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    with tempfile.TemporaryDirectory(prefix='retroos-nested-irq-') as directory:
        for name, marker in [('NESTIRQ', 'NESTED-IRQ'), ('IRQREGS', 'IRQ-REGS')]:
            shutil.copyfile(ROOT / f'bazel-bin/test/dos/rmexception/{name}.COM',
                            Path(directory) / f'{name}.COM')
            result = subprocess.run([
                'python3', str(ROOT / 'test/disk_fixture.py'), '--root', directory, '--',
                str(ROOT / 'bazel-bin/kernel/retroos-host-kvm'),
                '--c-root', '/', '--cmd', f'/{name}.COM',
            ], cwd=ROOT, capture_output=True, text=True, timeout=30)
            log = result.stdout + result.stderr
            assert result.returncode == 0, log
            assert f'{marker} PASS' in log and '[mem] exit tid=1 code=0' in log, log
            assert not any(error in log for error in
                           (f'{marker} FAIL', 'FATAL', 'panicked at')), log
    print('PASS: DPMI IRQ stack selection and legacy ISR register preservation')


if __name__ == '__main__':
    main()
