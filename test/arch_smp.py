#!/usr/bin/env python3
"""Boot the arch SMP example on four CPUs (add --kvm for hardware execution)."""
import argparse
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kvm', action='store_true')
    options = parser.parse_args()
    subprocess.run(['bazelisk', 'build', '//arch-metal:smp_example'], cwd=ROOT, check=True)
    cases = [('legacy', 'tcg', 'pentium3,-pae', ''), ('pae', 'tcg', 'max', ''), ('timeout', 'tcg', 'max', 'missing')]
    if options.kvm:
        cases = [('xapic', 'kvm', 'host', ''), ('x2apic', 'kvm', 'host', 'x2apic'), ('timeout', 'kvm', 'host', 'missing')]
    for name, accel, cpu, command in cases:
        result = subprocess.run([
            'qemu-system-x86_64', '-accel', accel, '-cpu', cpu, '-smp', '4',
            '-m', '64', '-kernel', str(ROOT / 'bazel-bin/arch-metal/smp_example'),
            '-append', command, '-display', 'none', '-serial', 'none',
            '-monitor', 'none', '-no-reboot', '-debugcon', 'stdio',
            '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
        ], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        output = result.stdout.decode(errors='replace')
        if command == 'missing':
            assert result.returncode == 1 and 'SMP TIMEOUT PASS' in output, output
            print('PASS:', name, 'missing CPU times out before kernel init')
            continue
        assert result.returncode == 1 and 'SMP PASS:' in output, output
        assert 'SMP DMA allocated after AP resources' in output, output
        assert output.count('SMP AP initialized') == 3, output
        if command:
            assert 'SMP x2APIC sender' in output, output
        print('PASS:', name, 'four cores, common Rust entry, private stacks/TLS/GDT/page roots')


if __name__ == '__main__':
    main()
