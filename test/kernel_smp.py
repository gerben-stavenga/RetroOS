#!/usr/bin/env python3
"""Real-kernel CPU discovery/startup, followed by a guest TLS/IRQ workload."""
import argparse
from pathlib import Path
import tempfile
from arch_tls import ROOT, run, session


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kvm', action='store_true')
    options = parser.parse_args()
    run('bazelisk', 'build', '//:boot_disk')
    work = Path(tempfile.mkdtemp(prefix='retroos-kernel-smp-'))
    print('Artifacts:', work, flush=True)
    disk = work / 'data.img'
    with disk.open('wb') as out:
        out.truncate(32 * 1024 * 1024)
    run('mkfs.fat', '-F', '16', disk)
    run('mmd', '-i', disk, '::RETROOS')
    (work / 'RETROOS.INI').write_text('[environment]\nTEST=TLS.ELF\n')
    run('mcopy', '-i', disk, work / 'RETROOS.INI', '::RETROOS/RETROOS.INI')
    run('nasm', '-f', 'elf32', ROOT / 'test/arch_tls_probe.asm', '-o', work / 'probe.o')
    run('ld', '-m', 'elf_i386', '-o', work / 'TLS.ELF', work / 'probe.o')
    run('mcopy', '-i', disk, work / 'TLS.ELF', '::TLS.ELF')
    accel, cpu = ('kvm', 'host') if options.kvm else ('tcg', 'max')
    cases = [
        ('single', ('-smp', '1'), 1),
        ('four', ('-smp', '4'), 4),
        ('capacity', ('-smp', '8'), 7),
        ('sparse', ('-smp', '4,sockets=2,cores=3,threads=1,maxcpus=6'), 4),
        ('no-acpi', ('-smp', '4', '-no-acpi'), 1),
    ]
    for name, extra, expected in cases:
        session(work, disk, name, cpu, accel, extra, expected)
    if not options.kvm:
        session(work, disk, 'legacy', 'pentium3,-pae', 'tcg', ('-smp', '4'), 4)


if __name__ == '__main__':
    main()
