#!/usr/bin/env python3
"""Real-kernel CPU discovery/startup, followed by a guest TLS/IRQ workload."""
import argparse
from pathlib import Path
import re
import tempfile
from arch_tls import ROOT, run, session


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kvm', action='store_true')
    options = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix='retroos-kernel-smp-'))
    print('Artifacts:', work, flush=True)
    disk = work / 'data.img'
    with disk.open('wb') as out:
        out.truncate(32 * 1024 * 1024)
    run('mkfs.fat', '-F', '16', disk)
    run('mmd', '-i', disk, '::RETROOS')
    (work / 'RETROOS.INI').write_text('[environment]\nTEST=TLS.ELF\n[sound]\nsb_audio=native\n')
    run('mcopy', '-i', disk, work / 'RETROOS.INI', '::RETROOS/RETROOS.INI')
    run('nasm', '-f', 'elf32', ROOT / 'test/arch_tls_probe.asm', '-o', work / 'probe.o')
    run('ld', '-m', 'elf_i386', '-o', work / 'TLS.ELF', work / 'probe.o')
    run('mcopy', '-i', disk, work / 'TLS.ELF', '::TLS.ELF')
    accel, cpu = ('kvm', 'host') if options.kvm else ('tcg', 'max')
    cases = [
        ('single', ('-smp', '1'), 1),
        ('dual-sb', ('-smp', '2', '-audiodev', 'none,id=sb',
                     '-device', 'sb16,audiodev=sb,irq=5,dma=1,dma16=5'), 2),
        ('four', ('-smp', '4'), 4),
        ('capacity', ('-smp', '8'), 8),
        ('sixteen', ('-smp', '16'), 16),
        ('sparse', ('-smp', '4,sockets=2,cores=3,threads=1,maxcpus=6'), 4),
        ('no-acpi', ('-smp', '4', '-no-acpi'), 1),
    ]
    for name, extra, expected in cases:
        session(work, disk, name, cpu, accel, extra, expected)
        if name == 'dual-sb':
            text = (work / f'{name}.log').read_text(errors='replace')
            assert 'Audio: NativeSb (SB_AUDIO=native)' in text, text
            dma = re.search(r'Audio: ISA DMA pages DMA1=(0x[0-9a-f]+) HDMA=(0x[0-9a-f]+)', text)
            assert dma and all(int(page, 16) for page in dma.groups()), text
    if not options.kvm:
        session(work, disk, 'legacy', 'pentium3,-pae', 'tcg', ('-smp', '4'), 4)
        # No LAPIC or TSC: one-shot PIC/PIT alarms must preserve the wrapping
        # PIT2 clock and preempt the same guest workload.
        session(work, disk, 'pic', '486', 'tcg', (), 1)


if __name__ == '__main__':
    main()
