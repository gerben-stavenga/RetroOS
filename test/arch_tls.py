#!/usr/bin/env python3
"""Prove guest FS/GS restoration with kernel TLS on legacy, PAE and long mode.

python3 test/arch_tls.py [--kvm]
"""
import argparse
from pathlib import Path
import subprocess
import tempfile
import time

from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    subprocess.run(list(map(str, args)), cwd=ROOT, check=True,
                   stdout=subprocess.DEVNULL)


def session(work, disk, name, cpu, accel, extra=(), initialized=None):
    boot = prepare_boot(work, disk)
    log = work / (name + '.log')
    serial = work / (name + '.serial.log')
    logging = (['-serial', f'file:{serial}', '-fw_cfg',
                'name=opt/cmdline,string=serial=com1;TLS.ELF']
               if initialized is not None else ['-serial', 'none'])
    with (work / (name + '.stderr')).open('w') as errors:
        process = subprocess.Popen([
            'qemu-system-x86_64', '-accel', accel, '-cpu', cpu, '-m', '128',
            '-display', 'none', *logging, '-no-reboot', *extra,
            '-drive', f'file={boot},format=raw,snapshot=on',
            '-drive', f'file={disk},format=raw,snapshot=on',
            '-debugcon', f'file:{log}',
        ], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=errors)
        try:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                text = log.read_text(errors='replace') if log.exists() else ''
                assert not any(marker in text for marker in
                               ('PANIC', 'SEGV', 'fatal Exception',
                                '[mem] exit tid=1 code=1 ')), text
                if '[mem] exit tid=1 code=0 ' in text:
                    if initialized is not None:
                        assert f'SMP: {initialized} CPUs initialized,' in text, text
                        assert text.count('initialized, parking') == initialized - 1, text
                        assert 'startup failed' not in text, text
                        if initialized > 1:
                            assert 'core 1: Media worker: audio and graphics ready' in text, text
                        serial_text = serial.read_text(errors='replace')
                        summary = f'core 0: SMP: {initialized} CPUs initialized,'
                        assert summary in text, text
                        assert summary in serial_text, serial_text
                        assert serial_text.count('initialized, parking') == initialized - 1, serial_text
                    print('PASS:', name, 'guest FS/GS across syscalls and timer IRQs', flush=True)
                    return
                assert process.poll() is None, text + (work / (name + '.stderr')).read_text()
                time.sleep(.05)
            raise AssertionError(name + ' timed out: ' + text)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kvm', action='store_true')
    options = parser.parse_args()
    run('bazelisk', 'build', '//:boot_disk')
    work = Path(tempfile.mkdtemp(prefix='retroos-arch-tls-'))
    print('Artifacts:', work, flush=True)
    disk = work / 'data.img'
    with disk.open('wb') as out:
        out.truncate(32 * 1024 * 1024)
    run('mkfs.fat', '-F', '16', disk)
    run('mmd', '-i', disk, '::RETROOS')
    (work / 'RETROOS.INI').write_text('[environment]\nTEST=TLS.ELF\n')
    run('mcopy', '-i', disk, work / 'RETROOS.INI', '::RETROOS/RETROOS.INI')
    for bits in (32, 64):
        flags = ['-DCLIENT64'] if bits == 64 else []
        run('nasm', *flags, '-f', f'elf{bits}', ROOT / 'test/arch_tls_probe.asm',
            '-o', work / 'probe.o')
        run('ld', '-m', 'elf_x86_64' if bits == 64 else 'elf_i386',
            '-o', work / 'TLS.ELF', work / 'probe.o')
        run('mcopy', '-o', '-i', disk, work / 'TLS.ELF', '::TLS.ELF')
        if bits == 32 and not options.kvm:
            session(work, disk, 'legacy', 'pentium', 'tcg')
        session(work, disk, f'guest{bits}', 'host' if options.kvm else 'max',
                'kvm' if options.kvm else 'tcg')


if __name__ == '__main__':
    main()
