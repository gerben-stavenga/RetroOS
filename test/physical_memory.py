#!/usr/bin/env python3
"""Prove native high-RAM allocation and release across paging/client modes."""
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    subprocess.run(list(map(str, args)), cwd=ROOT, check=True, stdout=subprocess.DEVNULL)


def session(work, disk, name, cpu, machine, accel):
    log = work / (name + '.log')
    process = subprocess.Popen([
        'qemu-system-x86_64', '-accel', accel, '-cpu', cpu, '-machine', machine,
        '-m', '512', '-display', 'none', '-serial', 'none', '-no-reboot',
        '-drive', f'file={ROOT / "bazel-bin/boot_disk.bin"},format=raw,snapshot=on',
        '-drive', f'file={disk},format=raw,snapshot=on',
        '-debugcon', f'file:{log}'],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            text = log.read_text(errors='replace') if log.exists() else ''
            assert not any(x in text for x in ('PHYSICAL-MEMORY-FAIL', 'PANIC', 'SEGV', '[mem] exit tid=1 code=1')), text
            if '[mem] exit tid=1 code=0 ' in text:
                break
            assert process.poll() is None, (text, process.stderr.read().decode())
            time.sleep(.1)
        else:
            raise AssertionError('memory probe timed out: ' + text)
        text = log.read_text(errors='replace')
        assert not any(x in text for x in ('PANIC', 'SEGV')), text
        print('PASS:', name, '300 MiB touched, verified, and released twice', flush=True)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)


def main():
    run('bazelisk', 'build', '//:boot_disk')
    work = Path(tempfile.mkdtemp(prefix='retroos-physical-memory-'))
    print('Artifacts:', work, flush=True)
    run('nasm', '-f', 'elf32', ROOT / 'test/physical_memory_probe.asm', '-o', work / 'probe.o')
    run('ld', '-m', 'elf_i386', '-o', work / 'MEMORY.ELF', work / 'probe.o')
    disk = work / 'data.img'
    with disk.open('wb') as out:
        out.truncate(32 * 1024 * 1024)
    run('mkfs.fat', '-F', '16', disk)
    run('mmd', '-i', disk, '::CONFIG')
    (work / 'CONFIG.SYS').write_text('TEST=MEMORY.ELF\n')
    run('mcopy', '-i', disk, work / 'CONFIG.SYS', '::CONFIG/CONFIG.SYS')
    run('mcopy', '-i', disk, work / 'MEMORY.ELF', '::MEMORY.ELF')
    session(work, disk, 'legacy-32', 'pentium', 'pc', 'tcg')
    session(work, disk, 'pae-high-ram', 'max', 'pc,max-ram-below-4g=128M', 'tcg')
    run('nasm', '-DCLIENT64', '-f', 'elf64', ROOT / 'test/physical_memory_probe.asm', '-o', work / 'probe64.o')
    run('ld', '-m', 'elf_x86_64', '-o', work / 'MEMORY64.ELF', work / 'probe64.o')
    run('mcopy', '-o', '-i', disk, work / 'MEMORY64.ELF', '::MEMORY.ELF')
    session(work, disk, 'client64-high-ram', 'max', 'pc,max-ram-below-4g=128M', 'tcg')


if __name__ == '__main__':
    main()
