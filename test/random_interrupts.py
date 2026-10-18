#!/usr/bin/env python3
"""Input interrupt entropy without RDRAND: 486/PIT and UEFI/TSC or HPET.

Injected input tests the plumbing and credit policy, not entropy quality.
"""
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parents[1]
SEEDED = 'random: seeded from interrupt timing'


def run(*args):
    subprocess.run(list(map(str, args)), cwd=ROOT, check=True,
                   stdout=subprocess.DEVNULL)


def session(work, uefi=False):
    work.mkdir()
    data = work / 'data.img'
    with data.open('wb') as stream:
        stream.truncate(32 * 1024 * 1024)
    run('mkfs.fat', '-F', '16', data)
    # Exercise both Linux ABIs: unseeded NONBLOCK, a blocking request, then
    # successful reads once input timing seeds the shared generator.
    bits = '64' if uefi else '32'
    run('gcc', '-m' + bits, '-nostdlib', '-static', '-no-pie', '-fno-pic',
        '-fno-stack-protector', '-fno-builtin', '-O2', '-e', '_start',
        *([] if uefi else ['-march=i486']),
        ROOT / 'test/linux_getrandom_probe.c', '-o', work / 'RND.ELF')
    run('mcopy', '-i', data, work / 'RND.ELF', '::RND.ELF')
    boot = prepare_boot(work, data, '[environment]\nTEST=RND.ELF\n')
    log, monitor = work / 'klog', work / 'monitor'
    args = ['qemu-system-x86_64', '-cpu', 'max,-rdrand' if uefi else '486,-tsc',
            '-m', '256', '-display', 'none', '-serial', 'none', '-no-reboot',
            '-debugcon', f'file:{log}', '-nic', 'none',
            '-drive', f'file={boot},format=raw,snapshot=on',
            '-drive', f'file={data},format=raw,snapshot=on',
            '-monitor', f'unix:{monitor},server=on,wait=off']
    if uefi:
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', work / 'vars.fd')
        args += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                 '-drive', f'if=pflash,format=raw,file={work / "vars.fd"}']
    else:
        args += ['-machine', 'pc,hpet=off']
    with (work / 'stderr').open('w') as errors:
        process = subprocess.Popen(args, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=errors)
        try:
            deadline = time.monotonic() + 30
            while True:
                text = log.read_text(errors='replace') if log.exists() else ''
                assert process.poll() is None, text[-5000:]
                assert 'PANIC' not in text and 'FATAL' not in text, text[-5000:]
                if 'GETRANDOM WAITING' in text:
                    break
                assert time.monotonic() < deadline, text[-5000:]
                time.sleep(.1)
            if not uefi:
                assert 'Clock: PIT channel 2' in text, text[-5000:]
                assert 'IRQ: PIT' in text, text[-5000:]
            else:
                assert 'IRQ: LAPIC timer tick' in text, text[-5000:]
            # Timer traffic by itself must never seed the generator.
            time.sleep(.5)
            assert SEEDED not in log.read_text(errors='replace')
            assert 'GETRANDOM PASS' not in log.read_text(errors='replace')
            with socket.socket(socket.AF_UNIX) as control:
                control.connect(str(monitor))
                control.settimeout(.001)
                for i in range(900):
                    control.sendall(b'sendkey a 1\n')
                    time.sleep(.01 + (i % 7) * .001)
                    try:
                        control.recv(65536)
                    except TimeoutError:
                        pass
                    if i % 20 == 0 and SEEDED in log.read_text(errors='replace'):
                        break
                else:
                    raise AssertionError(log.read_text(errors='replace')[-5000:])
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                text = log.read_text(errors='replace')
                if 'GETRANDOM PASS' in text and '[mem] exit tid=1 code=0' in text:
                    break
                assert process.poll() is None, text[-5000:]
                time.sleep(.1)
            else:
                raise AssertionError(text[-5000:])
            assert 'PANIC' not in text and 'FATAL' not in text, text[-5000:]
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
    print(f'PASS: {work.name}: Linux getrandom blocks until input timing seeds, then succeeds without RDRAND', flush=True)


def main():
    run('bazelisk', 'build', '//:boot_disk')
    work = Path(tempfile.mkdtemp(prefix='retroos-random-irqs-'))
    print('Artifacts:', work, flush=True)
    session(work / '486-pit')
    session(work / 'uefi', uefi=True)


if __name__ == '__main__':
    main()
