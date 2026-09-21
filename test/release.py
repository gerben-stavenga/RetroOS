#!/usr/bin/env python3
"""Validate public release contents and boot the extracted, compiler-free launcher."""
import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = Path(os.environ.get('RETROOS_RELEASE_DIR', ROOT / 'bazel-bin'))


def main():
    for line in (OUTPUT / 'SHA256SUMS').read_text().splitlines():
        expected, name = line.split()
        assert hashlib.file_digest((OUTPUT / name).open('rb'), 'sha256').hexdigest() == expected, name
    with tempfile.TemporaryDirectory(prefix='retroos-release-test-') as temp:
        work = Path(temp)
        vm, machine = work / 'vm', work / 'machine'
        for name, dest in [('vm', vm), ('machine', machine)]:
            with tarfile.open(OUTPUT / f'retroos-{name}.tar.gz') as archive:
                archive.extractall(dest, filter='data')
        assert os.access(vm / 'run.sh', os.X_OK)
        assert (vm / 'data.img').stat().st_mode & 0o200
        with (vm / 'data.img').open('rb') as disk:
            offset = struct.unpack_from('<I', disk.read(512), 454)[0] * 512
        volume = f'{vm}/data.img@@{offset}'
        listing = subprocess.check_output(['mdir', '-i', volume, '::/'])
        for forbidden in (b'BUILD~1', b'DOS32A', b'BORLANDC'):
            assert forbidden not in listing, forbidden
        with tarfile.open(machine / 'machine_boot.tar') as archive:
            names = {member.name.removeprefix('./') for member in archive.getmembers()}
            assert {'kernel.elf', 'RETROOS/COMMAND.COM', 'RETROOS/KERNEL.SYM', 'RETROOS/DN/DN.COM'} <= names
            assert 'RETROOS/DN/DN.HIS' not in names and 'RETROOS/DN/DN.FLG' not in names
        # Exercise the shipped installer/defaults without assuming CI's host
        # root is ext4 or writing to its /boot and /home directories.
        sys.path.insert(0, str(machine / 'tools'))
        spec = importlib.util.spec_from_file_location('release_install', machine / 'tools/machine_install.py')
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        home = work / 'croot'
        home.mkdir()
        installer.migrate(home)
        assert b'COMSPEC=C:\\RETROOS\\COMMAND.COM' in (home / 'CONFIG.SYS').read_bytes()
        assert (home / 'CONFIG/DN/DN.MNU').is_file()
        installer.validate = lambda *_: '00000000-0000-0000-0000-000000000001'
        installer.prepare(home, Path('/boot/retroos'), machine / 'machine_boot.tar')
        # No Bazel invocation: this launcher must consume only the release.
        for firmware, controller in [(fw, hd) for fw in ('bios', 'uefi') for hd in ('ata', 'ahci', 'nvme')]:
            log = work / f'vm-{firmware}-{controller}.log'
            with log.open('w') as output:
                proc = subprocess.Popen([str(vm / 'run.sh'), '--headless', '--sound', 'none',
                                         '--firmware', firmware, '--hd', controller,
                                         '--cmd', 'TESTS/HELLO.COM'], cwd=vm,
                                        stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 45
                    while time.monotonic() < deadline and proc.poll() is None:
                        if 'All commands done' in log.read_text(errors='replace'):
                            break
                        time.sleep(.1)
                finally:
                    if proc.poll() is None:
                        proc.terminate()
                    proc.wait(timeout=10)
            text = log.read_text(errors='replace')
            assert 'Hello from HELLO.COM!' in text and 'All commands done' in text, text
            expected = 'vga_passthrough=true firmware=NativeBios' if firmware == 'bios' else 'vga_passthrough=false firmware=Substitute'
            assert expected in text, text
            device = {'ata': 'ata1', 'ahci': 'ahci0p0', 'nvme': 'nvme0n1'}[controller]
            assert f'Storage: {device} ' in text, text
            print(f'PASS: packaged launcher {firmware}/{controller}')
            assert 'FATAL' not in text and 'panicked' not in text, text
    print('PASS: release checksums, public data, matched runtime, packaged installer, and prebuilt QEMU launcher')


if __name__ == '__main__':
    main()
