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
import zipfile

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = Path(os.environ.get('RETROOS_RELEASE_DIR', ROOT / 'bazel-bin'))


def check_usb(work):
    iso = OUTPUT / 'retroos_grub_module.iso'
    assert iso.is_file()
    for firmware in ('bios', 'uefi'):
        log = work / f'usb-{firmware}.log'
        args = ['qemu-system-x86_64', '-m', '512', '-cdrom', str(iso),
                '-boot', 'order=d', '-display', 'none', '-no-reboot',
                '-debugcon', 'file:' + str(log),
                '-fw_cfg', 'name=opt/cmdline,string=TESTS/HELLO.COM']
        if firmware == 'bios':
            args += ['-cpu', 'pentium3']
        else:
            import shutil
            variables = work / 'usb-vars.fd'
            shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
            args += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                     '-drive', f'if=pflash,format=raw,file={variables}']
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline and proc.poll() is None:
                text = log.read_text(errors='replace') if log.exists() else ''
                if any(marker in text for marker in ('Hello from HELLO.COM!', 'PANIC')):
                    break
                time.sleep(.1)
        finally:
            if proc.poll() is None:
                proc.terminate()
            proc.wait(timeout=10)
        text = log.read_text(errors='replace')
        assert 'Hello from HELLO.COM!' in text and 'PANIC' not in text, text
        assert 'Disk writes: volatile RAM overlay' in text, text
        expected = 'vga_passthrough=true firmware=NativeBios' if firmware == 'bios' else 'vga_passthrough=false firmware=Substitute'
        assert expected in text, text
        print(f'PASS: published USB/CD ISO {firmware}, protected default, RAM C:')


def main():
    for line in (OUTPUT / 'SHA256SUMS').read_text().splitlines():
        expected, name = line.split()
        assert hashlib.file_digest((OUTPUT / name).open('rb'), 'sha256').hexdigest() == expected, name
    with tempfile.TemporaryDirectory(prefix='retroos-release-test-') as temp:
        work = Path(temp)
        with zipfile.ZipFile(OUTPUT / 'retroos-usb-diagnostic.zip') as archive:
            assert archive.testzip() is None
            archive.extract('retroos-usb-diagnostic.iso', work)
        assert (OUTPUT / 'retroos-usb-diagnostic.zip').stat().st_size < 5_000_000
        subprocess.run(['xorriso', '-osirrox', 'on', '-indev',
                        str(work / 'retroos-usb-diagnostic.iso'), '-extract',
                        '/boot/grub/grub.cfg', str(work / 'lightweight-grub.cfg')],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        menu = (work / 'lightweight-grub.cfg').read_text()
        assert 'boot_choices base' in menu and 'isa-lpc=disappointment' in menu
        assert 'boot-log-only isa-lpc=disappointment' in menu
        subprocess.run(['grub-script-check', str(work / 'lightweight-grub.cfg')], check=True)
        print('PASS: lightweight USB ZIP below 5 MB, dISAppointment and photo entries')
        check_usb(work)
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
            assert {'kernel.elf', 'RETROOS/COMMAND.COM', 'RETROOS/KERNEL.SYM', 'RETROOS/DN/DN.COM', 'CONFIG/CONFIG.SYS'} <= names
            assert 'RETROOS/DN/DN.HIS' not in names and 'RETROOS/DN/DN.FLG' not in names
            kernel = next(member for member in archive.getmembers()
                          if member.name.removeprefix('./') == 'kernel.elf')
            # immediate-abort removes the Rust panic handler from the linked
            # kernel. Check the shipped binary retains its diagnostic path.
            assert b'!!! KERNEL PANIC !!!' in archive.extractfile(kernel).read()
        # Exercise the shipped installer/defaults without assuming CI's host
        # root is ext4 or writing to its /boot and /home directories.
        sys.path.insert(0, str(machine / 'tools'))
        spec = importlib.util.spec_from_file_location('release_install', machine / 'tools/machine_install.py')
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        home = work / 'croot'
        home.mkdir()
        installer.migrate(home)
        assert b'COMSPEC=C:\\RETROOS\\COMMAND.COM' in (home / 'CONFIG/CONFIG.SYS').read_bytes()
        assert (home / 'CONFIG/DN/DN.MNU').is_file()
        installer.validate = lambda *_: '00000000-0000-0000-0000-000000000001'
        installer.prepare(home, Path('/boot/retroos'), machine / 'machine_boot.tar')
        # No Bazel invocation: this launcher must consume only the release.
        cases = [('bios', cpu, hd) for cpu in ('386', '686') for hd in ('ata', 'ahci', 'nvme')]
        cases += [('uefi', 'x64', hd) for hd in ('ata', 'ahci', 'nvme')]
        for firmware, cpu, controller in cases:
            log = work / f'vm-{firmware}-{cpu}-{controller}.log'
            with log.open('w') as output:
                proc = subprocess.Popen([str(vm / 'run.sh'), '--headless', '--sound', 'none',
                                         '--firmware', firmware, '--arch', cpu, '--hd', controller,
                                         '--cmd', 'TESTS/WR.COM'], cwd=vm,
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
            assert 'WR: ok' in text and 'All commands done' in text, text
            # Read after QEMU exits: success must reach the backing disk, not
            # merely the guest cache. Remove it so every case creates anew.
            contents = subprocess.check_output(['mtype', '-i', volume, '::/WRTEST.TXT'])
            assert contents == b'RetroOS ext4 write test\r\n', contents
            subprocess.run(['mdel', '-i', volume, '::/WRTEST.TXT'], check=True)
            expected = 'vga_passthrough=true firmware=NativeBios' if firmware == 'bios' else 'vga_passthrough=false firmware=Substitute'
            assert expected in text, text
            if cpu == '386':
                assert 'VME not supported, using software VM86 monitor' in text, text
            device = {'ata': 'ata1', 'ahci': 'ahci0p0', 'nvme': 'nvme0n1'}[controller]
            assert f'Storage: {device} ' in text, text
            print(f'PASS: packaged launcher + persistent write {firmware}/{cpu}/{controller}')
            assert not any(marker in text for marker in ('FATAL', 'PANIC', 'panicked')), text
    print('PASS: release checksums, public data, matched runtime, packaged installer, and prebuilt QEMU launcher')


if __name__ == '__main__':
    main()
