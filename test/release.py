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
    image = OUTPUT / 'retroos_grub_module_usb.img'
    assert image.is_file()
    with image.open('rb') as disk:
        mbr = disk.read(512)
    assert mbr[510:512] == b'\x55\xaa'
    assert struct.unpack_from('<I', mbr, 0x1B8)[0] != 0
    assert mbr[450] == 0x0C
    assert mbr[462:510] == bytes(48)
    assert struct.unpack_from('<I', mbr, 454)[0] == 2048
    assert image.stat().st_size == (2048 + struct.unpack_from('<I', mbr, 458)[0]) * 512
    menu = subprocess.check_output(['mtype', '-i', f'{image}@@1048576',
                                    '::/boot/grub/grub.cfg']).decode()
    assert 'GOP 1024x768' in menu and 'GOP 800x600' in menu
    ini = subprocess.check_output(['mtype', '-i', f'{image}@@1048576', '::/boot/RETROOS.INI']).decode()
    assert 'source=bundle' in ini and 'start=C:\\DN\\DN.COM' in ini
    cfg = work / 'usb-grub.cfg'
    cfg.write_text(menu)
    subprocess.run(['grub-script-check', str(cfg)], check=True)
    for firmware in ('bios', 'uefi'):
        log = work / f'usb-{firmware}.log'
        args = ['qemu-system-x86_64', '-m', '512',
                '-device', 'qemu-xhci,id=usb',
                '-drive', f'if=none,id=usbdisk,file={image},format=raw,snapshot=on',
                '-device', 'usb-storage,bus=usb.0,drive=usbdisk,bootindex=1',
                '-boot', 'order=c', '-display', 'none', '-no-reboot',
                '-debugcon', 'file:' + str(log),
                '-fw_cfg', 'name=opt/cmdline,string=/bin/busybox true']
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
                if any(marker in text for marker in ('[mem] exit tid=1 code=0', 'PANIC')):
                    break
                time.sleep(.1)
        finally:
            if proc.poll() is None:
                proc.terminate()
            proc.wait(timeout=10)
        text = log.read_text(errors='replace')
        assert '[mem] exit tid=1 code=0' in text and 'PANIC' not in text, text
        assert 'Disk writes: volatile RAM overlay' in text, text
        expected = 'vga_passthrough=true firmware=NativeBios' if firmware == 'bios' else 'vga_passthrough=false firmware=Substitute'
        assert expected in text, text
        print(f'PASS: published USB image {firmware}, protected default, RAM C:')


def check_iso(work):
    image = OUTPUT / 'retroos_grub_module.iso'
    assert image.is_file()
    for firmware in ('bios', 'uefi'):
        log = work / f'iso-{firmware}.log'
        args = ['qemu-system-x86_64', '-m', '512', '-cdrom', str(image),
                '-boot', 'order=d', '-display', 'none', '-no-reboot',
                '-debugcon', 'file:' + str(log),
                '-fw_cfg', 'name=opt/cmdline,string=/bin/busybox true']
        if firmware == 'uefi':
            import shutil
            variables = work / 'iso-vars.fd'
            shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
            args += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                     '-drive', f'if=pflash,format=raw,file={variables}']
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline and proc.poll() is None:
                text = log.read_text(errors='replace') if log.exists() else ''
                if any(marker in text for marker in ('[mem] exit tid=1 code=0', 'PANIC')):
                    break
                time.sleep(.1)
        finally:
            if proc.poll() is None:
                proc.terminate()
            proc.wait(timeout=10)
        text = log.read_text(errors='replace')
        assert '[mem] exit tid=1 code=0' in text and 'PANIC' not in text, text
        assert 'Disk writes: volatile RAM overlay' in text, text
        print(f'PASS: published CD ISO {firmware}, protected default, RAM C:')


def main():
    for line in (OUTPUT / 'SHA256SUMS').read_text().splitlines():
        expected, name = line.split()
        assert hashlib.file_digest((OUTPUT / name).open('rb'), 'sha256').hexdigest() == expected, name
    with tempfile.TemporaryDirectory(prefix='retroos-release-test-') as temp:
        work = Path(temp)
        with zipfile.ZipFile(OUTPUT / 'retroos-usb-diagnostic.zip') as archive:
            assert archive.testzip() is None
            archive.extract('retroos-usb-diagnostic.img', work)
        assert (OUTPUT / 'retroos-usb-diagnostic.zip').stat().st_size < 5_000_000
        menu = subprocess.check_output(['mtype', '-i',
                                        f'{work / "retroos-usb-diagnostic.img"}@@1048576',
                                        '::/boot/grub/grub.cfg']).decode()
        assert 'boot_choices base' in menu and 'isa-lpc=disappointment' in menu
        assert 'boot-log-only isa-lpc=disappointment' in menu
        assert 'boot_modules games ' not in menu
        (work / 'lightweight-grub.cfg').write_text(menu)
        subprocess.run(['grub-script-check', str(work / 'lightweight-grub.cfg')], check=True)
        print('PASS: lightweight USB ZIP below 5 MB, dISAppointment and photo entries')
        check_usb(work)
        check_iso(work)
        vm, machine = work / 'vm', work / 'machine'
        for name, dest in [('vm', vm), ('machine', machine)]:
            with tarfile.open(OUTPUT / f'retroos-{name}.tar.gz') as archive:
                archive.extractall(dest, filter='data')
        module_installer = machine / 'tools/grub_module_install.py'
        assert module_installer.is_file(), 'machine bundle is missing the existing-GRUB module installer'
        spec = importlib.util.spec_from_file_location('module_install', module_installer)
        module_install = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module_install)
        usb_image = OUTPUT / 'retroos_grub_module_usb.img'
        module_install.extract_boot_file(usb_image, 'kernel.elf', work / 'usb-kernel.elf')
        module_install.extract_boot_file(usb_image, 'retroos-base.img.gz', work / 'usb-base.img.gz')
        assert (work / 'usb-kernel.elf').read_bytes()[:4] == b'\x7fELF'
        assert (work / 'usb-base.img.gz').read_bytes()[:2] == b'\x1f\x8b'
        assert os.access(vm / 'run.sh', os.X_OK)
        assert (vm / 'data.img').stat().st_mode & 0o200
        with (vm / 'data.img').open('rb') as disk:
            offset = struct.unpack_from('<I', disk.read(512), 454)[0] * 512
        volume = f'{vm}/data.img@@{offset}'
        listing = subprocess.check_output(['mdir', '-i', volume, '::/'])
        for forbidden in (b'BUILD~1', b'DOS32A', b'BORLANDC'):
            assert forbidden not in listing, forbidden
        for system_dir in ('WINDOWS/SYSTEM32', 'WINDOWS/SYSTEM', 'OS2/DLL'):
            old_dlls = subprocess.run(
                ['mdir', '-i', volume, f'::/{system_dir}/*.DLL'],
                capture_output=True,
            )
            assert b'.DLL' not in old_dlls.stdout, system_dir
        with tarfile.open(machine / 'machine_boot.tar') as archive:
            names = {member.name.removeprefix('./') for member in archive.getmembers()}
            assert {
                'kernel.elf', 'RETROOS/COMMAND.COM', 'RETROOS/KERNEL.SYM',
                'DN/DN.COM', 'VC/VC.COM', 'MC/MC.EXE',
                'RETROOS/WINDOWS/SYSTEM32/ADVAPI32.DLL',
                'RETROOS/WINDOWS/SYSTEM32/KERNEL32.DLL',
                'RETROOS/WINDOWS/SYSTEM/KERNEL.DLL',
                'RETROOS/OS2/DLL/DOSCALLS.DLL',
                'RETROOS/RETROOS.INI', 'VC/VC.INI', 'VC/VC.HLP',
                'MC/MC.INI', 'MC/MC.MNU', 'MC/MC.HLP',
                'RC/RC.EXE', 'bin/busybox', 'bin/sh',
            } <= names
            assert not any(
                name.endswith('.DLL') and name.startswith((
                    'WINDOWS/SYSTEM32/', 'WINDOWS/SYSTEM/', 'OS2/DLL/',
                )) for name in names
            )
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
        installer.validate = lambda *_: '00000000-0000-0000-0000-000000000001'
        installer.prepare(home, Path('/boot/retroos'), machine / 'machine_boot.tar')
        assert (vm / 'tools/run/unipcemu.sh').is_file()
        rom = work / 'ROM'
        rom.mkdir()
        (rom / 'BIOSROM.i430fx.BIN').write_bytes(b'test ROM')
        (rom / 'BIOSROM.i440fx.BIN').write_bytes(b'test i440fx ROM')
        fake_unipcemu = work / 'fake-unipcemu'
        fake_unipcemu.write_text('''#!/usr/bin/env python3
import configparser
import os
from pathlib import Path

root = Path(os.environ['UNIPCEMU'])
settings = configparser.ConfigParser()
assert settings.read(root / 'SETTINGS.INI')
assert settings['machine']['architecture'] == os.environ['EXPECTED_ARCHITECTURE']
assert settings['machine']['executionmode'] == '4'
assert settings['bios']['bootorder'] == os.environ['EXPECTED_BOOTORDER']
section = settings[os.environ['EXPECTED_CMOS_SECTION']]
assert section['memory'] == '134217728'
assert section['cpu'] == os.environ['EXPECTED_CPU']
assert section['clockingmode'] == '1'
assert section['hdd0'] == os.environ['EXPECTED_HDD0']
assert section['hdd1'] == os.environ['EXPECTED_HDD1']
assert section['cdrom0'] == os.environ['EXPECTED_CDROM']
assert section['videocard'] == os.environ['EXPECTED_VIDEO']
assert section['ET4000_extensions'] == os.environ['EXPECTED_ET4000']
assert section['soundblaster'] == os.environ['EXPECTED_SOUNDBLASTER']
assert not settings.has_section('disks')
assert not settings.has_section('sound')
assert not settings.has_option('machine', 'cpu')
assert (root / 'ROM' / os.environ['EXPECTED_ROM']).is_file()
assert (root / 'disks/data.img').resolve() == Path(os.environ['RETROOS_DATA_IMAGE']).resolve()
if os.environ.get('EXPECTED_BOOT_IMAGE'):
    assert (root / 'disks/boot.img').resolve() == Path(os.environ['EXPECTED_BOOT_IMAGE']).resolve()
if os.environ.get('EXPECTED_ISO_IMAGE'):
    assert (root / 'disks/boot.iso').resolve() == Path(os.environ['EXPECTED_ISO_IMAGE']).resolve()
''')
        fake_unipcemu.chmod(0o755)
        missing_rom = subprocess.run([str(vm / 'run.sh'), '--backend', 'unipcemu'],
                                     cwd=vm, env={**os.environ, 'UNIPCEMU_BIN': str(fake_unipcemu),
                                                 'UNIPCEMU_ROM_DIR': ''},
                                     capture_output=True, text=True)
        assert missing_rom.returncode != 0 and 'UNIPCEMU_ROM_DIR' in missing_rom.stderr
        for sound, expected in [('sb', '4'), ('none', '0')]:
            env = os.environ.copy()
            env.update(UNIPCEMU_BIN=str(fake_unipcemu), RETROOS_DATA_IMAGE=str(vm / 'data.img'),
                       UNIPCEMU_ROM_DIR=str(rom), UNIPCEMU_ARCH='i430fx',
                       UNIPCEMU_ISO_IMAGE='', UNIPCEMU_USB_IMAGE='',
                       EXPECTED_SOUNDBLASTER=expected,
                       EXPECTED_ARCHITECTURE='4', EXPECTED_CMOS_SECTION='i430fxCMOS',
                       EXPECTED_CPU='5', EXPECTED_ROM='BIOSROM.i430fx.BIN',
                       EXPECTED_BOOTORDER='14', EXPECTED_HDD0='boot.img', EXPECTED_HDD1='data.img',
                       EXPECTED_CDROM='', EXPECTED_VIDEO='0', EXPECTED_ET4000='0')
            subprocess.run([str(vm / 'run.sh'), '--backend', 'unipcemu', '--sound', sound],
                           cwd=vm, env=env, check=True, stdout=subprocess.DEVNULL)
        env.update(UNIPCEMU_USB_IMAGE=str(usb_image),
                   EXPECTED_BOOT_IMAGE=str(usb_image),
                   UNIPCEMU_VIDEO='et4000w32', EXPECTED_BOOTORDER='14',
                   EXPECTED_HDD0='boot.img', EXPECTED_HDD1='data.img',
                   EXPECTED_CDROM='', EXPECTED_VIDEO='6', EXPECTED_ET4000='1',
                   EXPECTED_SOUNDBLASTER='4')
        subprocess.run([str(vm / 'run.sh'), '--backend', 'unipcemu'],
                       cwd=vm, env=env, check=True, stdout=subprocess.DEVNULL)
        env.update(UNIPCEMU_USB_IMAGE='', UNIPCEMU_ISO_IMAGE=str(OUTPUT / 'retroos_grub_module.iso'),
                   EXPECTED_BOOTORDER='13', EXPECTED_HDD0='data.img', EXPECTED_HDD1='',
                   EXPECTED_CDROM='boot.iso', EXPECTED_BOOT_IMAGE='',
                   EXPECTED_ISO_IMAGE=str(OUTPUT / 'retroos_grub_module.iso'))
        subprocess.run([str(vm / 'run.sh'), '--backend', 'unipcemu'],
                       cwd=vm, env=env, check=True, stdout=subprocess.DEVNULL)
        env.update(UNIPCEMU_ARCH='i440fx', EXPECTED_ARCHITECTURE='5',
                   EXPECTED_CMOS_SECTION='i440fxCMOS', EXPECTED_CPU='7',
                   EXPECTED_ROM='BIOSROM.i440fx.BIN')
        subprocess.run([str(vm / 'run.sh'), '--backend', 'unipcemu'],
                       cwd=vm, env=env, check=True, stdout=subprocess.DEVNULL)
        print('PASS: packaged UniPCemu launcher configures current CMOS sections, USB HDD, CD ISO, and i440fx')
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
