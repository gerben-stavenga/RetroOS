#!/usr/bin/env python3
"""Boot real USB menus and verify that the default showcase and explicit core-only choice."""
from pathlib import Path
import configparser
import os
import shutil
import subprocess
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, stdout=subprocess.DEVNULL, **kwargs)


def boot(work, image, name, firmware, command):
    log = work / (name + '.log')
    args = ['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host', '-m', '512',
            '-device', 'qemu-xhci,id=usb',
            '-drive', f'if=none,id=stick,file={image},format=raw,snapshot=on',
            '-device', 'usb-storage,bus=usb.0,drive=stick,bootindex=1',
            '-boot', 'order=c', '-display', 'none', '-serial', 'none', '-no-reboot',
            '-debugcon', f'file:{log}', '-fw_cfg', 'name=opt/cmdline,string=' + command]
    if firmware == 'uefi':
        variables = work / (name + '-vars.fd')
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        args += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                 '-drive', f'if=pflash,format=raw,file={variables}']
    process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            text = log.read_text(errors='replace') if log.exists() else ''
            if '[mem] exit tid=1 code=' in text or 'PANIC' in text or process.poll() is not None:
                break
            time.sleep(.1)
        assert '[mem] exit tid=1 code=0' in text and 'PANIC' not in text, text[-8000:]
        return text
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)


def main():
    if not os.access('/dev/kvm', os.R_OK | os.W_OK):
        raise SystemExit('This regression requires KVM')
    run('bazelisk', 'build', '//:grub_module_usb', '//:machine_boot_tar')
    with tarfile.open(ROOT / 'bazel-bin/root_module_base_tar.tar') as archive:
        names = {m.name.removeprefix('./') for m in archive.getmembers()}
    assert 'DN/DN.COM' in names and 'bin/busybox' in names
    assert not any(n.startswith(('TC/', 'COMMANDER/', 'GAMES/', 'ULTRASND/')) for n in names)
    assert (ROOT / 'bazel-bin/retroos-base.img').stat().st_size == 16 * 1024 * 1024
    with tarfile.open(ROOT / 'bazel-bin/machine_boot_tar.tar') as archive:
        names = {m.name.removeprefix('./') for m in archive.getmembers()}
    assert 'DN/DN.COM' in names and 'RETROOS/COMMAND.COM' in names
    assert 'RETROOS/BOOT.INI' not in names
    assert not any(n.startswith(('OS2/APPS/', 'WINDOWS/APPS/', 'SRC/', 'TESTS/')) for n in names)
    assert not any(n.startswith(('COMMANDER/', 'GAMES/', 'TC/', 'ULTRASND/')) for n in names)
    with tempfile.TemporaryDirectory(prefix='retroos-showcase-') as folder:
        work = Path(folder)
        original = ROOT / 'bazel-bin/retroos_grub_module_usb.img'
        volume = str(original) + '@@1048576'
        menu = subprocess.check_output(['mtype', '-i', volume, '::/boot/grub/grub.cfg']).decode()
        user = subprocess.check_output(['mtype', '-i', volume, '::/boot/retroos/RETROOS.INI']).decode()
        storage = subprocess.check_output(['mtype', '-i', volume, '::/boot/retroos/BOOT.INI']).decode()
        ini = configparser.ConfigParser()
        ini.read_string(storage)
        assert ini['bundle']['source'] == 'module'
        assert '[mount ' not in user and 'set retroos_release=/boot/retroos/releases/' in menu
        menu_file = work / 'grub.cfg'
        menu_file.write_text(menu)
        run('grub-script-check', menu_file)
        with tarfile.open(ROOT / 'bazel-bin/showcase_module_tar.tar') as archive:
            names = {m.name.removeprefix('./') for m in archive.getmembers()}
        assert {'COMMANDER/DN2D214/DN.COM', 'COMMANDER/NDN-D32/NDN.COM', 'COMMANDER/RC/RC.EXE', 'GAMES/DOOMS/DOOM.EXE', 'TC/TC.EXE', 'ULTRASND/MIDI/ACPIANO.PAT',
                'WINDOWS/APPS/MINESWPR.EXE', 'OS2/APPS/SWEEPER/SWEEPER.EXE',
                'WINDOWS/APPS/HELLO.EXE', 'WINDOWS/APPS/WATCIO.EXE',
                'OS2/APPS/HELLO.EXE', 'OS2/APPS/PMSMOKE.EXE',
                'OS2/APPS/WATCIO.EXE', 'SRC/COMMAND.C',
                'TESTS/HELLO.COM', 'TESTS/DOSRT.EXE', 'TESTS/MODPLAY.EXE'} <= names
        with tarfile.open(ROOT / 'bazel-bin/showcase_module_tar.tar') as archive:
            packaged = {m.name.removeprefix('./') for m in archive.getmembers() if m.isfile()}
        source = {str(p.relative_to(ROOT / 'showcase-bundle'))
                  for p in (ROOT / 'showcase-bundle').rglob('*') if p.is_file()}
        generated = {'OS2/APPS/HELLO.EXE', 'OS2/APPS/PMSMOKE.EXE',
                     'OS2/APPS/WATCIO.EXE', 'WINDOWS/APPS/HELLO.EXE',
                     'WINDOWS/APPS/WATCIO.EXE'}
        generated |= {name for name in packaged if name.startswith(('SRC/', 'TESTS/'))}
        assert packaged == source | generated, ((source | generated) - packaged, packaged - source - generated)
        assert 'showcase_commander' not in menu and 'boot_choices showcase' in menu
        settings = work / 'RETROOS.INI'
        settings.write_text(user.replace('language=en-US', 'language=it-IT'))
        for firmware in ['bios', 'uefi']:
            image = work / (firmware + '.img')
            shutil.copyfile(original, image)
            run('mcopy', '-o', '-i', str(image) + '@@1048576', settings, '::/boot/retroos/RETROOS.INI')
            text = boot(work, image, 'showcase-' + firmware, firmware,
                        '/bin/busybox sh -c "test -d /SRC && test -d /TESTS && test -d /OS2 && test -d /WINDOWS"')
            assert text.count('Optional module:') == 1 and '/showcase/ (256 MiB)' in text, text
            assert 'Locale: it-IT' in text, text
            print('PASS: USB', firmware, 'defaults to one showcase image with games and commanders', flush=True)
            title = ('RetroOS (protected disk, native BIOS VGA)' if firmware == 'bios'
                     else 'RetroOS (protected disk, GOP framebuffer)')
            menu_file.write_text(menu.replace('set default=0',
                f'set default="Core only (less RAM)>{title}"').replace('set timeout=5', 'set timeout=0'))
            run('grub-script-check', menu_file)
            run('mcopy', '-o', '-i', str(image) + '@@1048576', menu_file, '::/boot/grub/grub.cfg')
            text = boot(work, image, 'core-' + firmware, firmware,
                        '/bin/busybox sh -c "test -s /bin/busybox && ! test -e /COMMANDER && ! test -e /GAMES"')
            assert 'Optional module:' not in text, text
            print('PASS: USB', firmware, 'core-only choice omits the showcase', flush=True)


if __name__ == '__main__':
    main()
