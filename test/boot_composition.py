#!/usr/bin/env python3
"""Boot sources supply runtime/defaults; ext4 or FAT supplies C: data."""
import hashlib
import pathlib
import shutil
import subprocess
import tempfile
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent

def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), cwd=ROOT, check=True, **kwargs)

def file(tree, name, data):
    path = tree / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def image(work, name, tree, kind):
    path = work / (name + '.img')
    with path.open('wb') as f:
        f.truncate(32 * 1024 * 1024)
    if kind == 'ext4':
        for entry in [tree, *tree.rglob('*')]:
            entry.chmod(0o775 if entry.is_dir() else 0o664)
        run('mkfs.ext4', '-q', '-F', '-b', '4096', '-d', tree, path)
    else:
        run('mkfs.fat', '-F', '16', path, stdout=subprocess.DEVNULL)
        for entry in tree.iterdir():
            run('mcopy', '-s', '-i', path, entry, '::/')
    return path

def boot(work, name, module, disks, protected=False, extra_args=""):
    tree = work / name
    grub = tree / 'boot/grub'
    grub.mkdir(parents=True)
    shutil.copyfile(ROOT / 'bazel-bin/kernel/kernel.elf', tree / 'boot/kernel.elf')
    cmd = ['set timeout=0', 'menuentry "probe" {',
           'multiboot /boot/kernel.elf' + (' ram-overlay' if protected else '') + ' ' + extra_args]
    if module:
        shutil.copyfile(module, tree / 'boot/root.img')
        cmd.append('module /boot/root.img retroos.mount=/')
    cmd += ['boot', '}']
    (grub / 'grub.cfg').write_text('\n'.join(cmd) + '\n')
    iso = work / (name + '.iso')
    run('grub-mkrescue', '-o', iso, tree, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log = work / (name + '.log')
    args = ['qemu-system-i386', '-m', '256', '-cpu', 'pentium3', '-cdrom', str(iso),
            '-boot', 'order=d', '-display', 'none', '-no-reboot', '-debugcon', 'file:' + str(log),
            '-fw_cfg', 'name=opt/cmdline,string=RETROOS/PROBE.COM']
    for index, disk in enumerate(disks):
        args += ['-drive', f'file={disk},format=raw,if=ide,index={index}']
    process = subprocess.Popen(args, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline and process.poll() is None:
            text = log.read_text(errors='replace') if log.exists() else ''
            if any(marker in text for marker in ['COMPOSITION-OK', 'COMPOSITION-FAIL', 'PANIC']):
                break
            time.sleep(.1)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
    text = log.read_text(errors='replace')
    if 'COMPOSITION-OK' not in text or 'PANIC' in text:
        raise AssertionError(name + '\n' + text)
    print('PASS:', name, flush=True)

def main():
    run('bazelisk', 'build', '//kernel:kernel_elf')
    with tempfile.TemporaryDirectory(prefix='retroos-composition-') as scratch:
        work = pathlib.Path(scratch)
        probe = work / 'probe.com'
        run('nasm', '-f', 'bin', '-o', probe, 'test/boot_composition_probe.asm')
        for source in ['module', 'efi']:
            boot_tree = work / (source + '-tree')
            home = boot_tree / 'home/retroos' if source == 'module' else boot_tree
            file(home, 'RETROOS/RUNTIME.TXT', b'B')
            file(home, 'RETROOS/PROBE.COM', probe.read_bytes())
            file(home, 'CONFIG/DEFAULT.TXT', b'B')
            file(home, 'CONFIG/OVERRIDE.TXT', b'B')
            file(home, 'CONFIG/NESTED/DEFAULT.TXT', b'B')
            (boot_tree / ('bin' if source == 'module' else 'EFI')).mkdir(exist_ok=True)
            boot_image = image(work, source, boot_tree, 'ext4' if source == 'module' else 'fat')
            boot_hash = hashlib.sha256(boot_image.read_bytes()).digest()
            for kind in ['ext4', 'fat']:
                data_tree = work / (source + '-' + kind)
                data_home = data_tree / 'home/retroos' if kind == 'ext4' else data_tree
                file(data_home, 'DATA.TXT', b'D')
                file(data_home, 'RETROOS/RUNTIME.TXT', b'D')
                file(data_home, 'CONFIG/OVERRIDE.TXT', b'D')
                file(data_home, 'TEMP/OLD.TXT', b'D')
                for protected in [False, True]:
                    # Also exercise a physical Unix root beside the RAM boot source.
                    if protected and kind == 'ext4':
                        (data_tree / 'bin').mkdir(exist_ok=True)
                    label = source + '-' + kind + ('-protected' if protected else '-persistent')
                    data_image = image(work, label, data_tree, kind)
                    before = hashlib.sha256(data_image.read_bytes()).digest()
                    boot(work, label, boot_image if source == 'module' else None,
                         ([boot_image] if source == 'efi' else []) + [data_image], protected)
                    if protected:
                        assert hashlib.sha256(data_image.read_bytes()).digest() == before
                    else:
                        if kind == 'fat':
                            result = run('mtype', '-i', data_image, '::CONFIG/OVERRIDE.TXT', capture_output=True)
                        else:
                            result = run('debugfs', '-R', 'cat /home/retroos/CONFIG/OVERRIDE.TXT',
                                         data_image, capture_output=True)
                        assert result.stdout == b'S', (label, result.stdout)
                    assert hashlib.sha256(boot_image.read_bytes()).digest() == boot_hash
            # Without a data disk, the same runtime/config/temp layout still works.
            file(home, 'DATA.TXT', b'D')
            file(home, 'CONFIG/OVERRIDE.TXT', b'D')
            file(home, 'TEMP/OLD.TXT', b'D')
            fallback = image(work, source + '-only', boot_tree, 'ext4' if source == 'module' else 'fat')
            before = hashlib.sha256(fallback.read_bytes()).digest()
            boot(work, source + '-only', fallback if source == 'module' else None,
                 [] if source == 'module' else [fallback])
            assert hashlib.sha256(fallback.read_bytes()).digest() == before

        # Installed releases use the same composition, selected explicitly by UUID.
        installed = work / 'installed-tree'
        for directory in ['RETROOS', 'CONFIG']:
            shutil.copytree(home / directory, installed / 'boot/release' / directory)
        data_home = installed / 'home/retroos'
        file(data_home, 'DATA.TXT', b'D')
        file(data_home, 'RETROOS/RUNTIME.TXT', b'D')
        file(data_home, 'CONFIG/OVERRIDE.TXT', b'D')
        file(data_home, 'TEMP/OLD.TXT', b'D')
        disk = image(work, 'installed', installed, 'ext4')
        with disk.open('rb') as stream:
            stream.seek(1024 + 104)
            root_uuid = uuid.UUID(bytes=stream.read(16))
        boot(work, 'installed', None, [disk], extra_args=
             f'retroos.root={root_uuid} retroos.c-root=/home/retroos retroos.runtime=/boot/release/RETROOS')
        result = run('debugfs', '-R', 'cat /home/retroos/CONFIG/OVERRIDE.TXT', disk, capture_output=True)
        assert result.stdout == b'S'
        result = run('debugfs', '-R', 'cat /boot/release/RETROOS/RUNTIME.TXT', disk, capture_output=True)
        assert result.stdout == b'B'

if __name__ == '__main__':
    main()
